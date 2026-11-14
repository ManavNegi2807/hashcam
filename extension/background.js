// HashCam Recorder background worker.
//
// It watches ONE tab that the person marked as agent-driven, and reports to the local recorder:
//   page loads   -> asked before they load; a load outside the passport is redirected away
//   form submits -> held by the content script until the person decides (passkey in side panel)
//   downloads    -> paused at once, resumed only after a granted approval, else cancelled
//   secrets      -> only a salted commitment computed inside the page ever arrives here
// What it does NOT see: data a page script sends itself (fetch, XHR, WebSocket). The receipt
// says so: its coverage is STEP_OBSERVED, never STEP_GATED.

import { api, hostPatterns } from "./lib/api.js";

const SCRIPT_ID = "hashcam-agent";
const held = new Map(); // action_id -> { resolve, kind, downloadId?, timer }
const navActions = new Map(); // tabId -> Promise<{actionId, url} | null> for the load in flight
const panels = new Set();

chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true }).catch(() => {});

async function state() {
  const { rec = null } = await chrome.storage.session.get("rec");
  return rec; // { sessionId, tabId, hosts } while recording
}

function broadcast(message) {
  for (const port of panels) {
    try { port.postMessage(message); } catch { panels.delete(port); }
  }
}

chrome.runtime.onConnect.addListener((port) => {
  if (port.name !== "panel") return;
  panels.add(port);
  port.onDisconnect.addListener(() => panels.delete(port));
});

function resolveHeld(actionId, decision) {
  const item = held.get(actionId);
  if (!item) return;
  held.delete(actionId);
  clearTimeout(item.timer);
  if (item.kind === "download") {
    if (decision === "ALLOW") chrome.downloads.resume(item.downloadId).catch(() => {});
    else chrome.downloads.cancel(item.downloadId).catch(() => {});
  } else {
    item.resolve({ decision });
  }
  broadcast({ type: "changed" });
}

function hold(answer, kind, extra = {}) {
  return new Promise((resolve) => {
    const timer = setTimeout(
      () => resolveHeld(answer.action_id, "TIMED_OUT"),
      (answer.expires_in + 2) * 1000,
    );
    held.set(answer.action_id, { resolve, kind, timer, ...extra });
    broadcast({ type: "waiting", action: answer });
  });
}

async function report(rec, body) {
  try {
    return await api(`/sessions/${rec.sessionId}/events`, body);
  } catch (error) {
    broadcast({ type: "error", message: String(error.message || error) });
    return { decision: "DENY", reasons: ["RECORDER_UNREACHABLE"] }; // fail closed
  }
}

// ---------------------------------------------------------------- page loads

const navUrls = new Map(); // tabId -> the URL the last check was about
const pageTexts = new Map(); // tabId -> { url, text } sent by the page itself when it loaded

function sameUrl(a, b) {
  try {
    const x = new URL(a); const y = new URL(b);
    x.hash = ""; y.hash = "";
    return x.href === y.href;
  } catch { return false; }
}

function checkNavigation(rec, tabId, url) {
  navUrls.set(tabId, url);
  // A fast page can finish loading before the recorder answers, so the load handler waits on
  // this promise rather than on a value that may not be there yet.
  const decided = report(rec, { kind: "navigate", url }).then((answer) => {
    if (answer.decision !== "ALLOW") {
      const page = chrome.runtime.getURL(
        `blocked.html?url=${encodeURIComponent(url)}&why=${encodeURIComponent((answer.reasons || []).join(","))}`,
      );
      chrome.tabs.update(tabId, { url: page }).catch((error) => {
        broadcast({ type: "error", message: `could not leave a blocked page: ${error.message || error}` });
      });
    }
    broadcast({ type: "changed", drift: answer.drift || null });
    return answer.decision === "ALLOW" ? { actionId: answer.action_id, url } : null;
  });
  navActions.set(tabId, decided);
}

chrome.webNavigation.onBeforeNavigate.addListener(async ({ tabId, frameId, url }) => {
  const rec = await state();
  if (!rec || tabId !== rec.tabId || frameId !== 0 || !/^https?:/.test(url)) return;
  pageTexts.delete(tabId);
  checkNavigation(rec, tabId, url);
});

// A server redirect lands somewhere the first check never saw: check that address too, or a
// redirect would carry the agent outside its passport unnoticed.
chrome.webNavigation.onCommitted.addListener(async ({ tabId, frameId, url }) => {
  const rec = await state();
  if (!rec || tabId !== rec.tabId || frameId !== 0 || !/^https?:/.test(url)) return;
  if (sameUrl(url, navUrls.get(tabId) || "")) return;
  checkNavigation(rec, tabId, url);
});

chrome.webNavigation.onCompleted.addListener(async ({ tabId, frameId }) => {
  const rec = await state();
  const decided = navActions.get(tabId);
  if (!rec || tabId !== rec.tabId || frameId !== 0 || !decided) return;
  navActions.delete(tabId);
  const allowed = await decided;
  if (allowed) await observe(rec, tabId, allowed.actionId, allowed.url);
});

async function pageTextFor(tabId, url) {
  // The page sends its own text on load, so the text always belongs to THIS page, even if the
  // agent has already moved on by the time we get here.
  for (let i = 0; i < 20; i++) {
    const cached = pageTexts.get(tabId);
    if (cached && sameUrl(cached.url, url)) return cached.text;
    await new Promise((r) => setTimeout(r, 100));
  }
  return "";
}

async function observe(rec, tabId, actionId, url) {
  const text = await pageTextFor(tabId, url);
  let snapshot = null;
  try {
    const tab = await chrome.tabs.get(tabId);
    // Only a picture of this page: if the agent already moved on, there is no snapshot.
    if (tab.active && sameUrl(tab.url || "", url)) {
      const shot = await chrome.tabs.captureVisibleTab(tab.windowId, { format: "png" });
      snapshot = shot.split(",", 2)[1];
    }
  } catch { /* no snapshot: the page is not visible, or capture is not allowed here */ }
  try {
    const seen = await api(`/sessions/${rec.sessionId}/observe`, {
      action_id: actionId, text, snapshot_png_b64: snapshot,
    });
    broadcast({ type: "changed", tripwire: seen.tripwire });
  } catch (error) {
    broadcast({ type: "error", message: String(error.message || error) });
  }
}

// ---------------------------------------------------------------- downloads

chrome.downloads.onCreated.addListener(async (item) => {
  const rec = await state();
  if (!rec) return;
  let agentOrigin = "";
  try { agentOrigin = new URL((await chrome.tabs.get(rec.tabId)).url).origin; } catch { return; }
  if (!item.referrer || !item.referrer.startsWith(agentOrigin)) return;
  chrome.downloads.pause(item.id).catch(() => {});
  const url = /^https?:/.test(item.finalUrl || item.url) ? item.finalUrl || item.url : item.referrer;
  const answer = await report(rec, {
    kind: "download", url, filename: (item.filename || "").split(/[\\/]/).pop(),
  });
  if (answer.decision === "NEEDS_APPROVAL") {
    hold(answer, "download", { downloadId: item.id });
  } else if (answer.decision !== "ALLOW") {
    chrome.downloads.cancel(item.id).catch(() => {});
  } else {
    chrome.downloads.resume(item.id).catch(() => {});
  }
  broadcast({ type: "changed" });
});

// ---------------------------------------------------------------- messages

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    const rec = await state();
    const fromAgentTab = rec && sender.tab && sender.tab.id === rec.tabId;
    switch (message.type) {
      case "hello":
        return { agent: Boolean(fromAgentTab) };
      case "pageLoaded":
        if (fromAgentTab) pageTexts.set(sender.tab.id, { url: message.url, text: String(message.text || "") });
        return { ok: true };
      case "submit": {
        if (!fromAgentTab) return { decision: "ALLOW" }; // not the agent's tab: not ours to gate
        const answer = await report(rec, {
          kind: "form_submit", url: message.url, fields: message.fields || [],
        });
        if (answer.decision === "NEEDS_APPROVAL") return hold(answer, "form");
        broadcast({ type: "changed" });
        return { decision: answer.decision, reasons: answer.reasons };
      }
      case "secret": {
        if (!fromAgentTab) return { ok: false };
        await report(rec, {
          kind: "secret", url: message.url, field_kind: message.fieldKind,
          commitment: message.commitment,
        });
        broadcast({ type: "changed" });
        return { ok: true };
      }
      case "decided":
        resolveHeld(message.actionId, message.decision);
        return { ok: true };
      case "armed":
        await arm(message);
        return { ok: true };
      case "stop":
        return finish(Boolean(message.killed));
      default:
        return { error: "unknown message" };
    }
  })().then(sendResponse, (error) => sendResponse({ error: String(error) }));
  return true; // answer asynchronously
});

async function arm({ sessionId, tabId, hosts }) {
  await chrome.storage.session.set({ rec: { sessionId, tabId, hosts } });
  await chrome.scripting.unregisterContentScripts({ ids: [SCRIPT_ID, SCRIPT_ID + "-main"] }).catch(() => {});
  const matches = hostPatterns(hosts);
  await chrome.scripting.registerContentScripts([
    { id: SCRIPT_ID, matches, js: ["content.js"], runAt: "document_start", allFrames: false,
      persistAcrossSessions: false },
    { id: SCRIPT_ID + "-main", matches, js: ["page-guard.js"], runAt: "document_start",
      world: "MAIN", allFrames: false, persistAcrossSessions: false },
  ]);
  // The page already open when recording starts is the first thing in the receipt.
  const tab = await chrome.tabs.get(tabId);
  await chrome.scripting.executeScript({ target: { tabId }, files: ["content.js"] }).catch(() => {});
  await chrome.scripting.executeScript({ target: { tabId }, files: ["page-guard.js"], world: "MAIN" }).catch(() => {});
  if (/^https?:/.test(tab.url || "")) {
    const rec = await state();
    navUrls.set(tabId, tab.url);
    const answer = await report(rec, { kind: "navigate", url: tab.url });
    if (answer.decision === "ALLOW") await observe(rec, tabId, answer.action_id, tab.url);
  }
}

async function finish(killed) {
  const rec = await state();
  if (!rec) return { error: "not recording" };
  for (const id of [...held.keys()]) resolveHeld(id, "NOT_SENT");
  if (killed) await chrome.tabs.remove(rec.tabId).catch(() => {});
  await chrome.scripting.unregisterContentScripts({ ids: [SCRIPT_ID, SCRIPT_ID + "-main"] }).catch(() => {});
  await chrome.storage.session.remove("rec");
  // All-sites access was only for screenshots during this session: give it back now.
  await chrome.permissions.remove({ origins: ["<all_urls>"] }).catch(() => {});
  const sealed = await api(`/sessions/${rec.sessionId}/stop`, { killed });
  broadcast({ type: "sealed", sessionId: rec.sessionId });
  return sealed;
}
