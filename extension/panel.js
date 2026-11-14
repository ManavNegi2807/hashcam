// The HashCam Recorder side panel. It shows what the recorder says and asks the person for
// decisions. It never decides validity itself: the verdict shown is the offline verifier's.

import { api, approvalChallenge, b64urlDecode, b64urlEncode, hostPatterns, settings } from "./lib/api.js";

const $ = (id) => document.getElementById(id);
const gsap = window.gsap;
const calm = matchMedia("(prefers-reduced-motion: reduce)").matches;
const port = chrome.runtime.connect({ name: "panel" });

let sessionId = null;
let view = null;
let shownLines = 0;
let timer = null;

// ------------------------------------------------------------------ small helpers

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  for (const c of children) if (c != null) node.append(c instanceof Node ? c : String(c));
  return node;
}
function svg(markup) {
  // Only fixed, hard-coded markup goes through here; never data from a page or the recorder.
  const t = document.createElement("template");
  t.innerHTML = markup.trim();
  return t.content.firstChild;
}
function showError(message) {
  const box = $("error");
  box.textContent = message;
  box.hidden = !message;
}
async function guarded(fn) {
  showError("");
  try { await fn(); } catch (error) { showError(String(error.message || error)); }
}
const clock = (s) => [s / 3600, (s % 3600) / 60, s % 60].map((x) => String(Math.floor(x)).padStart(2, "0")).join(":");
const host = (u) => { try { return new URL(u).host; } catch { return u || ""; } };

// ------------------------------------------------------------------ tabs

for (const tab of document.querySelectorAll(".tabs button")) {
  tab.addEventListener("click", () => {
    for (const t of document.querySelectorAll(".tabs button")) t.setAttribute("aria-selected", String(t === tab));
    for (const v of document.querySelectorAll(".view")) v.hidden = v.id !== `view-${tab.dataset.view}`;
    if (tab.dataset.view === "replay") renderReplay();
  });
}

// ------------------------------------------------------------------ setup flow

async function boot() {
  const { token, port: p } = await settings();
  $("port").value = p;
  const { sessionId: saved, credentialId } = await chrome.storage.local.get(["sessionId", "credentialId"]);
  if (!token) return stage("pair");
  let status;
  try { status = await api("/status"); } catch (error) { showError(String(error.message)); return stage("pair"); }
  if (!status.passkey || !credentialId) return stage("passkey");
  if (saved) {
    try { sessionId = saved; await refresh(); return; } catch { sessionId = null; }
  }
  stage("arm");
}

function stage(name) {
  $("pairCard").hidden = name !== "pair";
  $("passkeyCard").hidden = name !== "passkey";
  $("armCard").hidden = name !== "arm";
  $("liveArea").hidden = name !== "live";
}

$("pairBtn").addEventListener("click", () => guarded(async () => {
  await chrome.storage.local.set({ token: $("token").value.trim(), port: Number($("port").value) || 8770 });
  $("token").value = "";
  await api("/status");
  await boot();
}));

$("passkeyBtn").addEventListener("click", () => guarded(async () => {
  const { challenge } = await api("/passkey/challenge", { purpose: "register" });
  const credential = await navigator.credentials.create({
    publicKey: {
      rp: { name: "HashCam Recorder" },
      user: { id: crypto.getRandomValues(new Uint8Array(16)), name: "approver", displayName: "HashCam approver" },
      challenge: b64urlDecode(challenge),
      pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -257 }],
      authenticatorSelection: { userVerification: "required", residentKey: "discouraged" },
      timeout: 60000,
    },
  });
  const r = credential.response;
  await api("/passkey/register", {
    credential_id: b64urlEncode(credential.rawId),
    client_data_json: b64urlEncode(r.clientDataJSON),
    public_key_spki: b64urlEncode(r.getPublicKey()),
    algorithm: r.getPublicKeyAlgorithm(),
    authenticator_data: b64urlEncode(r.getAuthenticatorData()),
  });
  await chrome.storage.local.set({ credentialId: b64urlEncode(credential.rawId) });
  stage("arm");
}));

$("armBtn").addEventListener("click", () => guarded(async () => {
  const hosts = $("hosts").value.split(/[\s,]+/).map((h) => h.trim().toLowerCase()).filter(Boolean);
  if (!hosts.length) throw new Error("Give the passport at least one site.");
  // Asked in the click itself: the browser only grants access to the passport's sites.
  const granted = await chrome.permissions.request({ origins: hostPatterns(hosts) });
  if (!granted) throw new Error("Without access to those sites HashCam cannot watch the agent there.");
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !/^https?:/.test(tab.url || "")) throw new Error("Open the agent's tab (a web page) first.");
  const started = await api("/sessions", {
    task: $("task").value, agent: $("agent").value,
    passport: { hosts, minutes: Number($("minutes").value) || 30 },
  });
  sessionId = started.session_id;
  shownLines = 0;
  $("rollLines").textContent = "";
  $("verdict").hidden = true;
  await chrome.storage.local.set({ sessionId });
  await chrome.runtime.sendMessage({ type: "armed", sessionId, tabId: tab.id, hosts });
  await refresh();
}));

// ------------------------------------------------------------------ live view

async function refresh() {
  if (!sessionId) return;
  view = await api(`/sessions/${sessionId}`);
  stage("live");
  renderCluster();
  renderLine();
  renderApprovals();
  renderRoll();
  if (view.verdict) renderVerdict();
  $("controls").hidden = view.state !== "recording";
  clearInterval(timer);
  if (view.state === "recording") timer = setInterval(tick, 1000);
}

function tick() {
  if (!view) return;
  $("timecode").textContent = clock(Math.max(0, Date.now() / 1000 - view.started));
  for (const c of document.querySelectorAll("[data-deadline]")) {
    const left = Math.max(0, Math.round((Number(c.dataset.deadline) - Date.now()) / 1000));
    c.textContent = `${left}s left`;
    if (left === 0) refresh().catch(() => {});
  }
}

function renderCluster() {
  const rec = $("rec");
  rec.dataset.state = view.state === "recording" ? "recording" : "sealed";
  $("recLabel").textContent = view.state === "recording" ? "REC" : "SEALED";
  if (view.state === "recording") tick();
  // Trust gauge: the session's own track record (blocked, drift, tripwire), not a verdict.
  const t = view.trust;
  $("gaugeNum").textContent = String(t);
  $("gaugeFill").style.strokeDashoffset = String(126 - (126 * t) / 100);
  $("gaugeFill").style.stroke = t >= 75 ? "var(--orange)" : t >= 40 ? "var(--warn)" : "var(--bad)";
  $("gaugeNeedle").style.transform = `rotate(${-90 + (180 * t) / 100}deg)`;
}

function renderLine() {
  const line = $("sessionLine");
  line.textContent = "";
  const expires = new Date(view.passport.expires_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  line.append(
    el("span", {}, "agent ", el("b", {}, view.agent)),
    el("span", {}, "passport ", el("b", {}, view.passport.hosts.join(", "))),
    el("span", {}, "until ", el("b", {}, expires)),
  );
  $("rollRun").textContent = `RUN ${view.run_id.slice(0, 8)}`;
}

function renderApprovals() {
  const box = $("approvals");
  const showing = new Set([...box.children].map((c) => c.dataset.action));
  const waiting = new Set(view.waiting.map((w) => w.action_id));
  for (const c of [...box.children]) if (!waiting.has(c.dataset.action)) c.remove();
  for (const w of view.waiting) {
    if (showing.has(w.action_id)) continue;
    const readable = w.summary.split(" | ").slice(1).join(" | ") || w.summary;
    const card = el("div", { class: "approval", "data-action": w.action_id },
      el("div", { class: "kicker" }, el("span", {}, "HELD FOR YOUR APPROVAL"),
        el("span", { class: "countdown", "data-deadline": String(Date.now() + w.seconds_left * 1000) }, `${w.seconds_left}s left`)),
      el("div", { class: "what" }, readable),
      el("div", { class: "digest" }, `you sign: sha256 ${w.summary_digest.slice(0, 24)}…`),
      el("div", { class: "row" },
        el("button", { class: "btn deny", onclick: () => decide(w, "DENIED") }, "Deny"),
        el("button", { class: "btn", onclick: () => decide(w, "GRANTED") }, "Approve with passkey"),
      ),
    );
    box.append(card);
    if (gsap && !calm) gsap.from(card, { y: -16, opacity: 0, duration: 0.4, ease: "back.out(1.6)" });
  }
}

async function decide(waiting, decision) {
  await guarded(async () => {
    const { credentialId } = await chrome.storage.local.get("credentialId");
    const assertion = await navigator.credentials.get({
      publicKey: {
        challenge: b64urlDecode(approvalChallenge(decision, waiting.summary_digest)),
        allowCredentials: [{ type: "public-key", id: b64urlDecode(credentialId) }],
        userVerification: "required",
        timeout: 60000,
      },
    });
    const r = assertion.response;
    const answer = await api(`/sessions/${sessionId}/decide`, {
      action_id: waiting.action_id, decision, summary_digest: waiting.summary_digest,
      passkey: {
        credential_id: b64urlEncode(assertion.rawId),
        client_data_json: b64urlEncode(r.clientDataJSON),
        authenticator_data: b64urlEncode(r.authenticatorData),
        signature: b64urlEncode(r.signature),
      },
    });
    await chrome.runtime.sendMessage({ type: "decided", actionId: waiting.action_id, decision: answer.decision });
    await refresh();
    if (answer.decision === "ALLOW") stampSeal(waiting.action_id);
  });
}

const LINK = `<svg class="link" viewBox="0 0 24 24" aria-hidden="true"><path fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" d="M9 15l6-6M8 11l-2 2a3.5 3.5 0 0 0 5 5l2-2M16 13l2-2a3.5 3.5 0 0 0-5-5l-2 2"/></svg>`;
const SEAL = `<svg class="seal" viewBox="0 0 60 60" aria-hidden="true"><path fill="#A3161A" d="M30 3l5 4 6-2 3 6 6 1 0 6 5 4-3 5 3 6-5 3 0 6-6 1-3 6-6-2-5 4-5-4-6 2-3-6-6-1 0-6-5-3 3-6-3-5 5-4 0-6 6-1 3-6 6 2z"/><circle cx="30" cy="30" r="15" fill="none" stroke="#E7B9A0" stroke-width="1.4" opacity=".7"/><text x="30" y="34" text-anchor="middle" font-family="Consolas, monospace" font-weight="800" font-size="10" fill="#F6D9C6">OK</text></svg>`;

function lineFor(e) {
  const at = new Date(e.at * 1000).toLocaleTimeString([], {
    hour: "2-digit", minute: "2-digit", second: "2-digit", hourCycle: "h23",
  });
  const kind = { navigate: "PAGE", form_submit: "SUBMIT", download: "DOWNLOAD", secret: "SECRET", SESSION: "ARMED", SEALED: "SEALED" }[e.kind] || e.kind;
  const li = el("li", { class: "line", "data-action": e.action_id || "", "data-n": String(e.n) },
    el("span", { class: "t" }, at),
    el("span", { class: "k" }, kind + (e.field_kind ? ` · ${e.field_kind}` : "")),
    el("span", { class: `stamp-s s-${e.status}` }, e.status.replace("_", " ")),
    e.target ? el("span", { class: "tgt" }, host(e.target) + new URL(e.target, "https://x").pathname.slice(0, 40)) : null,
    e.reasons && e.reasons.length ? el("span", { class: "why" }, e.reasons.join(" · ").toLowerCase()) : null,
    e.tripwire ? el("span", { class: "flag trip" }, `⚠ tripwire: ${e.tripwire.verdict} (${e.tripwire.reasons.join(", ")})`) : null,
    e.drift ? el("span", { class: "flag drift" }, `↯ off-task: ${e.drift.host} is not in the task`) : null,
    e.leaf ? el("span", { class: "why hash" }, `leaf ${e.leaf.slice(0, 16)}…`) : null,
  );
  li.append(svg(LINK));
  return li;
}

function renderRoll() {
  const list = $("rollLines");
  // Re-render lines whose status changed; print new ones in from the top, newest first.
  for (const e of view.timeline) {
    const existing = list.querySelector(`[data-n="${e.n}"]`);
    if (existing) {
      const fresh = lineFor(e);
      if (existing.textContent !== fresh.textContent) existing.replaceWith(fresh);
      continue;
    }
    const li = lineFor(e);
    list.prepend(li);
    if (gsap && !calm) {
      gsap.fromTo(li, { clipPath: "inset(0 0 100% 0)", y: -10 }, { clipPath: "inset(0 0 0% 0)", y: 0, duration: 0.45, ease: "steps(6)" });
    }
  }
  shownLines = view.timeline.length;
}

function stampSeal(actionId) {
  const li = $("rollLines").querySelector(`[data-action="${actionId}"]`);
  if (!li) return;
  const seal = svg(SEAL);
  li.append(seal);
  if (gsap && !calm) gsap.fromTo(seal, { scale: 2.4, rotate: -30, opacity: 0 }, { scale: 1, rotate: -8, opacity: 1, duration: 0.35, ease: "power4.in" });
}

function renderVerdict() {
  const v = view.verdict;
  const box = $("verdict");
  box.hidden = false;
  box.textContent = "";
  const overall = String(v.overall || "UNREADABLE");
  const dims = el("ul", { class: "dims" });
  for (const [name, status] of Object.entries(v.dimensions || {})) {
    dims.append(el("li", {}, el("span", {}, name), el("span", { class: `d-${status}` }, status)));
  }
  box.append(el("div", { class: "verdict" },
    el("div", { class: "muted small" }, "The offline verifier says"),
    el("div", { class: `big-stamp v-${overall}` }, overall),
    el("p", { class: "small muted" }, "A valid receipt means this record has not changed since it was signed. It does not mean the agent was honest."),
    el("div", { class: "row" },
      el("button", { class: "btn", onclick: () => download("receipt") }, "Save receipt"),
      el("button", { class: "btn ghost", onclick: () => download("receipt-keys") }, "Save key manifest"),
      el("button", { class: "btn ghost", onclick: newSession }, "New session"),
    ),
    dims,
  ));
  // The chain as the verifier judged it: intact links on VALID, a snapped link otherwise.
  const links = [...document.querySelectorAll("#rollLines .link")];
  for (const l of links) l.classList.add(overall === "VALID" ? "sealed" : "broken");
  if (overall !== "VALID" && links[0] && gsap && !calm) gsap.fromTo(links[0], { rotate: 0 }, { rotate: 35, x: 4, duration: 0.3, ease: "back.out(3)" });
}

async function download(which) {
  await guarded(async () => {
    const response = await api(`/sessions/${sessionId}/${which}`, undefined, { raw: true });
    const url = URL.createObjectURL(await response.blob());
    await chrome.downloads.download({ url, filename: view.receipt + (which === "receipt-keys" ? ".keys.json" : "") });
    setTimeout(() => URL.revokeObjectURL(url), 30000);
  });
}

async function newSession() {
  await chrome.storage.local.remove("sessionId");
  sessionId = null; view = null;
  $("rollLines").textContent = "";
  $("verdict").hidden = true;
  $("rec").dataset.state = "idle";
  $("recLabel").textContent = "STANDBY";
  $("timecode").textContent = "00:00:00";
  stage("arm");
}

// ------------------------------------------------------------------ stop and kill

$("stopBtn").addEventListener("click", () => guarded(async () => {
  const answer = await chrome.runtime.sendMessage({ type: "stop", killed: false });
  if (answer && answer.error) throw new Error(answer.error);
  await refresh();
}));
$("killCover").addEventListener("click", () => {
  $("killCover").parentElement.classList.add("open");
  $("killBtn").disabled = false;
  $("killBtn").focus();
  setTimeout(() => { $("killCover").parentElement.classList.remove("open"); $("killBtn").disabled = true; }, 6000);
});
$("killBtn").addEventListener("click", () => guarded(async () => {
  const answer = await chrome.runtime.sendMessage({ type: "stop", killed: true });
  if (answer && answer.error) throw new Error(answer.error);
  await refresh();
}));

// ------------------------------------------------------------------ replay

async function renderReplay() {
  if (!view) return;
  const frames = view.timeline.filter((e) => e.snapshot != null);
  $("replayEmpty").hidden = frames.length > 0;
  $("replayFrame").hidden = frames.length === 0;
  $("scrub").hidden = frames.length === 0;
  const ticks = $("ticks");
  ticks.textContent = "";
  for (const e of view.timeline) ticks.append(el("span", { class: e.snapshot != null ? "snap" : "" }));
  if (!frames.length) return;
  const scrub = $("scrub");
  scrub.max = String(frames.length - 1);
  if (Number(scrub.value) > frames.length - 1) scrub.value = scrub.max;
  const show = async () => {
    const e = frames[Number(scrub.value)];
    const response = await api(`/sessions/${sessionId}/snapshot/${e.snapshot}`, undefined, { raw: true });
    const img = $("replayImg");
    if (img.src) URL.revokeObjectURL(img.src);
    img.src = URL.createObjectURL(await response.blob());
    $("replayCaption").textContent = `#${e.n} · ${new Date(e.at * 1000).toLocaleTimeString()} · ${host(e.target)} · ${e.status}`;
  };
  scrub.oninput = () => guarded(show);
  await guarded(show);
}

// ------------------------------------------------------------------ verify

const drop = $("drop");
drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
drop.addEventListener("dragleave", () => drop.classList.remove("over"));
drop.addEventListener("drop", (e) => { e.preventDefault(); drop.classList.remove("over"); verifyFiles([...e.dataTransfer.files]); });
$("files").addEventListener("change", (e) => verifyFiles([...e.target.files]));

async function verifyFiles(files) {
  await guarded(async () => {
    const receipt = files.find((f) => f.name.endsWith(".abbreceipt"));
    const keys = files.find((f) => f.name.endsWith(".json"));
    if (!receipt) throw new Error("Drop a .abbreceipt file.");
    const bytes = new Uint8Array(await receipt.arrayBuffer());
    let bin = "";
    for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
    const report = await api("/verify", { receipt_b64: btoa(bin), keys_json: keys ? await keys.text() : "" });
    const out = $("verifyOut");
    out.textContent = "";
    const dims = el("ul", { class: "dims" });
    for (const [name, status] of Object.entries(report.dimensions || {})) {
      dims.append(el("li", {}, el("span", {}, name), el("span", { class: `d-${status}` }, status)));
    }
    out.append(el("div", { class: "verdict" },
      el("div", { class: "muted small" }, `${receipt.name}${keys ? "" : " · no key manifest: signatures are UNKNOWN, never passed"}`),
      el("div", { class: `big-stamp v-${report.overall}` }, String(report.overall)),
      dims,
    ));
  });
}

// ------------------------------------------------------------------ live updates

port.onMessage.addListener((message) => {
  if (message.type === "error") showError(message.message);
  if (["changed", "waiting", "sealed"].includes(message.type)) refresh().catch((e) => showError(String(e.message)));
});
setInterval(() => { if (view && view.state === "recording") refresh().catch(() => {}); }, 4000);
boot();
