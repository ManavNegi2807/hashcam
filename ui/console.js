// The HashCam Console. It shows what the verifier and the local recorder say; it decides nothing.

import { bars3d, calm, cartoon, dominoes, glowAtom, isometric, merkle, printStrip, synthwave } from "/fx3d.js";

const $ = (id) => document.getElementById(id);
const el = (tag, attrs = {}, ...kids) => {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v; else node.setAttribute(k, v);
  }
  for (const kid of kids) if (kid != null) node.append(kid instanceof Node ? kid : String(kid));
  return node;
};
const host = (u) => { try { return new URL(u).host + new URL(u).pathname; } catch { return u || ""; } };
const hhmmss = (s) => new Date(s * 1000).toLocaleTimeString([], { hourCycle: "h23" });

// ------------------------------------------------------------------ hero and explainers

synthwave(document.querySelector(".hero"));
isometric($("iso"));
merkle($("merkle"), $("maths"));
const story = cartoon($("cartoon"));

// First visit: the short story of a held step, once. Skippable; never again after "Got it".
try {
  if (!localStorage.getItem("hc-onboarded")) {
    const d = $("onboard");
    const shown = cartoon($("onboardCartoon"));
    d.showModal();
    shown.play();
    d.addEventListener("close", () => { try { localStorage.setItem("hc-onboarded", "1"); } catch { /* ignore */ } });
  }
} catch { /* storage blocked: no onboarding, nothing breaks */ }
new IntersectionObserver((entries) => {
  if (entries.some((e) => e.isIntersecting)) story.play();
}, { threshold: 0.5 }).observe($("cartoon"));

// ------------------------------------------------------------------ live sessions

let sessions = [];
let chosen = null;
let chosenView = null;
let shown = 0;
const atom = glowAtom($("atom"), () => ({
  agent: chosenView?.agent, trust: chosenView?.trust,
  counts: chosenView ? countsByKind(chosenView.timeline) : {},
  waiting: chosenView?.waiting?.length || 0,
}));

function countsByKind(timeline) {
  const out = {};
  for (const e of timeline) {
    const k = e.kind === "secret" ? "secret" : e.kind;
    out[k] = (out[k] || 0) + 1;
  }
  return out;
}

function setRecorderState(ok, text) {
  for (const light of document.querySelectorAll('[data-light="recorder"]')) light.classList.toggle("on", ok);
  for (const p of document.querySelectorAll('[data-state="recorder"]')) p.textContent = text;
  $("liveState").textContent = text;
}

async function pollLive() {
  try {
    const response = await fetch("/api/live/sessions");
    const answer = await response.json();
    if (!response.ok) throw new Error(answer.error || "recorder unavailable");
    sessions = answer.sessions || [];
    setRecorderState(true, sessions.length
      ? `Recorder running · ${sessions.length} session${sessions.length > 1 ? "s" : ""}`
      : "Recorder running · no sessions yet. Start one from the extension.");
    renderSessions();
    if (!chosen && sessions.length) choose(sessions.at(-1).session_id);
    if (chosen) await loadSession();
  } catch (error) {
    setRecorderState(false, `Recorder not reachable: ${error.message}. Start python tools/recorder.py, then reload.`);
    sessions = [];
    renderSessions();
  }
}

function renderSessions() {
  bars3d($("bars"), sessions);
  const list = $("sessionList");
  list.textContent = "";
  for (const s of sessions) {
    const b = el("button", { class: "session-btn", type: "button", "aria-pressed": String(s.session_id === chosen) },
      el("b", {}, s.agent), " · ", s.state, s.waiting ? ` · ${s.waiting} waiting` : "", el("span", { class: "muted small" }, ` · ${s.task.slice(0, 60)}`));
    b.addEventListener("click", () => choose(s.session_id));
    list.append(el("li", {}, b));
  }
}

function choose(id) {
  if (chosen === id) return;
  chosen = id;
  shown = 0;
  $("liveRoll").textContent = "";
  renderSessions();
  loadSession();
}

async function loadSession() {
  const response = await fetch(`/api/live/session?id=${encodeURIComponent(chosen)}`);
  if (!response.ok) return;
  chosenView = await response.json();
  $("sessionPanel").hidden = false;
  $("sessionTitle").textContent = `${chosenView.agent} · ${chosenView.state}`;
  const facts = $("sessionFacts");
  facts.textContent = "";
  for (const [k, v] of [
    ["Task", chosenView.task], ["Passport", chosenView.passport.hosts.join(", ")],
    ["Trust", `${chosenView.trust} / 100`], ["Waiting", String(chosenView.waiting.length)],
    ["Receipt", chosenView.receipt || "not sealed yet"],
  ]) facts.append(el("dt", {}, k), el("dd", {}, v));
  for (const e of chosenView.timeline.slice(shown)) printStrip($("liveRoll"), lineFor(e), { prepend: true });
  shown = chosenView.timeline.length;
  atom.redraw();
}

function lineFor(e) {
  return el("li", {},
    el("span", { class: "t" }, hhmmss(e.at)),
    el("span", { class: "k" }, e.kind),
    el("span", { class: `s s-${e.status}` }, e.status.replace("_", " ")),
    e.target ? el("span", { class: "tgt" }, host(e.target)) : null,
    e.reasons?.length ? el("span", { class: "why" }, e.reasons.join(" · ").toLowerCase()) : null,
    e.tripwire ? el("span", { class: "flag" }, `⚠ tripwire: ${e.tripwire.verdict}`) : null);
}

pollLive();
setInterval(() => { if (!document.hidden) pollLive(); }, 3000);

// ------------------------------------------------------------------ receipt viewer

const drop = $("drop");
drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
drop.addEventListener("dragleave", () => drop.classList.remove("over"));
drop.addEventListener("drop", (e) => { e.preventDefault(); drop.classList.remove("over"); inspect([...e.dataTransfer.files]); });
$("files").addEventListener("change", (e) => inspect([...e.target.files]));

async function inspect(files) {
  const receipt = files.find((f) => f.name.endsWith(".abbreceipt"));
  const keys = files.find((f) => f.name.endsWith(".json"));
  const state = $("receiptState");
  if (!receipt) { state.textContent = "Choose a .abbreceipt file."; return; }
  state.textContent = `Checking ${receipt.name}…`;
  const bytes = new Uint8Array(await receipt.arrayBuffer());
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  const response = await fetch("/api/inspect", {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ receipt_b64: btoa(bin), keys_json: keys ? await keys.text() : "" }),
  });
  const answer = await response.json();
  if (!response.ok) { state.textContent = answer.error || "Could not check that receipt."; return; }
  state.textContent = keys
    ? `${receipt.name} checked with its key manifest.`
    : `${receipt.name} checked without a key manifest: signatures are UNKNOWN, never passed.`;
  showReceipt(answer);
}

function showReceipt({ verdict, summary, graph, snapshots }) {
  $("receiptOut").hidden = false;
  const overall = String(verdict.overall || "UNREADABLE");
  const stamp = $("stamp");
  stamp.className = `stamp v-${overall}`;
  stamp.textContent = overall;
  if (!calm() && window.gsap) window.gsap.fromTo(stamp, { scale: 2, rotate: -14, opacity: 0 }, { scale: 1, rotate: -4, opacity: 1, duration: 0.35, ease: "power4.in" });
  dominoes($("dominoes"), verdict.dimensions || {});

  const roll = $("eventRoll");
  roll.textContent = "";
  for (const e of (summary?.events || []).slice(0, 200)) {
    const p = e.payload || {};
    printStrip(roll, el("li", {},
      el("span", { class: "t" }, `#${e.sequence}`),
      el("span", { class: "k" }, e.event_type),
      p.action_type ? el("span", { class: "s" }, p.action_type) : null,
      p.target ? el("span", { class: "tgt" }, host(p.target)) : null,
      p.reason_codes ? el("span", { class: "why" }, p.reason_codes.join(" · ").toLowerCase()) : null));
  }

  const shots = snapshots || [];
  $("replay").hidden = $("scrub").hidden = shots.length === 0;
  $("replayNone").hidden = shots.length > 0;
  if (shots.length) {
    const scrub = $("scrub");
    scrub.max = String(shots.length - 1);
    scrub.value = "0";
    const show = () => {
      const s = shots[Number(scrub.value)];
      $("replayImg").src = s.src;
      $("replayImg").alt = `Page snapshot sealed at event ${s.sequence}`;
      $("replayCap").textContent = `Event #${s.sequence} · sha256 ${s.digest.slice(0, 16)}…`;
    };
    scrub.oninput = show;
    show();
  }

  const g = $("graph");
  g.textContent = "";
  // graph.js declares `graphView` with const in a classic script: a global binding, not a
  // property of window.
  // eslint-disable-next-line no-undef
  if (graph && typeof graphView !== "undefined") g.append(graphView.draw(graph));
}
