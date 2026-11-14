// The public HashCam site. Everything runs in the browser:
// * Live: reads YOUR recorder on 127.0.0.1 with its read-only viewer key (sample data until then).
// * Receipts: checked by the HashCam verifier compiled to WebAssembly; files never leave the page.
// Nothing is sent to this site's server.

import { bars3d, cartoon, dominoes, glowAtom, isometric, merkle, printStrip, synthwave } from "./fx3d.js";

const $ = (id) => document.getElementById(id);
const el = (tag, cls, ...kids) => {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  for (const kid of kids) if (kid != null) node.append(kid);
  return node;
};
const hostOf = (u) => { try { const x = new URL(u); return x.host + x.pathname; } catch { return u || ""; } };
const hhmmss = (s) => new Date(s * 1000).toLocaleTimeString([], { hourCycle: "h23" });

synthwave(document.querySelector(".hero"));
isometric($("iso"));
merkle($("merkle"), $("maths"));
const story = cartoon($("cartoon"));
new IntersectionObserver((entries) => {
  if (entries.some((e) => e.isIntersecting)) story.play();
}, { threshold: 0.5 }).observe($("cartoon"));

// ================================================================== live sessions

const SAMPLE = {
  sessions: [
    { agent: "Claude", counts: { allowed: 9, approved: 2, blocked: 1, tripwire: 0 } },
    { agent: "Comet", counts: { allowed: 6, approved: 1, blocked: 3, tripwire: 1 } },
    { agent: "my-agent", counts: { allowed: 4, approved: 0, blocked: 0, tripwire: 0 } },
  ],
  view: {
    agent: "Claude", trust: 75, waiting: [{}], timeline: [
      { at: 1700000462, kind: "navigate", status: "ALLOWED", target: "https://shop.example/checkout" },
      { at: 1700000469, kind: "secret", status: "COMMITTED", target: "https://shop.example/login" },
      { at: 1700000475, kind: "form_submit", status: "APPROVED", target: "https://shop.example/order" },
      { at: 1700000491, kind: "navigate", status: "BLOCKED", target: "https://bank.example/transfer" },
      { at: 1700000500, kind: "download", status: "WAITING", target: "https://shop.example/invoice.pdf" },
    ],
  },
};

let link = null; // { port, key } while connected
let current = SAMPLE.view;
let chosen = null;
let shown = 0;
let poll = null;

const atom = glowAtom($("atom"), () => {
  const counts = {};
  for (const e of current?.timeline || []) counts[e.kind] = (counts[e.kind] || 0) + 1;
  return { agent: current?.agent, trust: current?.trust, counts, waiting: current?.waiting?.length || 0 };
});

function drawTimeline(view, reset) {
  const roll = $("liveRoll");
  if (reset) { roll.textContent = ""; shown = 0; }
  for (const e of view.timeline.slice(shown)) {
    printStrip(roll, el("li", null,
      el("span", "t", hhmmss(e.at)), el("span", "k", e.kind),
      el("span", `s s-${e.status}`, e.status.replace("_", " ")),
      e.target ? el("span", "tgt", hostOf(e.target)) : null,
      e.tripwire ? el("span", "flag", `⚠ tripwire: ${e.tripwire.verdict}`) : null), { prepend: true });
  }
  shown = view.timeline.length;
  atom.redraw();
}

function showSample() {
  current = SAMPLE.view;
  $("sampleNote").hidden = false;
  $("coreTitle").textContent = "Session core (sample)";
  $("sessionList").textContent = "";
  bars3d($("bars"), SAMPLE.sessions);
  drawTimeline(SAMPLE.view, true);
}

async function recorder(path) {
  const response = await fetch(`http://127.0.0.1:${link.port}${path}`, {
    headers: { "X-HashCam-Token": link.key },
    // Chrome's Local Network Access: say that this request is meant for this computer.
    targetAddressSpace: "loopback",
    cache: "no-store",
  });
  if (!response.ok) {
    const answer = await response.json().catch(() => ({}));
    throw new Error(answer.error || `the recorder answered ${response.status}`);
  }
  return response.json();
}

async function refreshLive() {
  try {
    const { sessions } = await recorder("/sessions");
    $("liveState").textContent = sessions.length
      ? `Connected to your recorder · ${sessions.length} session${sessions.length > 1 ? "s" : ""}`
      : "Connected to your recorder · no sessions yet. Start one from the extension.";
    $("sampleNote").hidden = true;
    bars3d($("bars"), sessions);
    const list = $("sessionList");
    list.textContent = "";
    for (const s of sessions) {
      const b = el("button", "session-btn", el("b", null, s.agent), ` · ${s.state}`, s.waiting ? ` · ${s.waiting} waiting` : "");
      b.type = "button";
      b.setAttribute("aria-pressed", String(s.session_id === chosen));
      b.addEventListener("click", () => { chosen = s.session_id; refreshLive(); });
      list.append(el("li", null, b));
    }
    if (!chosen && sessions.length) chosen = sessions.at(-1).session_id;
    if (chosen) {
      const fresh = current === SAMPLE.view || current.session_id !== chosen;
      current = await recorder(`/sessions/${chosen}`);
      $("coreTitle").textContent = `${current.agent} · ${current.state}`;
      drawTimeline(current, fresh);
    }
  } catch (error) {
    $("liveState").textContent = `Could not reach your recorder: ${error.message}. Is it running, and is the key right?`;
  }
}

function connect(port, key) {
  link = { port, key };
  try { sessionStorage.setItem("hc-viewer", JSON.stringify(link)); } catch { /* fine */ }
  $("disconnect").hidden = false;
  $("liveState").textContent = "Connecting…";
  chosen = null;
  refreshLive();
  clearInterval(poll);
  poll = setInterval(() => { if (!document.hidden) refreshLive(); }, 3000);
}

$("connect").addEventListener("submit", (event) => {
  event.preventDefault();
  const key = $("viewerKey").value.trim();
  $("viewerKey").value = "";
  if (key) connect(Number($("viewerPort").value) || 8770, key);
});
$("disconnect").addEventListener("click", () => {
  clearInterval(poll);
  link = null;
  try { sessionStorage.removeItem("hc-viewer"); } catch { /* fine */ }
  $("disconnect").hidden = true;
  $("liveState").textContent = "Not connected: showing sample data.";
  showSample();
});

showSample();
try {
  const saved = JSON.parse(sessionStorage.getItem("hc-viewer") || "null");
  if (saved?.key) connect(saved.port, saved.key);
} catch { /* fine */ }

// ================================================================== receipts (WebAssembly verifier)

let wasm = null;
async function verifier() {
  if (!wasm) {
    const { instance } = await WebAssembly.instantiateStreaming(fetch("verifier.wasm"), {});
    wasm = instance.exports;
  }
  return wasm;
}

function put(exports, bytes) {
  if (!bytes.length) return 0;
  const ptr = exports.abb_alloc(bytes.length);
  new Uint8Array(exports.memory.buffer, ptr, bytes.length).set(bytes);
  return ptr;
}

// The same function as `abb verify --json`: returns the verifier's report, word for word.
async function verify(receiptBytes, keysBytes) {
  const x = await verifier();
  const rp = put(x, receiptBytes);
  const kp = put(x, keysBytes);
  const packed = x.abb_verify(rp, receiptBytes.length, kp, keysBytes.length, 0);
  x.abb_free(rp, receiptBytes.length);
  x.abb_free(kp, keysBytes.length);
  const ptr = Number(packed >> 32n);
  const len = Number(packed & 0xffffffffn);
  const json = new TextDecoder().decode(new Uint8Array(x.memory.buffer, ptr, len).slice());
  x.abb_free(ptr, len);
  return JSON.parse(json);
}

function showVerdict(report, label) {
  const overall = String(report.overall || "UNREADABLE");
  const stamp = $("stamp");
  stamp.className = `stamp v-${overall}`;
  stamp.textContent = overall;
  dominoes($("dominoes"), report.dimensions || {});
  const details = $("details");
  details.textContent = "";
  for (const d of report.details || []) details.append(el("li", null, `${d.dimension}: ${d.message}`));
  if (report.message) details.append(el("li", null, report.message));
  $("detailsBox").hidden = !details.children.length;
  $("receiptState").textContent = label;
}

async function check(receiptBytes, keysBytes, label) {
  $("receiptState").textContent = "Checking…";
  try {
    showVerdict(await verify(receiptBytes, keysBytes), label);
  } catch (error) {
    $("receiptState").textContent = `The verifier could not run here: ${error.message}`;
  }
}

async function bytesOf(file) { return new Uint8Array(await file.arrayBuffer()); }

async function fromFiles(files) {
  const receipt = files.find((f) => f.name.endsWith(".abbreceipt"));
  const keys = files.find((f) => f.name.endsWith(".json"));
  if (!receipt) { $("receiptState").textContent = "Choose a .abbreceipt file."; return; }
  await check(await bytesOf(receipt), keys ? await bytesOf(keys) : new Uint8Array(),
    keys ? `${receipt.name}, checked with its key manifest.`
      : `${receipt.name}, checked without a key manifest: signatures are UNKNOWN, never passed.`);
}

const drop = $("drop");
drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
drop.addEventListener("dragleave", () => drop.classList.remove("over"));
drop.addEventListener("drop", (e) => { e.preventDefault(); drop.classList.remove("over"); fromFiles([...e.dataTransfer.files]); });
$("files").addEventListener("change", (e) => fromFiles([...e.target.files]));

async function sample(name, label) {
  const [r, k] = await Promise.all([
    fetch(`samples/${name}.abbreceipt`).then((x) => x.arrayBuffer()),
    fetch("samples/sample.keys.json").then((x) => x.arrayBuffer()),
  ]);
  await check(new Uint8Array(r), new Uint8Array(k), label);
}
$("sampleValid").addEventListener("click", () => sample("genuine", "Sample receipt from a real recorder run, checked in this page."));
$("sampleInvalid").addEventListener("click", () => sample("edited", "The same sample with one event's address changed, checked in this page."));
