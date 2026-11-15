// The public HashCam site. A classic script, so it works from a file:// page as well as from the web.
// Everything runs in the browser:
// * Live: reads YOUR recorder on 127.0.0.1 with its read-only viewer key (sample data until then).
// * Receipts: checked by the HashCam verifier compiled to WebAssembly; files never leave the page.
// Nothing is sent to this site's server, and no other site is contacted.
(function () {
"use strict";

const { dominoes, eventBars, glowAtom, merkle, pipeline, printStrip, synthwave } = window.HCFX;
const M = window.HCMotion;
const R = window.HCReadable;

const $ = (id) => document.getElementById(id);
const el = (tag, cls, ...kids) => {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  for (const kid of kids) if (kid != null) node.append(kid);
  return node;
};
const hhmmss = (s) => new Date(s * 1000).toLocaleTimeString([], { hourCycle: "h23" });
const fromDisk = location.protocol === "file:";

synthwave(document.querySelector(".hero"));
M.hero(document.querySelector(".hero")); // the telemetry core replaces the old REC circle
pipeline($("iso"));
merkle($("merkle"), $("maths"));
const story = M.riskyStep($("cartoon"));
const storyWatch = new IntersectionObserver((entries) => {
  if (entries.some((e) => e.isIntersecting)) { story.play(); storyWatch.disconnect(); } // once; Replay does it again
}, { threshold: 0.5 });
storyWatch.observe($("cartoon"));

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
      { at: 1700000469, kind: "secret", status: "COMMITTED", target: "https://shop.example/login", field_kind: "password" },
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

// Each line is a plain sentence. The raw record is behind a closed "Technical details" opener, and
// is replaced by a note when the agent (or the step) is sensitive.
function drawTimeline(view, reset) {
  const roll = $("liveRoll");
  if (reset) { roll.textContent = ""; shown = 0; }
  const ctx = { agent: view.agent, sensitive: view.sensitive === true };
  for (const e of view.timeline.slice(shown)) {
    printStrip(roll, R.stripNode(document, R.describe(e, ctx), R.technical(e, ctx), hhmmss(e.at)), { prepend: true });
  }
  shown = view.timeline.length;
  atom.redraw();
}

function showSample() {
  current = SAMPLE.view;
  $("sampleNote").hidden = false;
  $("coreTitle").textContent = "Session core (sample)";
  $("sessionList").textContent = "";
  eventBars($("bars"), SAMPLE.sessions);
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
    eventBars($("bars"), sessions);
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
  // The port ends up inside a URL, and a saved one comes back from storage: take only a real port number,
  // and a key without control characters (it goes into a request header).
  port = Number(port);
  if (!Number.isInteger(port) || port < 1024 || port > 65535 || typeof key !== "string" || !/^[\x21-\x7e]{1,256}$/.test(key)) {
    $("liveState").textContent = "That port or key does not look right. The port is a number from 1024 to 65535.";
    return;
  }
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
if (fromDisk) {
  // A page opened from a file has no origin your recorder could trust, so it stays on sample data.
  $("liveState").textContent = "Opened from a file: the live view needs the hosted site (your recorder only answers that address). Showing sample data.";
  $("connect").querySelector("button[type=submit]").disabled = true;
} else {
  try {
    const saved = JSON.parse(sessionStorage.getItem("hc-viewer") || "null");
    if (saved?.key) connect(saved.port, saved.key);
  } catch { /* fine */ }
}

// ================================================================== receipts (WebAssembly verifier)

const { verify, bytesOfB64, offlineData } = window.HCVerify; // verify.js

function showVerdict(report, label) {
  const overall = String(report.overall || "UNREADABLE");
  const stamp = $("stamp");
  stamp.className = `stamp v-${overall}`;
  stamp.textContent = overall;
  const fallback = report.engine === "javascript";
  const clean = fallback && overall === "INCOMPLETE";
  // The run's id, as a digest that scrambles into place whenever a receipt is checked.
  if (report.run_id) M.hexify($("runDigest"), "run " + String(report.run_id).replace(/-/g, ""), "run");
  else $("runDigest").textContent = "";
  $("verdictPlain").textContent = clean
    ? "No problem was found in what the JavaScript fallback checks, but it cannot give a full verdict. Open this page where WebAssembly runs, or use abb verify."
    : R.verdictText(overall);
  $("engineNote").textContent = fallback
    ? `The WebAssembly verifier could not run here (${report.fallback_reason}), so the JavaScript fallback checked this receipt: the event hashes, the signed tree, the signatures and the global log. It does not check coverage, policy or the mandate, so it can say INVALID but never VALID.`
    : "Checked by the HashCam verifier compiled to WebAssembly: the same Rust code as abb verify.";
  dominoes($("dominoes"), report.dimensions || {});
  const details = $("details");
  details.textContent = "";
  for (const d of report.details || []) {
    const status = report.dimensions && report.dimensions[d.dimension];
    details.append(el("li", null, el("b", null, `${R.dimensionText(d.dimension)}${status ? ` (${R.statusText(status)})` : ""}: `), d.message));
  }
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
  try {
    let receipt;
    let keys;
    if (fromDisk) {
      const data = await offlineData();
      receipt = bytesOfB64(data[name]);
      keys = bytesOfB64(data.keys);
    } else {
      const [r, k] = await Promise.all([
        fetch(`samples/${name}.abbreceipt`).then((x) => x.arrayBuffer()),
        fetch("samples/sample.keys.json").then((x) => x.arrayBuffer()),
      ]);
      receipt = new Uint8Array(r);
      keys = new Uint8Array(k);
    }
    await check(receipt, keys, label);
  } catch (error) {
    $("receiptState").textContent = `Could not load the sample: ${error.message}`;
  }
}
$("sampleValid").addEventListener("click", () => sample("genuine", "Sample receipt from a real recorder run, checked in this page."));
$("sampleInvalid").addEventListener("click", () => sample("edited", "The same sample with one event's address changed, checked in this page."));
M.init();
M.tabs(".qs-tabs");
})();
