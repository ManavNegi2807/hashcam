// The Range page. A classic script (it works from a file:// page) with no libraries. Everything happens in
// this tab: the files you drop are read here, checked here and never sent anywhere.
(function () {
"use strict";

const D = window.HCRangeData;
const S = window.HCScore;
const L = window.HCLimits;
const C = window.HCChain;
const V = window.HCVerify;
const PLAN = "anonymous";
const levels = D.levels;
const ids = levels.map((l) => l.id);
const $ = (id) => document.getElementById(id);
const el = (tag, attrs = {}, ...kids) => {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v; else node.setAttribute(k, v);
  }
  for (const kid of kids) if (kid != null) node.append(kid instanceof Node ? kid : String(kid));
  return node;
};
const calm = () => matchMedia("(prefers-reduced-motion: reduce)").matches;

// Where the agent should go. From a file:// page there is no address of its own, so it names the hosted site.
const fromDisk = location.protocol === "file:";
const siteBase = fromDisk ? "https://hashcam.vercel.app" : new URL(".", location.href).href.replace(/\/$/, "");
const siteHost = fromDisk ? "hashcam.vercel.app" : location.hostname;

// ------------------------------------------------------------------ limits (shown, not enforced)

(function showLimits() {
  const lim = L.limitsFor(PLAN);
  const rows = [
    ["Plan", lim.name], ["Runs per day", lim.runs_per_day], ["Steps per run", lim.steps_per_run],
    ["Minutes per run", lim.minutes_per_run], ["Levels", `${lim.scenarios.length} of ${levels.length}`],
    ["Runs at once", lim.concurrent_runs], ["History kept", lim.history_days ? `${lim.history_days} days` : "none"],
  ];
  const list = $("limitList");
  for (const [name, value] of rows) list.append(el("div", {}, el("dt", {}, name), el("dd", {}, String(value))));
  $("limitNote").textContent = L.ENFORCED
    ? "These limits are enforced."
    : "These limits are shown, not enforced yet: this early version has no accounts and no server, and nothing is counted. " +
      "Levels marked “with an account” still run here.";
})();

// ------------------------------------------------------------------ the levels

const chip = (text, extra) => el("span", { class: "lv-chip" + (extra ? " " + extra : "") }, text);

for (const level of levels) {
  const locked = !L.allowed(PLAN, level.id);
  $("levelGrid").append(el("article", { class: "card level", "data-level": level.id, "data-reveal": "" },
    el("header", {}, el("span", { class: "lv-n" }, String(level.n).padStart(2, "0")), el("h3", {}, level.title)),
    el("div", { class: "lv-chips" }, chip(level.difficulty),
      chip(level.source === "sandbox" ? "Sandbox record" : "Extension receipt"),
      locked ? chip("With an account · coming soon", "lock") : null),
    el("p", { class: "muted" }, level.goal),
    el("ul", { class: "lv-looks" }, ...level.looks_at.map((t) => el("li", {}, t))),
    el("button", { class: "btn small", type: "button", "data-start": level.id }, "Start this level")));
  $("scoreLevel").append(el("option", { value: level.id }, `${level.n}. ${level.title}`));
}

let current = null;
let label = "";

function newLabel() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = crypto.getRandomValues(new Uint8Array(6));
  return "RNG-" + Array.from(bytes, (b) => alphabet[b % alphabet.length]).join("");
}

function fill(text) {
  return text.replaceAll("{site}", siteBase).replaceAll("{host}", siteHost).replaceAll("{label}", label);
}

function selectLevel(id, { scroll = true } = {}) {
  const level = levels.find((l) => l.id === id);
  if (!level) return;
  current = level;
  label = newLabel();
  for (const card of document.querySelectorAll(".level")) card.classList.toggle("on", card.dataset.level === id);
  $("run").hidden = false;
  $("runGoal").textContent = `Level ${level.n} · ${level.title}. ${level.goal}`;
  $("runLabel").textContent = label;
  $("taskText").value = fill(level.task);
  $("copyNote").textContent = "";
  $("scoreLevel").value = id;
  const steps = $("runSteps");
  steps.textContent = "";
  if (level.source === "sandbox") {
    steps.append(
      el("li", {}, "Let your agent open ", el("a", { href: `${siteBase}/sandbox.html` }, `${siteBase}/sandbox.html`),
        ". It runs in the browser; nothing is sent anywhere."),
      el("li", {}, "Give it the task above."),
      el("li", {}, "When it is done, press “Export Verified Receipt (.html)” on that page (or ask your agent to) and keep the file."),
      el("li", {}, "Come back here and drop that file under “Score my run”."));
    $("passport").hidden = true;
  } else {
    steps.append(
      el("li", {}, "In the HashCam extension, arm the agent's tab with the passport below."),
      el("li", {}, "Give your agent the task above."),
      el("li", {}, "When it is done, press Stop & seal and save the receipt: that gives you a .abbreceipt and its .keys.json."),
      el("li", {}, "Drop both files under “Score my run”."));
    $("pHosts").textContent = siteHost;
    $("pMinutes").textContent = String(level.passport_minutes || 15);
    $("pTask").textContent = `Range level ${level.n} · run ${label}`;
    $("passport").hidden = false;
  }
  history.replaceState(null, "", `#level=${id}`);
  if (scroll) $("run").scrollIntoView({ block: "start", behavior: calm() ? "auto" : "smooth" });
}

$("levelGrid").addEventListener("click", (e) => {
  const button = e.target.closest("[data-start]");
  if (button) selectLevel(button.dataset.start);
});

async function copy(text, note) {
  try {
    await navigator.clipboard.writeText(text);
    note.textContent = "Copied.";
  } catch {
    const box = el("textarea", { "aria-hidden": "true" });
    box.value = text;
    document.body.append(box);
    box.select();
    let done = false;
    try { done = document.execCommand("copy"); } catch { /* fine */ }
    box.remove();
    note.textContent = done ? "Copied." : "Select the text and copy it yourself.";
  }
}
$("copyTask").addEventListener("click", () => copy($("taskText").value, $("copyNote")));

// ------------------------------------------------------------------ the files

const input = $("files");
const drop = $("drop");

function listFiles() {
  const list = $("fileList");
  list.textContent = "";
  for (const file of input.files) list.append(el("li", {}, `${file.name} · ${Math.max(1, Math.round(file.size / 1024))} KB`));
  $("scoreNote").textContent = "";
}
input.addEventListener("change", listFiles);
drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
drop.addEventListener("dragleave", () => drop.classList.remove("over"));
drop.addEventListener("drop", (e) => {
  e.preventDefault();
  drop.classList.remove("over");
  if (e.dataTransfer && e.dataTransfer.files.length) {
    input.files = e.dataTransfer.files;
    listFiles();
  }
});

// ------------------------------------------------------------------ checking a record, then scoring it

const MAX_FILES = 4;
const MAX_BYTES = 8 * 1048576;

function sandboxExportOf(text) {
  let json = text;
  if (/^\s*</.test(text)) {
    // Cut the record out as text. Parsing a stranger's whole HTML file (DOMParser) would make the browser
    // read its styles and markup; this page only ever wants the one JSON block inside it.
    const open = text.match(/<script type="application\/json" id="receipt">/);
    const end = open ? text.indexOf("</script>", open.index + open[0].length) : -1;
    if (!open || end < 0) throw new Error("That HTML file is not a sandbox receipt: it has no record inside.");
    json = text.slice(open.index + open[0].length, end);
  }
  let data;
  try { data = JSON.parse(json); } catch { throw new Error("The record in that file could not be read."); }
  if (!data || data.format !== "hashcam-sandbox-receipt/1" || !Array.isArray(data.events) || !data.public_key_jwk) {
    throw new Error("That file is not a Gatekeeper Sandbox receipt.");
  }
  return data;
}

async function scoreSandboxFile(level, files) {
  const file = files.find((f) => /\.(html?|json)$/i.test(f.name) && !/\.keys\.json$/i.test(f.name));
  if (!file) throw new Error("Drop the receipt you exported from the sandbox (a .html file).");
  const data = sandboxExportOf(await file.text());
  const check = await C.verifyChain(data.events, data.public_key_jwk);
  if (!check.ok) {
    return { result: S.refusal(`This record does not check out: event #${check.firstBad} no longer matches its fingerprint or its signature, so it is not scored.`), engine: "" };
  }
  return {
    result: S.scoreSandbox(level, data.events),
    engine: "Checked here: every event's fingerprint and the signatures re-computed and they match. That shows the record was not edited after it was made. A sandbox record cannot prove where it came from (the extension's signed receipt can).",
  };
}

async function scoreReceiptFile(level, files) {
  const receipt = files.find((f) => /\.abbreceipt$/i.test(f.name));
  if (!receipt) throw new Error("Drop the .abbreceipt your extension saved (and its .keys.json).");
  const keys = files.find((f) => /\.keys\.json$/i.test(f.name));
  const bytes = new Uint8Array(await receipt.arrayBuffer());
  const keyBytes = keys ? new Uint8Array(await keys.arrayBuffer()) : new Uint8Array();
  const report = await V.verify(bytes, keyBytes);
  const verdict = String(report.overall || "UNREADABLE");
  const via = report.engine === "wasm" ? "the HashCam verifier (WebAssembly)" : "the JavaScript fallback";
  if (verdict !== "VALID") {
    const why = verdict === "INVALID" ? "The receipt does not check out: something in it was changed or does not add up."
      : verdict === "INCOMPLETE" ? `The verdict is INCOMPLETE (checked by ${via})${keys ? "" : "; no .keys.json was dropped, so signatures could not be checked"}. A run is only scored when the whole receipt is VALID.`
        : `The receipt could not be read (verdict ${verdict}).`;
    return { result: S.refusal(`${why} It is not scored.`), engine: "" };
  }
  const events = await window.HCFallback.readEvents(bytes);
  return {
    result: S.scoreReceipt(level, events, { siteHost }),
    engine: `Verdict VALID from ${via}. The extension watches page loads, form submits and downloads in one tab; requests a page's own scripts send are not seen.`,
  };
}

// ------------------------------------------------------------------ showing the result

let last = null;
let lastRun = null; // what the report is written from: the level, the result and how it was checked

function badgeNode(svg) {
  const doc = new DOMParser().parseFromString(svg, "image/svg+xml");
  return document.importNode(doc.documentElement, true);
}

function showResult(level, result, engine) {
  const box = $("result");
  box.hidden = false;
  const overall = result.overall;
  const head = $("overall");
  head.className = "rg-overall " + overall.replace(/\s/g, "");
  head.textContent = overall;
  const list = $("criteria");
  list.textContent = "";
  $("badge").textContent = "";
  last = null;
  if (!result.scored) {
    $("tally").textContent = result.reason;
    $("engine").textContent = "";
  } else {
    $("tally").textContent = `Level ${level.n} · ${level.title}: ${result.tally.pass} of ${result.tally.total} checks passed.`;
    for (const c of result.criteria) {
      list.append(el("li", { class: c.status },
        el("span", { class: "rg-st" }, c.status),
        el("span", { class: "rg-what" }, el("b", {}, c.label), el("span", {}, c.evidence))));
    }
    $("engine").textContent = engine;
    last = { v: 1, level: level.id, overall, pass: result.tally.pass, total: result.tally.total, source: result.source, at: new Date().toISOString().slice(0, 10) };
    $("badge").append(badgeNode(S.badgeSvg("HashCam Range", `Level ${level.n} · ${overall}`, overall)));
  }
  for (const id of ["copyLink", "copyMd", "saveBadge"]) $(id).disabled = !last;
  $("shareNote").textContent = "";
  lastRun = { level, result, engine, files: [], at: new Date().toISOString().slice(0, 10) };
  $("reportBtn").disabled = false;
  $("reportKey").hidden = true;
  $("reportPass").textContent = "";
  $("reportNote").textContent = "";
  box.scrollIntoView({ block: "start", behavior: calm() ? "auto" : "smooth" });
}

$("scoreBtn").addEventListener("click", async () => {
  const level = levels.find((l) => l.id === $("scoreLevel").value);
  const files = [...input.files];
  const note = $("scoreNote");
  if (!files.length) { note.textContent = "Choose or drop the record of your run first."; return; }
  // A record is a few hundred KB at most. A huge or long list of files is refused before anything is read,
  // so a stranger's file cannot freeze the tab.
  if (files.length > MAX_FILES || files.some((f) => f.size > MAX_BYTES)) {
    note.textContent = `Too much to check: drop at most ${MAX_FILES} files, each under ${MAX_BYTES / 1048576} MB.`;
    return;
  }
  note.textContent = "Checking the record…";
  $("scoreBtn").disabled = true;
  try {
    const { result, engine } = level.source === "sandbox" ? await scoreSandboxFile(level, files) : await scoreReceiptFile(level, files);
    note.textContent = "";
    showResult(level, result, engine);
    // The report names the record it was written from, by fingerprint.
    for (const f of files) {
      const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", await f.arrayBuffer()));
      lastRun.files.push({ name: f.name.slice(0, 80), sha256: Array.from(hash, (b) => b.toString(16).padStart(2, "0")).join("") });
    }
  } catch (error) {
    note.textContent = String((error && error.message) || error);
  } finally {
    $("scoreBtn").disabled = false;
  }
});

// ------------------------------------------------------------------ the report (a PDF that needs a password)

$("reportBtn").addEventListener("click", async () => {
  if (!lastRun) return;
  const note = $("reportNote");
  $("reportBtn").disabled = true;
  note.textContent = "Writing and locking the report…";
  try {
    const { bytes, password } = await window.HCReport.build(lastRun);
    const link = el("a", { href: URL.createObjectURL(new Blob([bytes], { type: "application/pdf" })), download: `hashcam-range-level-${lastRun.level.n}-report.pdf` });
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(link.href), 4000);
    // The password lives only on this page, until the next report or a reload. It is not stored or sent.
    $("reportPass").textContent = password;
    $("reportKey").hidden = false;
    note.textContent = "Saved. Each report gets its own new password.";
  } catch (error) {
    note.textContent = `The report could not be made: ${String((error && error.message) || error)}`;
  } finally {
    $("reportBtn").disabled = false;
  }
});
$("copyPass").addEventListener("click", async () => {
  const note = $("reportNote");
  try {
    await navigator.clipboard.writeText($("reportPass").textContent);
    note.textContent = "Password copied. Keep it apart from the file.";
  } catch {
    note.textContent = "Select the password and copy it yourself.";
  }
});

// ------------------------------------------------------------------ sharing (a summary in the URL fragment)

function shareUrl() {
  const url = new URL(location.href);
  url.search = "";
  url.hash = "r=" + S.encodeShare(last);
  return url.href;
}
const titleOf = () => {
  const level = levels.find((l) => l.id === last.level);
  return `HashCam Range · Level ${level.n} · ${last.overall}`;
};
$("copyLink").addEventListener("click", () => last && copy(shareUrl(), $("shareNote")));
$("copyMd").addEventListener("click", () => last && copy(`[${titleOf()}](${shareUrl()})`, $("shareNote")));
$("saveBadge").addEventListener("click", () => {
  if (!last) return;
  const level = levels.find((l) => l.id === last.level);
  const blob = new Blob([S.badgeSvg("HashCam Range", `Level ${level.n} · ${last.overall}`, last.overall)], { type: "image/svg+xml" });
  const link = el("a", { href: URL.createObjectURL(blob), download: `hashcam-range-level-${level.n}.svg` });
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(link.href), 4000);
});

// A result that arrived as a link: checked field by field, shown as text, and said not to be a proof.
(function showShared() {
  const m = /^#r=([A-Za-z0-9_-]+)$/.exec(location.hash);
  if (!m) return;
  const box = $("shared");
  box.hidden = false;
  const s = S.decodeShare(m[1], ids);
  if (!s) {
    box.append(el("h2", {}, "A shared result"), el("p", {}, "This link's result could not be read, so nothing is shown."));
    return;
  }
  const level = levels.find((l) => l.id === s.level);
  box.append(
    el("h2", {}, "A shared result"),
    el("p", { class: "rg-overall " + s.overall }, s.overall),
    el("p", {}, `Level ${level.n} · ${level.title}: ${s.pass} of ${s.total} checks passed, on ${s.at}.`),
    el("p", { class: "muted small" }, "This is a summary from a link, not a proof. To check it, run the level yourself and drop the record below."),
    badgeNode(S.badgeSvg("HashCam Range", `Level ${level.n} · ${s.overall}`, s.overall)));
})();

// ------------------------------------------------------------------ start

const deep = /^#level=([a-z0-9-]+)$/.exec(location.hash);
if (deep && ids.includes(deep[1])) selectLevel(deep[1], { scroll: false });
// The limits and the levels are drawn by this script, after the first paint. Until then the sections are
// hidden (range.css), so they appear in place instead of jumping down the page.
document.querySelector("main.rg").classList.add("ready");
if (window.HCMotion) window.HCMotion.init();
})();
