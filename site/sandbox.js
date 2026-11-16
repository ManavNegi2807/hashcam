// The HashCam Gatekeeper Sandbox. A classic script (it works from a file:// page) with no libraries:
// SHA-256 and ECDSA P-256 come from the browser's own Web Crypto, and nothing leaves this tab.
//
// What is real here: the policy decision is deterministic code; every event is hash-chained; the
// approval is a real ECDSA signature by a key made when the page opened; tampering is detected by
// recomputing the whole chain. What is simulated: the agent, the money and the format (see chain.js).
(function () {
"use strict";

const C = window.HCChain;
const { verifyChain } = C;
const $ = (id) => document.getElementById(id);
// A digest that changed scrambles into place (motion.js); the page still works without it.
const hexify = (node, text, key) => (window.HCMotion ? window.HCMotion.hexify(node, text, key) : (node.textContent = text));
const clone = (v) => JSON.parse(JSON.stringify(v));

// ------------------------------------------------------------------ helpers the exported receipt reuses
// (plain function declarations that depend on nothing outside themselves: the export embeds their source)

function money(cents) {
  return "$" + (Number(cents) / 100).toFixed(2);
}

function kindLabel(type) {
  const labels = {
    SESSION_STARTED: "Session opened", ACTION_REQUESTED: "Request", POLICY_DECISION: "Decision",
    HUMAN_DECISION: "Person's decision", ACTION_DISPATCHED: "Went ahead", SESSION_HALTED: "Halted",
  };
  return labels[type] || "Event";
}

// One event as a plain sentence. The exported receipt embeds this function's source, so it depends
// on nothing but money().
function summarize(ev) {
  const b = ev && ev.body;
  if (!b || typeof b !== "object" || !b.data || typeof b.data !== "object") return "This event can no longer be read.";
  const d = b.data;
  switch (b.type) {
    case "SESSION_STARTED": return "Session opened with a " + money(d.budget_cents) + " budget, under policy " + d.policy + ".";
    case "ACTION_REQUESTED":
      return "Asked to run “" + d.label + "”: " + (Number(d.amount_cents) ? "costs " + money(d.amount_cents) : "free") + ", on " + d.domain + ".";
    case "POLICY_DECISION":
      return (d.outcome === "ALLOW" ? "Allowed" : d.outcome === "DENY" ? "Denied" : "Held for a person to sign") + ": " + d.trigger_reason + ".";
    case "HUMAN_DECISION":
      return (d.decision === "GRANTED" ? "A person approved it" : "A person rejected it") + ", signed with key " + d.key_id + ".";
    case "ACTION_DISPATCHED": return "Went ahead: " + money(d.amount_cents) + " spent, " + money(d.escrow_after_cents) + " left.";
    case "SESSION_HALTED": return "Session halted: " + d.reason + ".";
    default: return "An event of an unknown kind.";
  }
}

// ------------------------------------------------------------------ the deterministic policy

// The standard policy, or a custom one a link asked for (#policy=..., made in the Policy Studio). Both come from
// policy.js, which checks a custom policy field by field; a link that does not check out is ignored and said so.
const asked = window.HCPolicy.fromHash(location.hash);
const POLICY = asked.state === "ok" ? asked.policy : window.HCPolicy.STANDARD;

const ACTIONS = {
  docs: { action: "read_repo_docs", label: "Read Repo Docs", amount_cents: 0, domain: "docs.github.com", target: "https://docs.github.com/en/repositories" },
  webhook: { action: "sync_external_webhook", label: "Sync External Webhook", amount_cents: 0, domain: "hooks.partner-sync.example", target: "https://hooks.partner-sync.example/v1/sync" },
  gpu: { action: "provision_sandbox_gpu", label: "Provision Sandbox GPU", amount_cents: 3500, domain: "api.gpu-cloud.example", target: "https://api.gpu-cloud.example/v1/instances" },
  bulk: { action: "bulk_token_purchase", label: "Bulk Token Purchase", amount_cents: 25000, domain: "tokens.example-bank.test", target: "https://tokens.example-bank.test/v1/purchase" },
};

const decide = (a, spentCents) => window.HCPolicy.decide(a, spentCents, POLICY);

// ------------------------------------------------------------------ state

let keys = null;
let sessionJwk = null;
let keyId = "";
let ledger = [];          // the real record: [{ body, prev, hash }]
let working = [];         // what the verifier is shown: a copy, edited in tamper mode
let rawTexts = {};        // index -> text that is not valid JSON (kept so typing is not lost)
let state = "starting";   // starting | idle | held | halted
let pending = null;       // { req, dec, action } while the gate is held
let tamper = false;
let busy = false;
let selected = -1;        // index (in the ledger) of the decision the radar is explaining
let flash = "";           // a short-lived gate state ("released")
let verifySeq = 0;
let lastVerify = null;

const spentCents = () => ledger.reduce((t, e) => t + (e.body.type === "ACTION_DISPATCHED" ? Number(e.body.data.amount_cents) : 0), 0);
const dirty = () => C.canon(working) !== C.canon(ledger);

async function append(type, data) {
  const body = { v: 1, n: ledger.length, ts: Date.now(), type, data };
  const prev = ledger.length ? ledger[ledger.length - 1].hash : C.ZERO;
  const hash = await C.eventHash(prev, body);
  const ev = { body, prev, hash };
  ledger.push(ev);
  working = clone(ledger);
  return ev;
}

// ------------------------------------------------------------------ the session

async function startSession() {
  busy = true;
  state = "starting";
  tamper = false;
  pending = null;
  selected = -1;
  rawTexts = {};
  ledger = [];
  working = [];
  lastVerify = null;
  renderAll();
  keys = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  const jwk = await crypto.subtle.exportKey("jwk", keys.publicKey);
  sessionJwk = { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };
  keyId = (await C.sha256hex(C.canon(sessionJwk))).slice(0, 16);
  const started = { policy: POLICY.id, budget_cents: POLICY.budget_cents, key_id: keyId, public_key_jwk: sessionJwk };
  // A custom policy is written into the first event, so the hash chain commits to the rules that were used.
  if (POLICY.id === window.HCPolicy.CUSTOM_ID) started.policy_spec = JSON.parse(JSON.stringify(POLICY));
  await append("SESSION_STARTED", started);
  state = "idle";
  busy = false;
  await refresh();
}

async function fly(name) {
  if (busy || state !== "idle" || tamper || dirty()) return;
  busy = true;
  renderControls();
  try {
    const a = ACTIONS[name];
    const spent = spentCents();
    const req = await append("ACTION_REQUESTED", {
      action: a.action, label: a.label, amount_cents: a.amount_cents, domain: a.domain, target: a.target,
      spent_before_cents: spent, budget_cents: POLICY.budget_cents,
    });
    const d = decide(a, spent);
    const dec = await append("POLICY_DECISION", {
      request_hash: req.hash, policy: POLICY.id, rule_id: d.rule_id, rule: d.rule, outcome: d.outcome,
      trigger_reason: d.trigger_reason, domain_check: d.domain_check, deterministic: true,
    });
    selected = dec.body.n;
    if (d.outcome === "ALLOW") await dispatch(req, a);
    else if (d.outcome === "HOLD") { pending = { req, dec, action: a }; state = "held"; }
  } finally {
    busy = false;
  }
  await refresh();
}

async function dispatch(req, a) {
  await append("ACTION_DISPATCHED", {
    request_hash: req.hash, label: a.label, amount_cents: a.amount_cents,
    escrow_after_cents: POLICY.budget_cents - spentCents() - a.amount_cents,
  });
}

async function resolveHold(decision) {
  if (busy || state !== "held" || tamper || dirty()) return;
  busy = true;
  renderControls();
  try {
    const signature = await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" }, keys.privateKey, C.approvalBytes(decision, pending.req.hash));
    await append("HUMAN_DECISION", {
      decision, request_hash: pending.req.hash, key_id: keyId, signature: C.toB64(new Uint8Array(signature)),
    });
    if (decision === "GRANTED") {
      await dispatch(pending.req, pending.action);
      state = "idle";
      flash = "released";
      setTimeout(() => { flash = ""; renderGate(); }, 1800);
    } else {
      await append("SESSION_HALTED", { reason: "a person rejected the held action" });
      state = "halted";
    }
    pending = null;
  } finally {
    busy = false;
  }
  await refresh();
}

// ------------------------------------------------------------------ rendering

const SVG = "http://www.w3.org/2000/svg";
function svgEl(tag, attrs) {
  const node = document.createElementNS(SVG, tag);
  for (const k of Object.keys(attrs)) node.setAttribute(k, attrs[k]);
  return node;
}

async function refresh() {
  renderMeter();
  renderGate();
  renderRadar();
  renderWhy();
  renderLedger();
  renderControls();
  hexify($("keyLine"), keyId ? `key id ${keyId} · P-256 · public key x ${sessionJwk.x.slice(0, 14)}…` : "Making a key…", "key");
  await refreshVerify();
}

function renderAll() {
  renderMeter();
  renderGate();
  renderControls();
}

function renderMeter() {
  const spent = ledger.length ? spentCents() : 0;
  const held = pending ? pending.action.amount_cents : 0;
  const left = POLICY.budget_cents - spent;
  const pct = (c) => (Math.max(0, c) / POLICY.budget_cents) * 100 + "%";
  $("liquid").style.setProperty("--level", pct(left));
  $("meterHold").style.setProperty("--bottom", pct(left - held));
  $("meterHold").style.setProperty("--sy", String(Math.max(0, held) / POLICY.budget_cents));
  $("meterHold").hidden = held === 0;
  $("mCap").textContent = money(POLICY.budget_cents);
  $("mSpent").textContent = money(spent);
  $("mHeld").textContent = money(held);
  $("mLeft").textContent = money(left - held);   // spent + held + left always adds up to the cap
  $("meter").setAttribute("aria-label", `Escrow budget: ${money(left - held)} left of ${money(POLICY.budget_cents)}` +
    (held ? `, ${money(held)} held for sign-off` : ""));
}

function renderGate() {
  const gate = $("gate");
  const shown = flash || state;
  gate.dataset.state = shown;
  const text = {
    starting: "Starting a session…",
    idle: "Gate open. The agent may act within policy.",
    held: "POLICY_HOLD: the agent is frozen until a person signs.",
    released: "Authorized. Your signature is in the ledger and the agent may continue.",
    halted: "Rejected. The session is halted: reset it to start again.",
  }[shown];
  $("gateState").textContent = text;
  const what = $("gateWhat");
  if (pending) {
    what.hidden = false;
    hexify(what, `You are asked to approve: ${pending.action.label} · ${money(pending.action.amount_cents)} · ${pending.action.domain}. ` +
      `Your signature covers the SHA-256 of exactly this request (${pending.req.hash.slice(0, 12)}…).`, "gate");
  } else {
    what.hidden = true;
  }
}

function blipStatus(dec) {
  const d = dec.body.data;
  if (d.outcome === "ALLOW") return "allow";
  if (d.outcome === "DENY") return "deny";
  const human = ledger.find((e) => e.body.type === "HUMAN_DECISION" && e.body.data.request_hash === d.request_hash);
  if (!human) return "hold";
  return human.body.data.decision === "GRANTED" ? "released" : "deny";
}

function renderRadar() {
  const g = $("blips");
  g.textContent = "";
  const decisions = ledger.filter((e) => e.body.type === "POLICY_DECISION");
  $("radarEmpty").hidden = decisions.length > 0;
  for (const dec of decisions) {
    const angle = (parseInt(dec.hash.slice(0, 6), 16) / 0xffffff) * Math.PI * 2;
    const radius = 26 + (parseInt(dec.hash.slice(6, 12), 16) / 0xffffff) * 80;
    const cx = 120 + radius * Math.cos(angle);
    const cy = 120 + radius * Math.sin(angle);
    const status = blipStatus(dec);
    const req = ledger.find((e) => e.hash === dec.body.data.request_hash);
    if (status === "hold") g.append(svgEl("circle", { cx, cy, r: 7, class: "pulse" }));
    const blip = svgEl("circle", {
      cx, cy, r: 7, class: `blip ${status}${dec.body.n === selected ? " sel" : ""}`, tabindex: 0, role: "button",
      "aria-label": `${req.body.data.label}: ${dec.body.data.outcome}. Show why.`,
    });
    const pick = () => { selected = dec.body.n; renderRadar(); renderWhy(); };
    blip.addEventListener("click", pick);
    blip.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); pick(); } });
    g.append(blip);
  }
}

function renderWhy() {
  const box = $("why");
  box.textContent = "";
  const dec = ledger.find((e) => e.body.n === selected && e.body.type === "POLICY_DECISION");
  if (!dec) return;
  const d = dec.body.data;
  const req = ledger.find((e) => e.hash === d.request_hash);
  const again = decide(req.body.data, req.body.data.spent_before_cents);
  const same = again.rule_id === d.rule_id && again.outcome === d.outcome;
  const rows = [
    ["RULE_ID", `${d.rule_id} · ${d.rule}`],
    ["TRIGGER_REASON", d.trigger_reason],
    ["DOMAIN_CHECK", `${d.domain_check} · ${req.body.data.domain}`],
    ["DETERMINISTIC_OUTCOME", `${d.outcome} · re-running the policy gives ${same ? "the same answer" : "a DIFFERENT answer"}`],
  ];
  const head = document.createElement("p");
  head.className = "why-head";
  head.textContent = `Why: ${req.body.data.label} (${money(req.body.data.amount_cents)})`;
  box.append(head);
  const plain = document.createElement("p");
  plain.className = "why-plain";
  plain.textContent = summarize(dec);
  box.append(plain);
  for (const [k, v] of rows) {
    const badge = document.createElement("div");
    badge.className = `badge ${k === "DETERMINISTIC_OUTCOME" ? d.outcome.toLowerCase() : ""}`;
    badge.dataset.k = k;
    const key = document.createElement("span");
    key.className = "k";
    key.textContent = k;
    const val = document.createElement("span");
    val.className = "v";
    val.textContent = v;
    badge.append(key, val);
    box.append(badge);
  }
}

function renderLedger() {
  const list = $("ledger");
  list.textContent = "";
  working.forEach((ev, i) => {
    const li = document.createElement("li");
    li.className = "ev";
    li.dataset.i = String(i);
    const head = document.createElement("div");
    head.className = "ev-head";
    const type = (ev.body && ev.body.type) || "UNREADABLE";
    const n = document.createElement("span");
    n.className = "ev-n";
    n.textContent = `#${i}`;
    const name = document.createElement("b");
    name.textContent = kindLabel(type);
    const status = document.createElement("span");
    status.className = "ev-status";
    head.append(n, name, status);
    const sum = document.createElement("p");
    sum.className = "ev-sum";
    sum.textContent = summarize(ev);
    const hashes = document.createElement("code");
    hashes.className = "ev-hash";
    hexify(hashes, `links back to ${ev.prev.slice(0, 10)}… · own fingerprint ${ev.hash.slice(0, 10)}…`, "ev" + i);
    hashes.title = `prev ${ev.prev}\nhash ${ev.hash}`;
    const note = document.createElement("p");
    note.className = "ev-note";
    li.append(head, sum, hashes, note);
    if (tamper) {
      const area = document.createElement("textarea");
      area.className = "ev-json";
      area.spellcheck = false;
      area.setAttribute("aria-label", `JSON of event ${i}`);
      area.value = i in rawTexts ? rawTexts[i] : JSON.stringify(ev.body, null, 2);
      area.rows = Math.min(14, area.value.split("\n").length + 1);
      area.addEventListener("input", () => {
        try {
          working[i] = { prev: working[i].prev, hash: working[i].hash, body: JSON.parse(area.value) };
          delete rawTexts[i];
        } catch {
          working[i] = { prev: working[i].prev, hash: working[i].hash, body: null };
          rawTexts[i] = area.value;
        }
        renderControls();
        refreshVerify();
      });
      li.append(area);
    }
    list.append(li);
  });
  renderStatus();
}

function renderStatus() {
  const rows = lastVerify ? lastVerify.rows : [];
  const items = $("ledger").children;
  let signed = 0;
  for (let i = 0; i < items.length; i++) {
    const row = rows[i];
    if (!row) continue;
    const ok = row.hashOk && row.sigOk !== false;
    if (row.sigOk) signed += 1;
    items[i].classList.toggle("ok", ok);
    items[i].classList.toggle("bad", !ok);
    items[i].querySelector(".ev-status").textContent = ok
      ? (row.sigOk ? "✓ Intact · signature valid" : "✓ Intact")
      : "✗ Broken";
    hexify(items[i].querySelector(".ev-note"), ok ? "" : row.note, "note" + i);
  }
  const status = $("chainStatus");
  if (!lastVerify || !working.length) {
    status.className = "chain-status";
    status.textContent = "Waiting for the first event…";
  } else if (lastVerify.ok) {
    status.className = "chain-status ok";
    status.textContent = `✓ Record intact: ${working.length} event${working.length > 1 ? "s" : ""}, all linked` +
      (signed ? ` · ${signed} signed decision${signed === 1 ? "" : "s"} valid` : "");
  } else {
    status.className = "chain-status bad";
    status.textContent = `✗ Record broken at event #${lastVerify.firstBad}: ${lastVerify.badCount} of ${working.length} events no longer check out`;
  }
  renderControls();
}

function renderControls() {
  const free = !busy && !tamper && !dirty();
  for (const b of document.querySelectorAll(".flight")) b.disabled = !(free && state === "idle");
  $("signBtn").disabled = !(free && state === "held");
  $("rejectBtn").disabled = !(free && state === "held");
  $("tamperBtn").disabled = busy || !ledger.length;
  $("tamperBtn").setAttribute("aria-pressed", String(tamper));
  $("tamperBtn").textContent = "Simulate Tamper";
  $("tamperHint").hidden = !tamper;
  $("restoreBtn").disabled = !dirty();
  $("resetBtn").disabled = busy;
  // A step that is still held can be exported too: the record is valid and shows the hold, unresolved. (The
  // Range's levels "stop at the gate" and "once each" end exactly there.)
  $("exportBtn").disabled = !(lastVerify && lastVerify.ok && !dirty() && !busy && state !== "starting" && ledger.length > 0);
}

async function refreshVerify() {
  const seq = ++verifySeq;
  if (!working.length) { lastVerify = null; renderStatus(); return; }
  const input = working.map((e) => ({ body: e.body, prev: e.prev, hash: e.hash }));
  const result = await verifyChain(input, sessionJwk);
  if (seq !== verifySeq) return; // a newer edit is already being checked
  lastVerify = result;
  renderStatus();
}

// ------------------------------------------------------------------ the receipt that checks itself

// Runs INSIDE the exported file (its source is embedded with the verifier functions): it reads the
// receipt next to it and re-checks the whole chain and every signature, offline, with no server.
function receiptPageMain() {
  const original = JSON.parse(document.getElementById("receipt").textContent);
  const area = document.getElementById("edit");
  const list = document.getElementById("rows");
  const banner = document.getElementById("banner");
  async function run(receipt) {
    let result;
    try {
      result = await verifyChain(receipt.events, receipt.public_key_jwk);
    } catch (e) {
      banner.textContent = "✗ This receipt could not be read: " + e.message;
      banner.className = "bad";
      return;
    }
    list.textContent = "";
    let signed = 0;
    receipt.events.forEach(function (ev, i) {
      const r = result.rows[i];
      const ok = r.hashOk && r.sigOk !== false;
      if (r.sigOk) signed += 1;
      const li = document.createElement("li");
      li.className = ok ? "ok" : "bad";
      li.textContent = "#" + i + " " + kindLabel(ev && ev.body && ev.body.type) + ": " + summarize(ev) + " " +
        (ok ? "✓ Intact" + (r.sigOk ? " · signature valid" : "") : "✗ Broken. " + (r.note || ""));
      list.append(li);
    });
    banner.textContent = result.ok
      ? "✓ Record intact: " + receipt.events.length + " events, all linked" + (signed ? " · " + signed + " signed decision" + (signed === 1 ? "" : "s") + " valid" : "")
      : "✗ Record broken at event #" + result.firstBad + ": " + result.badCount + " of " + receipt.events.length + " events no longer check out";
    banner.className = result.ok ? "ok" : "bad";
  }
  document.getElementById("verify").addEventListener("click", function () {
    let parsed;
    try { parsed = JSON.parse(area.value); } catch (e) {
      banner.textContent = "✗ That text is not a readable record.";
      banner.className = "bad";
      return;
    }
    run(parsed);
  });
  document.getElementById("reset").addEventListener("click", function () {
    area.value = JSON.stringify(original, null, 2);
    run(original);
  });
  area.value = JSON.stringify(original, null, 2);
  run(original);
}

const RECEIPT_CSS = "body{margin:0;background:#080B12;color:#F1F5F9;font:15px/1.55 system-ui,Segoe UI,sans-serif}" +
  "main{max-width:860px;margin:0 auto;padding:28px 18px 60px}h1{font-size:26px;margin:8px 0}" +
  ".chip{display:inline-block;font:700 11px ui-monospace,Consolas,monospace;letter-spacing:.12em;color:#fbbf24;border:1px solid #f59e0b;border-radius:999px;padding:5px 12px}" +
  "#banner{font:700 16px ui-monospace,Consolas,monospace;padding:12px 14px;border-radius:10px;border:2px solid rgba(255, 255, 255, .09)}" +
  "#banner.ok{color:#10b981;border-color:#10b981;background:rgba(16,185,129,.08)}#banner.bad{color:#ef4444;border-color:#ef4444;background:rgba(239,68,68,.08)}" +
  "ol{list-style:none;padding:0}li{font:13px ui-monospace,Consolas,monospace;padding:8px 12px;margin:6px 0;border-left:4px solid rgba(255, 255, 255, .09);background:#101624;border-radius:6px;overflow-wrap:anywhere}" +
  "li.ok{border-left-color:#10b981}li.bad{border-left-color:#ef4444;color:#fecaca}" +
  "textarea{width:100%;box-sizing:border-box;min-height:260px;background:#060910;color:#CBD5E1;border:1px solid rgba(255, 255, 255, .09);border-radius:10px;padding:10px;font:12px/1.5 ui-monospace,Consolas,monospace}" +
  "button{background:#f59e0b;color:#1a1204;border:0;border-radius:8px;padding:10px 16px;font:700 14px system-ui;cursor:pointer;margin-right:8px}button#reset{background:#172033;color:#F1F5F9}" +
  ".small{font-size:13px;color:#94A3B8}summary{cursor:pointer;color:#fbbf24;margin:8px 0}";

function buildReceiptHtml(receipt) {
  const functions = [C.canon, C.sha256hex, C.eventHash, C.fromB64, C.approvalBytes, C.verifyChain, money, kindLabel, summarize, receiptPageMain]
    .map((f) => f.toString()).join("\n\n");
  // `<` is escaped so no value inside the receipt can close the script tag around it.
  const data = JSON.stringify(receipt, null, 2).replace(/</g, "\\u003c");
  return [
    "<!doctype html>",
    '<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">',
    "<title>HashCam sandbox receipt</title>",
    `<style>${RECEIPT_CSS}</style></head><body><main>`,
    '<p class="chip">SIMULATION · not an .abbreceipt · checks itself in this page</p>',
    "<h1>HashCam Gatekeeper Sandbox receipt</h1>",
    `<p class="small">Made ${receipt.created_utc} · policy ${receipt.policy.id} · session key ${receipt.key_id}. Nothing on this page contacts any server.</p>`,
    '<p id="banner" role="status">Checking…</p>',
    '<ol id="rows" aria-label="Events"></ol>',
    "<h2>Try to break it</h2>",
    "<details><summary>Show the raw record (technical) and edit it</summary>",
    '<p class="small">This is the whole receipt in its raw form, with made-up data only. Change any value below (an amount, a decision, a signature), then press Verify again.</p>',
    '<textarea id="edit" spellcheck="false" aria-label="The receipt in its raw form"></textarea>',
    '<p><button id="verify" type="button">Verify again</button><button id="reset" type="button">Restore original</button></p>',
    "</details>",
    '<p class="small">What this proves: the chain of hashes and the signatures check out against the public key inside this file, so the record has not changed since it was signed. It does not prove who held the key (here it travels with the receipt; real HashCam keeps its key manifest in a separate channel), or that the agent was honest. This is a simplified simulation format: <code>abb verify</code> cannot read it.</p>',
    "</main>",
    `<script type="application/json" id="receipt">${data}</script>`,
    `<script>\nconst ZERO = ${JSON.stringify(C.ZERO)};\n${functions}\nreceiptPageMain();\n<\/script>`,
    "</body></html>",
  ].join("\n");
}

function exportReceipt() {
  if ($("exportBtn").disabled) return;
  const receipt = {
    format: "hashcam-sandbox-receipt/1",
    simulation: true,
    created_utc: new Date().toISOString(),
    policy: POLICY,
    key_id: keyId,
    public_key_jwk: sessionJwk,
    events: ledger.map((e) => ({ body: e.body, prev: e.prev, hash: e.hash })),
  };
  const blob = new Blob([buildReceiptHtml(receipt)], { type: "text/html" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = `hashcam-sandbox-receipt-${ledger[ledger.length - 1].hash.slice(0, 8)}.html`;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(link.href), 5000);
}

// ------------------------------------------------------------------ wiring

for (const button of document.querySelectorAll(".flight")) {
  button.addEventListener("click", () => fly(button.dataset.action));
}
$("signBtn").addEventListener("click", () => resolveHold("GRANTED"));
$("rejectBtn").addEventListener("click", () => resolveHold("REJECTED"));
$("tamperBtn").addEventListener("click", () => {
  tamper = !tamper;
  renderLedger();
  renderControls();
});
$("restoreBtn").addEventListener("click", () => {
  working = clone(ledger);
  rawTexts = {};
  renderLedger();
  renderControls();
  refreshVerify();
});
$("exportBtn").addEventListener("click", exportReceipt);
$("resetBtn").addEventListener("click", () => { if (!busy) startSession(); });

// Bring the panels in as they scroll into view. Without this every panel (data-reveal) stays at opacity 0
// and the page looks empty: the buttons still work, so the tests that only clicked them did not notice.
if (window.HCMotion) window.HCMotion.init();

// Say which policy is running. A custom one is never mistaken for the standard one.
(function showPolicy() {
  const banner = $("policyBanner");
  const P = window.HCPolicy;
  if (asked.state === "ok") {
    banner.textContent = `Custom policy in use (${POLICY.id}): budget ${P.money(POLICY.budget_cents)}, a person must approve above ${P.money(POLICY.auto_limit_cents)}, ` +
      (POLICY.refuse_over_cents != null ? `refused above ${P.money(POLICY.refuse_over_cents)}, ` : "") +
      `${POLICY.allow_domains.length} allowed host${POLICY.allow_domains.length === 1 ? "" : "s"}. This is a sandbox policy, not the real gateway's. `;
    banner.append(Object.assign(document.createElement("a"), { href: "sandbox.html", textContent: "Back to the standard policy" }));
    banner.hidden = false;
    $("rulesId").textContent = POLICY.id;
    const body = $("rulesBody");
    body.textContent = "";
    for (const row of P.rules(POLICY)) {
      const tr = document.createElement("tr");
      const first = document.createElement("td");
      first.append(Object.assign(document.createElement("code"), { textContent: row[0] }));
      for (const text of [row[1], row[2]]) tr.append(Object.assign(document.createElement("td"), { textContent: text }));
      tr.prepend(first);
      body.append(tr);
    }
  } else if (asked.state === "bad") {
    banner.textContent = `The policy in this link could not be used (${asked.reason}), so the standard policy is running. `;
    banner.append(Object.assign(document.createElement("a"), { href: "policy.html", textContent: "Make a policy" }));
    banner.hidden = false;
  }
  window.addEventListener("hashchange", () => location.reload());
})();

if (!window.crypto || !crypto.subtle) {
  $("cryptoBanner").hidden = false;
  $("gateState").textContent = "Web Crypto is not available here.";
} else {
  startSession().catch((error) => {
    $("gateState").textContent = `Could not start: ${error.message}`;
  });
}
})();
