// Customer issue triage, in this tab. A maintainer drops what a customer sent: the agent's record (.abbreceipt with its
// .keys.json, or a Gatekeeper Sandbox receipt) and, optionally, a small "issue" note (.issue.json) with the same base
// name. Every record is VERIFIED FIRST. A bundle whose record does not check out, or that has no record at all, is
// marked NOT INCLUDED: it is listed with the reason but never counted in the ranking. Nothing is uploaded.
//
// The categories of a VERIFIED bundle come from the customer's note (it is a claim about the symptom, not proof) or,
// failing that, from words in the verified record. A bundle that is NOT INCLUDED is tallied separately so you can see
// how many broken records you are receiving, but it never changes what is ranked.
(() => {
"use strict";

const R = window.HCRecords;
const CATEGORIES = ["WASM_LOAD", "SIGNATURE_INVALID", "CHAIN_BROKEN", "POLICY_HOLD_TIMEOUT", "DOMAIN_ALERT"];
const UNCAT = "UNCATEGORISED";
const FORMAT = "hashcam-issue/1";
const MAX_FILES = 200;
const MAX_BYTES = 8 * 1048576;

const NEXT = {
  WASM_LOAD: "Make the in-browser verifier load more reliably: serve verifier.wasm with the right type and headers, and show a clear fallback message.",
  SIGNATURE_INVALID: "Explain missing or mismatched .keys.json files at the moment of export, and say which key a receipt needs.",
  CHAIN_BROKEN: "Warn before a record is edited or re-saved, and offer a one-click re-export from the original session.",
  POLICY_HOLD_TIMEOUT: "Give held steps a visible countdown and a reminder to the approver, and let a boss pre-approve known cases.",
  DOMAIN_ALERT: "Let a company keep its own list of expected sites, so fewer true-but-routine domain alerts need a person.",
  [UNCAT]: "Ask customers to say what went wrong when they send a record, so it can be counted.",
};

const clean = (s, n) => String(s == null ? "" : s).replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, n);
const baseOf = (name) => String(name).replace(/\.(issue\.json|keys\.json|abbreceipt|html?|json)$/i, "");
const isIssueName = (n) => /\.issue\.json$/i.test(n);

function deriveFrom(events) {
  const text = JSON.stringify(events || []).toLowerCase();
  if (/policy_hold|held/.test(text) && /timeout|timed out|expired/.test(text)) return "POLICY_HOLD_TIMEOUT";
  if (/domain/.test(text) && /alert|off.?passport|blocked/.test(text)) return "DOMAIN_ALERT";
  return UNCAT;
}

async function readIssue(file) {
  try {
    const data = JSON.parse(await file.text());
    if (!data || typeof data !== "object" || data.format !== FORMAT) return null;
    return { category: CATEGORIES.includes(data.category) ? data.category : null, note: clean(data.note, 200), id: clean(data.id, 40), app: clean(data.app_version, 40) };
  } catch { return null; }
}

// Files in, one result per bundle out. Never throws: a bad file becomes a NOT INCLUDED row with its reason.
async function analyze(files) {
  const list = Array.from(files || []).slice(0, MAX_FILES);
  const groups = new Map();
  const add = (file, slot) => { const key = baseOf(file.name); const g = groups.get(key) || { key }; g[slot] = file; groups.set(key, g); };
  const oversized = [];
  for (const f of list) {
    if (f.size > MAX_BYTES) { oversized.push(f); continue; }
    if (isIssueName(f.name)) add(f, "issue");
    else if (R.isKeys(f)) add(f, "keys");
    else if (R.isReceiptFile(f)) add(f, "receipt");
    else if (R.isSandboxFile(f)) add(f, "sandbox");
  }
  const items = [];
  for (const f of oversized) items.push({ name: clean(f.name, 80), status: "NOT INCLUDED", category: UNCAT, reason: "That file is over 8 MB, so it was not read.", note: "" });
  for (const g of groups.values()) {
    const meta = g.issue ? await readIssue(g.issue) : null;
    const item = { name: clean(g.key, 80), status: "NOT INCLUDED", category: (meta && meta.category) || UNCAT, reason: "", note: meta ? meta.note : "", claimed: Boolean(meta && meta.category) };
    if (g.issue && !meta) item.reason = "The issue note is not a HashCam issue note (format " + FORMAT + "). ";
    try {
      const record = g.receipt || g.sandbox;
      if (!record) { item.reason += "No record to check: a note alone is not counted."; items.push(item); continue; }
      const checked = g.receipt ? await R.checkReceipt(g.receipt, g.keys) : await R.checkSandbox(g.sandbox);
      if (checked.ok) {
        item.status = "VERIFIED";
        item.reason = "The record checks out (" + (checked.via || "hash chain and signatures") + ").";
        if (!item.claimed) item.category = deriveFrom(checked.events);
      } else {
        item.reason += R.explain(checked.failure, "included");
        if (!item.claimed) {
          const f = checked.failure;
          item.category = f.kind === "tampered" ? "CHAIN_BROKEN" : (f.verdict === "INVALID" || f.verdict === "INCOMPLETE") ? "SIGNATURE_INVALID" : UNCAT;
        }
      }
    } catch (error) {
      item.reason += "That record could not be read: " + clean(error && error.message, 120);
    }
    items.push(item);
  }
  return items;
}

// Count and rank. Only VERIFIED bundles are ranked; NOT INCLUDED ones are shown beside them, never added.
function summarize(items) {
  const cats = [...CATEGORIES, UNCAT];
  const rows = cats.map((category) => ({
    category,
    verified: items.filter((i) => i.status === "VERIFIED" && i.category === category).length,
    notIncluded: items.filter((i) => i.status !== "VERIFIED" && i.category === category).length,
  })).filter((r) => r.verified || r.notIncluded);
  const ranking = rows.filter((r) => r.verified).sort((a, b) => b.verified - a.verified || cats.indexOf(a.category) - cats.indexOf(b.category))
    .map((r, i) => ({ rank: i + 1, category: r.category, count: r.verified, next: NEXT[r.category] }));
  return { rows, ranking, verified: items.filter((i) => i.status === "VERIFIED").length, notIncluded: items.filter((i) => i.status !== "VERIFIED").length };
}

window.HCInsights = { analyze, summarize, CATEGORIES, FORMAT, NEXT };
})();
