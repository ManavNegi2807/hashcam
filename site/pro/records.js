// Checking a record before anything is done with it. Shared by the Range (scoring) and Pro (audit pack, CSV):
// a record is verified FIRST, and one that does not check out is never used; callers get the reason in words.
// Everything is read and checked in this tab; nothing is uploaded.
(() => {
"use strict";

const C = window.HCChain;
const V = window.HCVerify;

const isKeys = (f) => /\.keys\.json$/i.test(f.name);
const isSandboxFile = (f) => /\.(html?|json)$/i.test(f.name) && !isKeys(f);
const isReceiptFile = (f) => /\.abbreceipt$/i.test(f.name);

// The sandbox's exported record, cut out of its HTML file (or a bare .json) as TEXT. Parsing a stranger's whole
// HTML file would make the browser read its styles and markup; only the one JSON block is wanted.
function sandboxExportOf(text) {
  let json = text;
  if (/^\s*</.test(text)) {
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

// A sandbox record: its hash chain and signatures are re-computed. { ok, data } or { ok: false, failure }.
async function checkSandbox(file) {
  const data = sandboxExportOf(await file.text());
  const check = await C.verifyChain(data.events, data.public_key_jwk);
  if (!check.ok) return { ok: false, failure: { kind: "tampered", firstBad: check.firstBad } };
  return { ok: true, data, events: data.events };
}

// An extension receipt: the real verifier (WebAssembly, or the JavaScript fallback that never says VALID). Only
// VALID passes. { ok, events, via } or { ok: false, failure }.
async function checkReceipt(receiptFile, keysFile) {
  const bytes = new Uint8Array(await receiptFile.arrayBuffer());
  const keyBytes = keysFile ? new Uint8Array(await keysFile.arrayBuffer()) : new Uint8Array();
  const report = await V.verify(bytes, keyBytes);
  const verdict = String(report.overall || "UNREADABLE");
  const via = report.engine === "wasm" ? "the HashCam verifier (WebAssembly)" : "the JavaScript fallback";
  if (verdict !== "VALID") return { ok: false, failure: { kind: "receipt", verdict, via, hasKeys: Boolean(keysFile) } };
  return { ok: true, events: await window.HCFallback.readEvents(bytes), via };
}

// Why a record was refused, in plain words. mode: "scored" (the Range) or "included" (the audit pack).
function explain(failure, mode) {
  const used = mode === "included" ? "included" : "scored";
  if (failure.kind === "tampered") {
    return `This record does not check out: event #${failure.firstBad} no longer matches its fingerprint or its signature, so it is not ${used}.`;
  }
  const { verdict, via, hasKeys } = failure;
  const why = verdict === "INVALID" ? "The receipt does not check out: something in it was changed or does not add up."
    : verdict === "INCOMPLETE"
      ? `The verdict is INCOMPLETE (checked by ${via})${hasKeys ? "" : "; no .keys.json was dropped, so signatures could not be checked"}. ${mode === "included" ? "A session is only included when its whole receipt is VALID." : "A run is only scored when the whole receipt is VALID."}`
      : `The receipt could not be read (verdict ${verdict}).`;
  return `${why} It is not ${used}.`;
}

// The Range levels assume the standard policy: a record made under a custom policy (Policy Studio) is not scored.
function policyRefusal(events) {
  const first = events && events[0] && events[0].body && events[0].body.data;
  if (first && first.policy && first.policy !== "sandbox-policy/1") {
    return `This record was made under a custom policy (${String(first.policy).slice(0, 40)}). The Range levels assume the standard policy, so it is not scored.`;
  }
  return null;
}

async function sha256Hex(file) {
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", await file.arrayBuffer()));
  return Array.from(hash, (b) => b.toString(16).padStart(2, "0")).join("");
}

window.HCRecords = { sandboxExportOf, checkSandbox, checkReceipt, explain, policyRefusal, sha256Hex, isKeys, isSandboxFile, isReceiptFile };
})();
