// The hash chain behind the Gatekeeper Sandbox and the "telemetry bus" samples.
//
// A classic script (it also loads from a file:// page) with no dependencies: SHA-256 and ECDSA P-256
// come from the browser's own Web Crypto. It sets window.HCChain.
//
// THIS IS A SIMULATION FORMAT, not abb/1. Real HashCam receipts hash canonical JSON (RFC 8785) with
// domain tags into a Merkle tree and are checked by the Rust verifier (`abb verify`). This chain is
// simpler on purpose, so a page can show every step: each event's hash covers the hash of the event
// before it, so changing one event changes it and every event after it.
//
// The verifier functions below are plain function declarations with no outside dependencies except
// each other and ZERO: the sandbox embeds their source (Function.prototype.toString) into the
// receipt it exports, so the exported file re-checks itself with exactly this code.
(function () {
"use strict";

const ZERO = "0".repeat(64);

function canon(value) {
  if (Array.isArray(value)) return "[" + value.map(canon).join(",") + "]";
  if (value && typeof value === "object") {
    return "{" + Object.keys(value).sort().map(function (k) {
      return JSON.stringify(k) + ":" + canon(value[k]);
    }).join(",") + "}";
  }
  return JSON.stringify(value);
}

async function sha256hex(text) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return Array.from(new Uint8Array(digest), function (b) { return b.toString(16).padStart(2, "0"); }).join("");
}

// The hash of one event: SHA-256 of the previous event's hash, a newline, and the event's canonical JSON.
async function eventHash(prev, body) {
  return sha256hex(prev + "\n" + canon(body));
}

function fromB64(text) {
  const bin = atob(text);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function toB64(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

// What a human signs: the decision and the hash of the request they were shown.
function approvalBytes(decision, requestHash) {
  return new TextEncoder().encode("hashcam-sandbox-approval:" + decision + ":" + requestHash);
}

// Re-check a list of {body, prev, hash} from the first event on, using only what is in front of us.
// Each recomputed hash feeds the next one, so one edit fractures every link after it.
// A HUMAN_DECISION event must also carry a valid signature over the request it names.
async function verifyChain(events, publicJwk) {
  const rows = [];
  let key = null;
  try {
    key = await crypto.subtle.importKey("jwk", publicJwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  } catch (e) {
    key = null;
  }
  let prev = ZERO;
  for (let i = 0; i < events.length; i++) {
    const ev = events[i];
    const row = { hashOk: false, sigOk: null, note: "", hash: "" };
    if (ev && ev.body && typeof ev.body === "object" && !Array.isArray(ev.body)) {
      row.hash = await eventHash(prev, ev.body);
      row.hashOk = row.hash === ev.hash;
      if (!row.hashOk) row.note = "Changed: this event no longer matches its fingerprint (it now works out to " + row.hash.slice(0, 12) + "…, but the record says " + String(ev.hash).slice(0, 12) + "…).";
    } else {
      row.note = "This event can no longer be read.";
    }
    rows.push(row);
    prev = row.hash || "unreadable";
  }
  for (let i = 0; i < events.length; i++) {
    const body = events[i] && events[i].body;
    if (!body || body.type !== "HUMAN_DECISION" || !body.data) continue;
    const d = body.data;
    const target = events.findIndex(function (e) { return e && e.hash === d.request_hash; });
    if (target < 0 || !rows[target].hashOk) {
      rows[i].sigOk = false;
      rows[i].note = "The signature points to a request that is missing or was changed.";
      continue;
    }
    try {
      rows[i].sigOk = !!key && await crypto.subtle.verify(
        { name: "ECDSA", hash: "SHA-256" }, key, fromB64(String(d.signature)), approvalBytes(String(d.decision), String(d.request_hash)));
    } catch (e) {
      rows[i].sigOk = false;
    }
    if (!rows[i].sigOk && !rows[i].note) rows[i].note = "The signature does not match this session's key.";
  }
  const bad = rows.map(function (r, i) { return r.hashOk && r.sigOk !== false ? -1 : i; }).filter(function (i) { return i >= 0; });
  return { rows: rows, ok: bad.length === 0, firstBad: bad.length ? bad[0] : -1, badCount: bad.length };
}

window.HCChain = { ZERO, canon, sha256hex, eventHash, fromB64, toB64, approvalBytes, verifyChain };
})();
