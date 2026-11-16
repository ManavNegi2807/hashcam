// HashCam Pro licence check. A licence key is a small signed note ("HCPRO1.<payload>.<signature>"); this file
// checks the signature in the browser with the PUBLIC key in pubkey.js (Ed25519, WebCrypto). No server.
//
// What this check is worth: it stops a typo, a copied-and-edited key and a key made by anyone but the owner.
// It runs in the visitor's own browser, so a determined person can bypass any browser-side check; it is
// there to keep honest people honest, not to be copy protection. The key is kept in localStorage on this
// device only and is never sent anywhere. A pasted key is untrusted input: everything is checked.
(() => {
"use strict";

const STORE = "hashcam-pro-licence";
const MAX_KEY = 2000;
const B64U = /^[A-Za-z0-9_-]+$/;
const DAY = 24 * 60 * 60 * 1000;
const enc = new TextDecoder("utf-8", { fatal: true });

function bytesOfB64u(text) {
  if (!B64U.test(text)) throw new Error("bad characters");
  const bin = atob(text.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (text.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}
const bytesOfHex = (hex) => Uint8Array.from(hex.match(/../g), (h) => parseInt(h, 16));
const isDate = (s) => typeof s === "string" && /^\d{4}-\d{2}-\d{2}$/.test(s) && !Number.isNaN(Date.parse(s + "T00:00:00Z"));

const no = (reason) => ({ ok: false, reason });
// The checked licence as the pages see it: org and seats only when the key carries them.
const licenceOf = (p) => ({ name: p.name, plan: p.plan, issued: p.issued, expires: p.expires, id: p.id,
  ...(p.org !== undefined ? { org: p.org } : {}), ...(p.seats !== undefined ? { seats: p.seats } : {}) });

// Check one key against one public key (64 hex characters). `now` is a number of milliseconds (default: now).
async function verifyLicense(token, publicKeyHex, now = Date.now()) {
  if (typeof token !== "string" || typeof publicKeyHex !== "string" || !/^[0-9a-f]{64}$/.test(publicKeyHex)) {
    return no("This site has no licence key set up to check against.");
  }
  const text = token.trim();
  if (!text || text.length > MAX_KEY) return no("That does not look like a HashCam Pro key.");
  const parts = text.split(".");
  if (parts.length !== 3 || parts[0] !== "HCPRO1") return no("That does not look like a HashCam Pro key.");
  let raw, sig;
  try { raw = bytesOfB64u(parts[1]); sig = bytesOfB64u(parts[2]); } catch { return no("That key is damaged: it could not be read."); }
  if (sig.length !== 64) return no("That key is damaged: its signature has the wrong size.");
  let key;
  try {
    key = await crypto.subtle.importKey("raw", bytesOfHex(publicKeyHex), { name: "Ed25519" }, false, ["verify"]);
  } catch {
    return { ok: false, unsupported: true, reason: "This browser cannot check licence keys (it has no Ed25519 support). Pro stays off here; try a current Chrome, Edge, Firefox or Safari." };
  }
  let good = false;
  try { good = await crypto.subtle.verify({ name: "Ed25519" }, key, sig, raw); } catch { good = false; }
  if (!good) return no("That key was not made for this site, or it was changed. Check that you copied all of it.");
  let p;
  try { p = JSON.parse(enc.decode(raw)); } catch { return no("That key is damaged: its contents could not be read."); }
  if (!p || typeof p !== "object" || p.v !== 1) return no("That key is from a version this site does not know.");
  if (p.plan !== "pro" && p.plan !== "enterprise") return no("That key is not a Pro key.");
  if (p.org !== undefined && (typeof p.org !== "string" || !p.org.trim() || p.org.length > 80 || /[\u0000-\u001f\u007f]/.test(p.org))) return no("That key has an organisation name that is not valid.");
  if (p.seats !== undefined && (!Number.isInteger(p.seats) || p.seats < 1 || p.seats > 10000)) return no("That key has a number of seats that is not valid.");
  if (typeof p.name !== "string" || !p.name.trim() || p.name.length > 80 || /[\u0000-\u001f\u007f]/.test(p.name)) {
    return no("That key has a name that is not valid.");
  }
  if (!isDate(p.issued) || !(p.expires === null || isDate(p.expires))) return no("That key has a date that is not valid.");
  if (typeof p.id !== "string" || !/^[A-Za-z0-9-]{1,40}$/.test(p.id)) return no("That key has an id that is not valid.");
  if (Date.parse(p.issued + "T00:00:00Z") > now + DAY) return no("That key says it was issued in the future. Check this computer's date.");
  if (p.expires !== null && Date.parse(p.expires + "T23:59:59Z") < now) {
    return { ok: false, expired: true, reason: `That licence ended on ${p.expires}.`, licence: licenceOf(p) };
  }
  return { ok: true, licence: licenceOf(p) };
}

// ---------------------------------------------------------------- what this page has stored

function stored() {
  try { return localStorage.getItem(STORE) || ""; } catch { return ""; }
}
function keep(token) {
  try { if (token) localStorage.setItem(STORE, token); else localStorage.removeItem(STORE); } catch { /* private window: it just will not be remembered */ }
}

let current = null; // a promise for { plan, state, licence?, reason? }

// state: "none" | "not-configured" | "unsupported" | "valid" | "expired" | "invalid"
async function evaluate(token) {
  const publicKeyHex = window.HCProKey && window.HCProKey.publicKeyHex;
  const free = (state, extra) => ({ plan: "anonymous", state, ...extra });
  if (!publicKeyHex) return free("not-configured", { reason: "Licence checking is not set up on this site yet, so nothing can be unlocked." });
  if (!token) return free("none");
  const result = await verifyLicense(token, publicKeyHex);
  // "plan" stays "pro" for both paid plans (every Pro feature works for Enterprise); "tier" tells them apart.
  if (result.ok) return { plan: "pro", tier: result.licence.plan, state: "valid", licence: result.licence };
  if (result.unsupported) return free("unsupported", { reason: result.reason });
  if (result.expired) return free("expired", { reason: result.reason, licence: result.licence });
  return free("invalid", { reason: result.reason });
}

// The current state. Never rejects: any trouble reads as the free plan.
function ready() {
  if (!current) current = evaluate(stored()).catch(() => ({ plan: "anonymous", state: "none" }));
  return current;
}

// Check a pasted key and, only if it is good, keep it on this device.
async function save(token) {
  const state = await evaluate(String(token || "").trim());
  if (state.state === "valid") {
    keep(String(token).trim());
    current = Promise.resolve(state);
  }
  return state;
}

function remove() {
  keep("");
  current = Promise.resolve({ plan: "anonymous", state: "none" });
}

window.HCLicense = { verifyLicense, ready, save, remove, isPro: async () => (await ready()).plan === "pro" };
})();
