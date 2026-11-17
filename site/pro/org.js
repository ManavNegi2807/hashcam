// Enterprise companies and their people, checked in the browser. Three small signed notes, all Ed25519 (WebCrypto):
//   HCORG1  the company certificate: org_id, org_name and the COMPANY public key, signed by the site OWNER key
//   HCMEM1  one person's access key: org_id, member_id, role (boss | member), scopes, expires_at, signed by the COMPANY key
//   HCREV1  the company's revocation list (member ids), signed by the COMPANY key
// A person pastes their certificate and their access key. Both are untrusted input: every field is checked.
//
// What this is worth (NOT ENFORCED): there is no server. A person's data lives in this browser under the company's own
// storage prefix, and the pages only ever open the prefix of the company that signed in, so one company's key cannot
// open another's workspace. Anyone with this browser's developer tools can still read this browser's storage, and a
// revocation only takes effect where the signed list has been imported. It keeps honest people honest.
(() => {
"use strict";

const SESSION = "hashcam-org-session";
const MAX = 4000;
const B64U = /^[A-Za-z0-9_-]+$/;
const DAY = 24 * 60 * 60 * 1000;
const ORG_ID = /^[a-z0-9][a-z0-9-]{0,39}$/;
const MEMBER_ID = /^[A-Za-z0-9-]{1,40}$/;
const NAME = (s) => typeof s === "string" && s.trim() !== "" && s.length <= 80 && !/[\u0000-\u001f\u007f]/.test(s);
const isDate = (s) => typeof s === "string" && /^\d{4}-\d{2}-\d{2}$/.test(s) && !Number.isNaN(Date.parse(s + "T00:00:00Z"));
const BOSS_SCOPES = ["triage", "verify", "reproduce", "notes", "members", "policy", "approve", "insights"];
const MEMBER_SCOPES = ["triage", "verify", "reproduce", "notes"];
const dec = new TextDecoder("utf-8", { fatal: true });

const no = (reason, extra = {}) => ({ ok: false, reason, ...extra });
const bytesOfB64u = (text) => {
  if (!B64U.test(text)) throw new Error("bad characters");
  const bin = atob(text.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (text.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
};
const bytesOfHex = (hex) => Uint8Array.from(hex.match(/../g), (h) => parseInt(h, 16));

// One signed token: { ok, payload } or { ok: false, reason }.
async function open(token, prefix, publicKeyHex) {
  const parts = String(token || "").trim().split(".");
  if (parts.length !== 3 || parts[0] !== prefix) return no("That is not a " + prefix + " token.");
  let raw, sig;
  try { raw = bytesOfB64u(parts[1]); sig = bytesOfB64u(parts[2]); } catch { return no("That token is damaged: it could not be read."); }
  if (sig.length !== 64) return no("That token is damaged: its signature has the wrong size.");
  let key;
  try { key = await crypto.subtle.importKey("raw", bytesOfHex(publicKeyHex), { name: "Ed25519" }, false, ["verify"]); }
  catch { return no("This browser cannot check keys (it has no Ed25519 support).", { unsupported: true }); }
  let good = false;
  try { good = await crypto.subtle.verify({ name: "Ed25519" }, key, sig, raw); } catch { good = false; }
  if (!good) return no("That token was not signed by the expected key, or it was changed.");
  try {
    const payload = JSON.parse(dec.decode(raw));
    if (!payload || typeof payload !== "object" || payload.v !== 1) return no("That token is from a version this site does not know.");
    return { ok: true, payload };
  } catch { return no("That token is damaged: its contents could not be read."); }
}

// Pull the tokens out of whatever was pasted: whitespace, commas and "~" may separate them.
function split(text) {
  const out = { cert: "", member: "", revoke: "" };
  for (const piece of String(text || "").split(/[\s,~]+/)) {
    if (piece.startsWith("HCORG1.")) out.cert = piece;
    else if (piece.startsWith("HCMEM1.")) out.member = piece;
    else if (piece.startsWith("HCREV1.")) out.revoke = piece;
  }
  return out;
}

// Which company a pasted certificate CLAIMS to be (unchecked: only to pick which stored revocation list to read).
function claimedOrg(text) {
  try {
    const part = split(text).cert.split(".")[1];
    const org = JSON.parse(dec.decode(bytesOfB64u(part))).org_id;
    return typeof org === "string" && ORG_ID.test(org) ? org : null;
  } catch { return null; }
}

async function checkRevocations(token, cert) {
  const r = await open(token, "HCREV1", cert.org_pubkey);
  if (!r.ok) return no("The revocation list is not signed by this company: " + r.reason);
  const p = r.payload;
  if (p.org_id !== cert.org_id || !Array.isArray(p.revoked) || p.revoked.length > 5000 || !p.revoked.every((m) => typeof m === "string" && MEMBER_ID.test(m)) || !isDate(p.issued)) {
    return no("That revocation list is not for this company or is not valid.");
  }
  return { ok: true, revoked: p.revoked };
}

// Check a person's two tokens (and, optionally, the company's signed revocation list). `now` in milliseconds.
async function verifySession(text, revocationToken, now = Date.now()) {
  const ownerKey = window.HCProKey && window.HCProKey.publicKeyHex;
  if (typeof text !== "string" || text.length > MAX * 3) return no("That does not look like an access key.");
  if (typeof ownerKey !== "string" || !/^[0-9a-f]{64}$/.test(ownerKey)) return no("This site has no owner key set up yet, so company keys cannot be checked.", { notConfigured: true });
  const t = split(text);
  if (!t.cert || !t.member || t.cert.length > MAX || t.member.length > MAX) return no("Paste both the company certificate (HCORG1…) and your access key (HCMEM1…).");
  const c = await open(t.cert, "HCORG1", ownerKey);
  if (!c.ok) return no("The company certificate was not made for this site: " + c.reason, { unsupported: c.unsupported });
  const cert = c.payload;
  if (!ORG_ID.test(cert.org_id || "") || !NAME(cert.org_name) || !/^[0-9a-f]{64}$/.test(cert.org_pubkey || "") || !isDate(cert.issued) || !(cert.expires === null || isDate(cert.expires))) {
    return no("The company certificate has a field that is not valid.");
  }
  if (cert.expires !== null && Date.parse(cert.expires + "T23:59:59Z") < now) return no("This company's certificate ended on " + cert.expires + ".", { expired: true });
  const m = await open(t.member, "HCMEM1", cert.org_pubkey);
  if (!m.ok) return no("That access key was not made by this company, or it was changed.");
  const p = m.payload;
  if (p.org_id !== cert.org_id) return no("That access key belongs to another company.");
  if (!MEMBER_ID.test(p.member_id || "") || !NAME(p.name) || (p.role !== "boss" && p.role !== "member")) return no("That access key has a field that is not valid.");
  const allowed = p.role === "boss" ? BOSS_SCOPES : MEMBER_SCOPES;
  if (!Array.isArray(p.scopes) || !p.scopes.length || p.scopes.some((s) => !allowed.includes(s)) || new Set(p.scopes).size !== p.scopes.length) {
    return no("That access key asks for more than a " + p.role + " may have, so it is refused.");
  }
  if (!isDate(p.issued) || !(p.expires_at === null || isDate(p.expires_at))) return no("That access key has a date that is not valid.");
  if (Date.parse(p.issued + "T00:00:00Z") > now + DAY) return no("That access key says it was issued in the future. Check this computer's date.");
  if (p.expires_at !== null && Date.parse(p.expires_at + "T23:59:59Z") < now) return no("That access key ended on " + p.expires_at + ".", { expired: true });
  const list = revocationToken || t.revoke;
  if (list) {
    const rv = await checkRevocations(list, cert);
    if (!rv.ok) return rv;
    if (rv.revoked.includes(p.member_id)) return no("That access key was revoked by the company.", { revoked: true });
  }
  return { ok: true, org: { org_id: cert.org_id, org_name: cert.org_name }, member: { member_id: p.member_id, name: p.name, role: p.role, scopes: p.scopes.slice(), expires_at: p.expires_at } };
}

// ---------------------------------------------------------------- this browser's storage, one company at a time
function lsGet(k) { try { return localStorage.getItem(k); } catch { return null; } }
function lsSet(k, v) { try { if (v == null) localStorage.removeItem(k); else localStorage.setItem(k, v); return true; } catch { return false; } }

// A store bound to ONE company: the prefix is fixed here, so nothing built on it can name another company's data.
function storeFor(orgId) {
  if (!ORG_ID.test(orgId)) throw new Error("bad org id");
  const prefix = "hashcam-org:" + orgId + ":";
  const bad = (k) => !/^[a-z-]{1,30}$/.test(k);
  return {
    orgId,
    get(k, fallback) { if (bad(k)) return fallback; try { const v = JSON.parse(lsGet(prefix + k)); return v == null ? fallback : v; } catch { return fallback; } },
    set(k, v) { return !bad(k) && lsSet(prefix + k, JSON.stringify(v)); },
  };
}

function has(session, scope) { return Boolean(session && session.ok && session.member.scopes.includes(scope)); }

// Sign in from pasted tokens. Keeps the tokens (never a private key: there is none here) so a reload stays signed in.
async function signIn(text) {
  const org = claimedOrg(text);
  const rev = org ? storeFor(org).get("revocations", "") : "";
  const session = await verifySession(text, rev || undefined);
  if (session.ok) lsSet(SESSION, text.trim());
  return session;
}
async function current() {
  const text = lsGet(SESSION);
  if (!text) return { ok: false, reason: "", none: true };
  const org = claimedOrg(text);
  const rev = org ? storeFor(org).get("revocations", "") : "";
  const session = await verifySession(text, rev || undefined);
  if (!session.ok) lsSet(SESSION, null);
  return session;
}
function signOut() { lsSet(SESSION, null); }

// Import a company's signed revocation list: only kept if it checks out against the signed-in company's certificate.
async function importRevocations(session, text) {
  const t = split(text);
  const stored = lsGet(SESSION) || "";
  const cert = split(stored).cert;
  const ownerKey = window.HCProKey && window.HCProKey.publicKeyHex;
  const c = await open(cert, "HCORG1", ownerKey);
  if (!c.ok || !t.revoke) return no("Paste the company's signed revocation list (HCREV1…).");
  const rv = await checkRevocations(t.revoke, c.payload);
  if (!rv.ok) return rv;
  storeFor(session.org.org_id).set("revocations", t.revoke);
  return { ok: true, revoked: rv.revoked };
}

window.HCOrg = { verifySession, storeFor, signIn, current, signOut, importRevocations, has, claimedOrg, BOSS_SCOPES, MEMBER_SCOPES };
})();
