// A second receipt checker, in plain JavaScript with the browser's own Web Crypto. It exists so the
// "Check a receipt" box still gives an honest answer when the WebAssembly verifier cannot load (the
// file is missing, the browser blocks WebAssembly, or the page is opened from disk without it).
//
// What it checks, ported from the Rust verifier (core/abb-receipt, abb-merkle, abb-checkpoint):
//   evidence_integrity   every event is exactly canonical, in order, and in the signed Merkle tree
//   checkpoint_signatures  each checkpoint's Ed25519 signature, against the key manifest
//   consistency          the checkpoint chain links up and only grows
//   global_log_inclusion the run's record is in the signed global log
// What it does NOT check, and says so: coverage, policy, mandate, approvals, artifacts, witnesses,
// anchors and the advisory channels. Those stay UNKNOWN, so its best answer is INCOMPLETE: it can
// prove a receipt INVALID, but it can never call one VALID. Use the WebAssembly verifier (the same
// Rust code as `abb verify`) or `abb verify` itself for the full verdict.
//
// A classic script (works from file://). Nothing here touches the network.
(function () {
"use strict";

const te = new TextEncoder();
const ZERO32 = "0".repeat(64);

const DIMENSIONS = [
  "anchor_match", "artifact_availability", "artifact_manifest_integrity", "behavior_anomaly_assessment",
  "checkpoint_signatures", "consistency", "evidence_integrity", "execution_outcome",
  "global_log_inclusion", "mandate_compliance", "ml_assessment", "observation_coverage",
  "policy_assessment", "prompt_security_assessment", "semantic_assessment", "witness_quorum",
];
const CHECKED = ["evidence_integrity", "checkpoint_signatures", "consistency", "global_log_inclusion"];

class Unreadable extends Error {}
class Unsupported extends Error {}
class ProofError extends Error {}

// ------------------------------------------------------------------ bytes

function cat() {
  let size = 0;
  for (const part of arguments) size += part.length;
  const out = new Uint8Array(size);
  let at = 0;
  for (const part of arguments) { out.set(part, at); at += part.length; }
  return out;
}
const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
function fromHex(text, what) {
  if (typeof text !== "string" || !/^(?:[0-9a-f]{2})*$/.test(text)) throw new Unreadable(what + " is not lowercase hex");
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(text.slice(2 * i, 2 * i + 2), 16);
  return out;
}
function fromB64(text, what) {
  if (typeof text !== "string" || text.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(text)) {
    throw new Unreadable(what + " is not base64");
  }
  const binary = atob(text);
  if (btoa(binary) !== text) throw new Unreadable(what + " is not canonical base64");
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
}
async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}
// SHA-256(tag || 0x00 || data), the protocol's domain-separated input (PROTOCOL.md 4).
const tagged = (tag, data) => cat(te.encode(tag), Uint8Array.of(0), data);
const utf8 = (bytes, what) => {
  try { return new TextDecoder("utf-8", { fatal: true }).decode(bytes); } catch (_) { throw new Unreadable(what + " is not UTF-8"); }
};

// ------------------------------------------------------------------ strict JSON and canonical form

// The limits of PROTOCOL.md 3.3 for canonical documents (events, checkpoint payloads); the receipt
// file itself is read with the relaxed tooling limits, as the Rust reader does.
const PROTOCOL_LIMITS = { bytes: 65536, depth: 16, string: 16384 };
const RELAXED_LIMITS = { bytes: 64 << 20, depth: 64, string: 1 << 20 };
const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;

// A JSON parser that refuses what canonical JSON refuses: duplicate keys, fractions and exponents,
// integers beyond +-(2^53-1), negative zero, control characters, lone surrogates, trailing data.
function parseStrict(text, limits = RELAXED_LIMITS) {
  let i = 0;
  const fail = (why) => { throw new Unreadable("not canonical JSON: " + why); };
  const skip = () => { while (i < text.length && " \t\n\r".includes(text[i])) i++; };
  function string() {
    i++;
    let out = "";
    for (;;) {
      if (i >= text.length) fail("unterminated string");
      const code = text.charCodeAt(i);
      if (code === 0x22) { i++; break; }
      if (code < 0x20) fail("control character in a string");
      if (code !== 0x5c) { out += text[i++]; continue; }
      const next = text[i + 1];
      const simple = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" }[next];
      if (simple !== undefined) { out += simple; i += 2; continue; }
      if (next === "u" && /^[0-9a-fA-F]{4}$/.test(text.slice(i + 2, i + 6))) {
        out += String.fromCharCode(parseInt(text.slice(i + 2, i + 6), 16));
        i += 6;
        continue;
      }
      fail("bad escape");
    }
    if (LONE_SURROGATE.test(out)) fail("lone surrogate");
    if (out.length * 3 > limits.string && te.encode(out).length > limits.string) fail("a string is too long");
    return out;
  }
  function number() {
    const match = /^-?(?:0|[1-9][0-9]*)/.exec(text.slice(i, i + 32));
    if (!match) fail("unexpected character");
    i += match[0].length;
    if (".eE".includes(text[i] || "")) fail("a fraction or exponent (floats are not allowed)");
    const n = Number(match[0]);
    if (Object.is(n, -0)) fail("negative zero");
    if (!Number.isSafeInteger(n)) fail("integer out of range");
    return n;
  }
  function value(depth) {
    skip();
    const c = text[i];
    if ((c === "{" || c === "[") && depth + 1 > limits.depth) fail("nested too deeply");
    if (c === "{") {
      i++;
      const out = Object.create(null);
      skip();
      if (text[i] === "}") { i++; return out; }
      for (;;) {
        skip();
        if (text[i] !== '"') fail("expected a key");
        const key = string();
        if (key in out) fail("duplicate key " + key);
        skip();
        if (text[i++] !== ":") fail("expected a colon");
        out[key] = value(depth + 1);
        skip();
        if (text[i] === ",") { i++; continue; }
        if (text[i] === "}") { i++; return out; }
        fail("expected , or }");
      }
    }
    if (c === "[") {
      i++;
      const out = [];
      skip();
      if (text[i] === "]") { i++; return out; }
      for (;;) {
        out.push(value(depth + 1));
        skip();
        if (text[i] === ",") { i++; continue; }
        if (text[i] === "]") { i++; return out; }
        fail("expected , or ]");
      }
    }
    if (c === '"') return string();
    if (text.startsWith("true", i)) { i += 4; return true; }
    if (text.startsWith("false", i)) { i += 5; return false; }
    if (text.startsWith("null", i)) { i += 4; return null; }
    return number();
  }
  const result = value(0);
  skip();
  if (i !== text.length) fail("data after the value");
  return result;
}

// RFC 8785 canonical text of a value parsed by parseStrict (keys sorted by UTF-16 code unit).
function canon(v) {
  if (v === null) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") return String(v);
  if (typeof v === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
  return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canon(v[k])).join(",") + "}";
}

// Parse bytes that must already BE canonical (events, checkpoint payloads): the text has to equal
// its own canonical form, byte for byte.
function parseCanonical(bytes, what) {
  if (bytes.length > PROTOCOL_LIMITS.bytes) throw new Unreadable(what + " is over the size limit");
  const text = utf8(bytes, what);
  const value = parseStrict(text, PROTOCOL_LIMITS);
  if (canon(value) !== text) throw new Unreadable(what + " is not in canonical form");
  return value;
}

// ------------------------------------------------------------------ the Merkle tree (RFC 6962 / 9162)

const leafHash = async (data) => sha256(cat(Uint8Array.of(0), data));
const nodeHash = async (left, right) => sha256(cat(Uint8Array.of(1), left, right));

function powerOfTwoBelow(n) {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}
async function mth(leaves) {
  if (leaves.length === 0) return sha256(new Uint8Array(0));
  if (leaves.length === 1) return leafHash(leaves[0]);
  const k = powerOfTwoBelow(leaves.length);
  return nodeHash(await mth(leaves.slice(0, k)), await mth(leaves.slice(k)));
}

// The root an audit path derives for a leaf; throws ProofError with the protocol's reason code.
async function verifyInclusion(leaf, index, treeSize, path) {
  let fin = BigInt(index);
  let sin = BigInt(treeSize) - 1n;
  if (BigInt(treeSize) === 0n || fin >= BigInt(treeSize)) throw new ProofError("LEAF_INDEX_OUT_OF_RANGE");
  let node = leaf;
  for (const sibling of path) {
    if (sin === 0n) throw new ProofError("PATH_TOO_LONG");
    if (fin % 2n === 1n || fin === sin) {
      node = await nodeHash(sibling, node);
      while (fin % 2n === 0n && fin !== 0n) { fin /= 2n; sin /= 2n; }
    } else {
      node = await nodeHash(node, sibling);
    }
    fin /= 2n;
    sin /= 2n;
  }
  if (sin !== 0n) throw new ProofError("PATH_TOO_SHORT");
  return node;
}

// The second root a consistency proof derives; also requires it to reproduce the first root.
async function verifyConsistency(firstSize, secondSize, firstRoot, path) {
  const first = BigInt(firstSize);
  const second = BigInt(secondSize);
  if (first === 0n) throw new ProofError("FIRST_SIZE_ZERO");
  if (first > second) throw new ProofError("SIZE_REGRESSION");
  if (first === second) {
    if (path.length === 0) return firstRoot;
    throw new ProofError("PATH_TOO_LONG");
  }
  if (path.length === 0) throw new ProofError("EMPTY_PROOF");
  const nodes = (first & (first - 1n)) === 0n ? [firstRoot, ...path] : [...path];
  let fin = first - 1n;
  let sin = second - 1n;
  while (fin % 2n === 1n) { fin /= 2n; sin /= 2n; }
  let firstDerived = nodes[0];
  let secondDerived = nodes[0];
  for (const sibling of nodes.slice(1)) {
    if (sin === 0n) throw new ProofError("PATH_TOO_LONG");
    if (fin % 2n === 1n || fin === sin) {
      firstDerived = await nodeHash(sibling, firstDerived);
      secondDerived = await nodeHash(sibling, secondDerived);
      while (fin % 2n === 0n && fin !== 0n) { fin /= 2n; sin /= 2n; }
    } else {
      secondDerived = await nodeHash(secondDerived, sibling);
    }
    fin /= 2n;
    sin /= 2n;
  }
  if (sin !== 0n) throw new ProofError("PATH_TOO_SHORT");
  if (hex(firstDerived) !== hex(firstRoot)) throw new ProofError("FIRST_ROOT_MISMATCH");
  return secondDerived;
}

// ------------------------------------------------------------------ the .abbreceipt container (a ZIP)

const MAX_RECEIPT_JSON = 32 * 1024 * 1024;
const MAX_TOTAL = 256 * 1024 * 1024;
const MAX_ENTRIES = 10000;
const MAX_RATIO = 200;

let crcTable = null;
function crc32(bytes) {
  if (!crcTable) {
    crcTable = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      crcTable[n] = c >>> 0;
    }
  }
  let crc = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) crc = crcTable[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

async function inflateRaw(bytes, limit) {
  if (typeof DecompressionStream !== "function") {
    throw new Unreadable("this browser cannot decompress ZIP entries (no DecompressionStream)");
  }
  const reader = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("deflate-raw")).getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.length;
    if (total > limit) { await reader.cancel(); throw new Unreadable("receipt.json is larger than its header says"); }
    chunks.push(value);
  }
  return cat(...chunks);
}

// Returns the bytes of receipt.json after the same limits the Rust reader applies.
async function readContainer(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let end = -1;
  for (let i = bytes.length - 22; i >= Math.max(0, bytes.length - 22 - 65535); i--) {
    if (view.getUint32(i, true) === 0x06054b50) { end = i; break; }
  }
  if (end < 0) throw new Unreadable("not a readable receipt container: this is not a ZIP file");
  const count = view.getUint16(end + 10, true);
  const dirSize = view.getUint32(end + 12, true);
  const dirAt = view.getUint32(end + 16, true);
  if (count === 0xffff || dirAt === 0xffffffff) throw new Unreadable("not a readable receipt container: ZIP64 is not supported here");
  if (count > MAX_ENTRIES) throw new Unreadable("over a container limit: " + count + " entries");
  if (dirAt + dirSize > bytes.length) throw new Unreadable("not a readable receipt container: bad directory");

  let at = dirAt;
  let declaredTotal = 0;
  let found = null;
  for (let n = 0; n < count; n++) {
    if (at + 46 > bytes.length || view.getUint32(at, true) !== 0x02014b50) {
      throw new Unreadable("not a readable receipt container: bad directory entry");
    }
    const method = view.getUint16(at + 10, true);
    const crc = view.getUint32(at + 16, true);
    const packed = view.getUint32(at + 20, true);
    const size = view.getUint32(at + 24, true);
    const nameLength = view.getUint16(at + 28, true);
    const extraLength = view.getUint16(at + 30, true);
    const commentLength = view.getUint16(at + 32, true);
    const local = view.getUint32(at + 42, true);
    const name = utf8(bytes.subarray(at + 46, at + 46 + nameLength), "an entry name");
    at += 46 + nameLength + extraLength + commentLength;
    if (/^[/\\]|\.\.|:|\0/.test(name)) throw new Unreadable("entry \"" + name + "\" would be written outside the archive");
    if (/\.(zip|abbreceipt|gz|tar)$/i.test(name)) throw new Unreadable("entry \"" + name + "\" is itself an archive");
    declaredTotal += size;
    if (Math.floor(size / Math.max(packed, 1)) > MAX_RATIO) throw new Unreadable("over a container limit: " + name + " looks like a zip bomb");
    if (name === "receipt.json") found = { method, crc, packed, size, local };
  }
  if (declaredTotal > MAX_TOTAL) throw new Unreadable("over a container limit: " + declaredTotal + " bytes declared");
  if (!found) throw new Unreadable("the container has no receipt.json");
  if (found.size > MAX_RECEIPT_JSON) throw new Unreadable("over a container limit: receipt.json is too large");
  if (found.local + 30 > bytes.length || view.getUint32(found.local, true) !== 0x04034b50) {
    throw new Unreadable("not a readable receipt container: bad local header");
  }
  const start = found.local + 30 + view.getUint16(found.local + 26, true) + view.getUint16(found.local + 28, true);
  const raw = bytes.subarray(start, start + found.packed);
  if (raw.length !== found.packed) throw new Unreadable("not a readable receipt container: truncated");
  let content;
  if (found.method === 0) content = raw;
  else if (found.method === 8) content = await inflateRaw(raw, found.size);
  else throw new Unreadable("not a readable receipt container: unsupported compression " + found.method);
  if (content.length !== found.size) throw new Unreadable("not a readable receipt container: wrong size");
  if (crc32(content) !== found.crc) throw new Unreadable("not a readable receipt container: checksum mismatch");
  if ((content[0] === 0x50 && content[1] === 0x4b && content[2] === 3 && content[3] === 4) || (content[0] === 0x1f && content[1] === 0x8b)) {
    throw new Unreadable("entry \"receipt.json\" is itself an archive");
  }
  return content;
}

// ------------------------------------------------------------------ reading the receipt and the key manifest

function need(node, name, kind) {
  const v = node && node[name];
  const ok = kind === "array" ? Array.isArray(v) : kind === "object" ? v && typeof v === "object" && !Array.isArray(v) : typeof v === kind;
  if (!ok) throw new Unreadable("the receipt is missing " + name);
  return v;
}
const digestOf = (text, what) => {
  const bytes = fromHex(text, what);
  if (bytes.length !== 32) throw new Unreadable(what + " must be 32 bytes");
  return bytes;
};
const pathOf = (node, name) => {
  const list = node && node[name] !== undefined ? need(node, name, "array") : [];
  return list.map((h) => digestOf(h, name));
};
const intOf = (node, name) => {
  const n = need(node, name, "number");
  if (!Number.isSafeInteger(n)) throw new Unreadable(name + " is not an integer");
  return n;
};

async function checkpointOf(node) {
  const payloadBytes = fromB64(need(node, "payload_b64", "string"), "payload_b64");
  const p = parseCanonical(payloadBytes, "a checkpoint payload");
  const fields = ["created_at", "key_id", "manifest_head", "manifest_size", "prev_checkpoint_hash", "protocol_version", "root_hash", "stream_id", "tree_size"];
  if (Object.keys(p).sort().join() !== fields.join()) throw new Unreadable("a checkpoint payload has the wrong fields");
  if (p.protocol_version !== "abb/1") throw new Unreadable("a checkpoint payload has another protocol version");
  for (const f of ["root_hash", "manifest_head", "prev_checkpoint_hash"]) {
    if (typeof p[f] !== "string" || !/^[0-9a-f]{64}$/.test(p[f])) throw new Unreadable("checkpoint " + f + " is not a digest");
  }
  for (const f of ["tree_size", "manifest_size", "created_at"]) {
    if (!Number.isSafeInteger(p[f]) || p[f] < 0) throw new Unreadable("checkpoint " + f + " is not a count");
  }
  if (typeof p.stream_id !== "string" || !p.stream_id || typeof p.key_id !== "string") throw new Unreadable("a checkpoint payload has a bad identity");
  const signing = tagged("ABB1-CHECKPOINT", payloadBytes);
  return {
    payload: p, signing, signature: need(node, "signature", "string"),
    consistency: pathOf(node, "consistency_from_previous"),
    hash: hex(await sha256(signing)),
  };
}

async function parseReceipt(bytes) {
  const value = parseStrict(utf8(bytes, "receipt.json"));
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Unreadable("receipt.json is not an object");
  if (need(value, "protocol_version", "string") !== "abb/1") throw new Unsupported("protocol_version " + value.protocol_version);
  if (intOf(value, "schema_version") !== 1) throw new Unsupported("schema_version " + value.schema_version);
  const run = need(value, "run", "object");
  const receipt = {
    runId: need(run, "run_id", "string"), profile: need(run, "profile", "string"),
    declaredCoverage: need(run, "declared_coverage", "string"),
    events: [], checkpoints: [], global: null,
    mandatePresent: Boolean(value.mandate),
    artifactsPresent: Boolean(value.artifacts && Array.isArray(value.artifacts.manifest_entries) && value.artifacts.manifest_entries.length),
  };
  for (const item of need(value, "events", "array")) {
    const proof = need(item, "inclusion_proof", "object");
    receipt.events.push({
      canonical: fromB64(need(item, "canonical_b64", "string"), "canonical_b64"),
      index: intOf(proof, "leaf_index"), size: intOf(proof, "tree_size"), path: pathOf(proof, "path"),
    });
  }
  for (const item of need(value, "checkpoints", "array")) receipt.checkpoints.push(await checkpointOf(item));
  if (value.global_log !== undefined) {
    const g = need(value, "global_log", "object");
    const proof = need(g, "inclusion_proof", "object");
    const checkpoints = [];
    for (const item of need(g, "checkpoints", "array")) checkpoints.push(await checkpointOf(item));
    receipt.global = {
      record: fromB64(need(g, "record_b64", "string"), "record_b64"),
      index: intOf(proof, "leaf_index"), size: intOf(proof, "tree_size"), path: pathOf(proof, "path"), checkpoints,
    };
  }
  return receipt;
}

const ROLES = ["signer", "witness", "approver", "mandate_issuer"];
function parseKeys(bytes) {
  let value;
  try { value = JSON.parse(utf8(bytes, "the key manifest")); } catch (e) { throw new Unreadable("the key manifest is not JSON"); }
  if (!value || !Array.isArray(value.keys)) throw new Unreadable("the key manifest has no keys list");
  return value.keys.map((k) => {
    if (!k || typeof k.key_id !== "string" || typeof k.public_key_hex !== "string" || !ROLES.includes(k.role) || typeof k.status !== "string") {
      throw new Unreadable("a key manifest entry is malformed");
    }
    const publicKey = fromHex(k.public_key_hex, "public_key_hex");
    if (publicKey.length !== 32) throw new Unreadable("a public key must be 32 bytes");
    return { keyId: k.key_id, publicKey, role: k.role, status: k.status };
  });
}

// An active key of the wanted role whose id is the digest of its own public key, or the reason not.
async function requireKey(keys, keyId, role) {
  const entry = keys.find((k) => k.keyId === keyId);
  if (!entry) return { why: "unknown key" };
  if (entry.role !== role) return { why: "the key has the wrong role" };
  if (entry.status !== "active") return { why: "the key is not active" };
  if ("ed25519:" + hex(await sha256(entry.publicKey)) !== entry.keyId) return { why: "the key id is not the digest of its public key" };
  return { entry };
}

// "ok", "bad", "badkey", or "unsupported" (this browser's Web Crypto has no Ed25519).
async function ed25519(publicKey, signatureHex, message) {
  if (!/^[0-9a-f]{128}$/.test(signatureHex)) return "bad";
  let key;
  try {
    key = await crypto.subtle.importKey("raw", publicKey, { name: "Ed25519" }, false, ["verify"]);
  } catch (e) {
    return e && e.name === "NotSupportedError" ? "unsupported" : "badkey";
  }
  try {
    return (await crypto.subtle.verify({ name: "Ed25519" }, key, fromHex(signatureHex, "signature"), message)) ? "ok" : "bad";
  } catch (e) {
    return e && e.name === "NotSupportedError" ? "unsupported" : "bad";
  }
}

// ------------------------------------------------------------------ the report

function newReport() {
  const status = {};
  for (const d of DIMENSIONS) status[d] = "UNKNOWN";
  return {
    status, details: [],
    fail(dim, locator, message) { status[dim] = "FAIL"; this.note(dim, locator, message); },
    note(dim, locator, message) {
      const d = { dimension: dim, message };
      if (locator) d.locator = locator;
      this.details.push(d);
    },
    pass(dim) { if (status[dim] !== "FAIL") status[dim] = "PASS"; },
  };
}

// ------------------------------------------------------------------ the four checks

async function checkEvents(r, report) {
  const dim = "evidence_integrity";
  if (!r.events.length) { report.note(dim, null, "the receipt carries no events"); return; }
  const last = r.checkpoints[r.checkpoints.length - 1];
  if (!last) { report.note(dim, null, "no checkpoint to check events against"); return; }
  const expectedRoot = last.payload.root_hash;
  const leaves = r.events.map((e) => tagged("ABB1-EVENT", e.canonical));
  const receiptRoot = hex(await mth(leaves));
  const failures = [];
  let ok = true;
  let previous = null;
  for (let position = 0; position < r.events.length; position++) {
    const event = r.events[position];
    const where = "event at position " + position;
    let body;
    try {
      body = parseCanonical(event.canonical, "an event");
      if (!body || typeof body !== "object" || Array.isArray(body) || typeof body.run_id !== "string"
        || typeof body.event_id !== "string" || !Number.isSafeInteger(body.sequence) || body.sequence < 0) {
        throw new Unreadable("it has no run_id, event_id and sequence");
      }
    } catch (e) {
      report.fail(dim, where, "not a valid canonical event: " + e.message);
      ok = false;
      continue;
    }
    const named = "event " + body.event_id;
    if (body.run_id !== r.runId) { report.fail(dim, named, "belongs to another run"); ok = false; }
    if (previous === null && body.sequence !== 0) {
      report.fail(dim, where, "the first event has sequence " + body.sequence + ", expected 0");
      ok = false;
    } else if (previous !== null && body.sequence !== previous + 1) {
      report.fail(dim, named, "sequence " + body.sequence + " does not follow " + previous + ": the history has a gap, a repeat or a reordering");
      ok = false;
    }
    previous = body.sequence;
    if (event.index !== body.sequence) {
      report.fail(dim, named, "the proof's leaf index does not match the event's sequence");
      ok = false;
    }
    try {
      const derived = hex(await verifyInclusion(await leafHash(leaves[position]), event.index, event.size, event.path));
      if (derived !== expectedRoot) {
        failures.push({ locator: "event " + body.event_id + " (sequence " + body.sequence + ")", derived });
        ok = false;
      }
    } catch (e) {
      if (!(e instanceof ProofError)) throw e;
      report.fail(dim, named, "inclusion proof rejected: " + e.message);
      ok = false;
    }
  }
  if (failures.length && failures.length === r.events.length && r.events.length > 1) {
    report.fail(dim, null, "none of the " + r.events.length + " events in this receipt is in the signed tree: they hash to " + receiptRoot
      + " but the signed checkpoint says " + expectedRoot + ". The receipt was rebuilt from data that had already been changed");
  } else {
    for (const f of failures) {
      report.fail(dim, f.locator, "this event is not in the signed tree: its proof derives " + f.derived + " but the checkpoint says "
        + expectedRoot + ". Its recorded bytes have been changed");
    }
  }
  if (last.payload.tree_size !== r.events.length) {
    report.fail(dim, null, "the final checkpoint covers " + last.payload.tree_size + " events but the receipt carries " + r.events.length
      + ": the history has been truncated or padded");
    ok = false;
  }
  if (ok) report.pass(dim);
}

// Signature check shared by the run's chain and the global chain. Returns "ok" | "failed" | "unsupported".
async function checkSignatures(checkpoints, keys, dim, report, label) {
  let ok = true;
  for (const c of checkpoints) {
    const got = await requireKey(keys, c.payload.key_id, "signer");
    if (got.why) { report.fail(dim, c.hash, label + "key " + c.payload.key_id + ": " + got.why); ok = false; continue; }
    const verdict = await ed25519(got.entry.publicKey, c.signature, c.signing);
    if (verdict === "unsupported") return "unsupported";
    if (verdict === "badkey") { report.fail(dim, c.hash, "unusable key"); ok = false; }
    else if (verdict !== "ok") { report.fail(dim, c.hash, label + "signature did not verify"); ok = false; }
  }
  return ok ? "ok" : "failed";
}

async function checkCheckpoints(r, keys, report) {
  const sig = "checkpoint_signatures";
  const cons = "consistency";
  if (!r.checkpoints.length) { report.note(sig, null, "the receipt carries no checkpoints"); return; }
  if (!keys) {
    report.note(sig, null, "no key manifest was supplied, so signatures were not checked");
  } else {
    const verdict = await checkSignatures(r.checkpoints, keys, sig, report, "");
    if (verdict === "ok") report.pass(sig);
    if (verdict === "unsupported") report.note(sig, null, "this browser's Web Crypto cannot check Ed25519 signatures, so they were not checked");
  }
  let ok = true;
  let earlier = null;
  for (const c of r.checkpoints) {
    if (c.payload.stream_id !== r.runId) { report.fail(cons, null, "a checkpoint belongs to another stream"); ok = false; }
    if (earlier === null) {
      if (!(c.payload.prev_checkpoint_hash === ZERO32 && c.payload.tree_size >= 1)) {
        report.fail(cons, null, "the first checkpoint is not a genesis: its previous hash is not zero");
        ok = false;
      }
    } else {
      if (c.payload.prev_checkpoint_hash !== earlier.hash) {
        report.fail(cons, c.hash, "this checkpoint does not link to the previous one");
        ok = false;
      }
      if (c.payload.tree_size < earlier.payload.tree_size) {
        report.fail(cons, null, "a later checkpoint covers fewer events than an earlier one");
        ok = false;
      }
      try {
        const derived = hex(await verifyConsistency(earlier.payload.tree_size, c.payload.tree_size, fromHex(earlier.payload.root_hash, "root"), c.consistency));
        if (derived !== c.payload.root_hash) {
          report.fail(cons, c.hash, "the consistency proof does not reach this checkpoint's root");
          ok = false;
        }
      } catch (e) {
        if (!(e instanceof ProofError)) throw e;
        report.fail(cons, c.hash, "consistency proof rejected: " + e.message);
        ok = false;
      }
    }
    earlier = c;
  }
  if (ok) report.pass(cons);
}

async function checkGlobalLog(r, keys, report) {
  const dim = "global_log_inclusion";
  const g = r.global;
  if (!g) {
    report.note(dim, null, "the receipt carries no global-log inclusion, so a deleted run could not be detected from it");
    return;
  }
  const finalGlobal = g.checkpoints[g.checkpoints.length - 1];
  if (!finalGlobal) { report.note(dim, null, "no global checkpoint"); return; }
  let ok = true;
  let record = null;
  try { record = parseStrict(utf8(g.record, "the global record")); } catch (_) { record = null; }
  const runFinal = r.checkpoints[r.checkpoints.length - 1];
  if (record && typeof record === "object" && runFinal) {
    if (record.run_id !== r.runId) { report.fail(dim, null, "the global record names another run"); ok = false; }
    if (record.checkpoint_hash !== runFinal.hash) { report.fail(dim, null, "the global record does not name this run's final checkpoint"); ok = false; }
  } else {
    report.fail(dim, null, "the global record is unreadable");
    ok = false;
  }
  try {
    const leaf = await leafHash(tagged("ABB1-RUNROOT", g.record));
    const derived = hex(await verifyInclusion(leaf, g.index, g.size, g.path));
    if (derived !== finalGlobal.payload.root_hash) { report.fail(dim, null, "this run is not in the signed global log"); ok = false; }
  } catch (e) {
    if (!(e instanceof ProofError)) throw e;
    report.fail(dim, null, "global inclusion proof rejected: " + e.message);
    ok = false;
  }
  if (finalGlobal.payload.stream_id !== "global") { report.fail(dim, null, "the global checkpoint is not the global stream"); ok = false; }
  if (keys) {
    const verdict = await checkSignatures(g.checkpoints, keys, dim, report, "global checkpoint ");
    if (verdict === "failed") ok = false;
    if (verdict === "unsupported") {
      report.note(dim, null, "this browser's Web Crypto cannot check Ed25519 signatures, so the global checkpoint signature was not checked");
    }
  }
  if (ok) report.pass(dim);
}

// ------------------------------------------------------------------ the whole check

const REQUIRED = ["evidence_integrity", "checkpoint_signatures", "consistency", "global_log_inclusion", "observation_coverage", "policy_assessment"];

function requirements(r) {
  const out = {};
  for (const d of DIMENSIONS) {
    out[d] = REQUIRED.includes(d) ? "required"
      : d === "mandate_compliance" ? (r.mandatePresent ? "required" : "optional")
      : d === "artifact_manifest_integrity" ? (r.artifactsPresent ? "required" : "optional")
      : ["witness_quorum", "anchor_match", "artifact_availability"].includes(d) ? "optional" : "informational";
  }
  return out;
}

const refusal = (error) => ({
  overall: error instanceof Unsupported ? "UNSUPPORTED" : "UNREADABLE",
  message: error.message, engine: "javascript",
});

// The same report shape as `abb verify --json` (plus `engine` and `unchecked`). Never VALID.
async function verifyReceipt(receiptBytes, keysBytes) {
  let receipt;
  try {
    receipt = await parseReceipt(await readContainer(receiptBytes));
  } catch (e) {
    if (e instanceof Unreadable || e instanceof Unsupported) return refusal(e);
    throw e;
  }
  let keys = null;
  if (keysBytes && keysBytes.length) {
    try { keys = parseKeys(keysBytes); } catch (e) {
      if (e instanceof Unreadable) return refusal(e);
      throw e;
    }
  }
  const report = newReport();
  await checkEvents(receipt, report);
  await checkCheckpoints(receipt, keys, report);
  await checkGlobalLog(receipt, keys, report);
  const unchecked = DIMENSIONS.filter((d) => !CHECKED.includes(d));
  for (const d of unchecked) report.note(d, null, "not checked by the JavaScript fallback");
  const failed = DIMENSIONS.some((d) => report.status[d] === "FAIL");
  return {
    overall: failed ? "INVALID" : "INCOMPLETE",
    run_id: receipt.runId, profile: receipt.profile, declared_coverage: receipt.declaredCoverage,
    dimensions: report.status, requirements: requirements(receipt), details: report.details,
    engine: "javascript", unchecked,
  };
}

window.HCFallback = {
  verifyReceipt,
  checked: CHECKED.slice(),
  internals: { PROTOCOL_LIMITS, parseStrict, canon, parseCanonical, leafHash, nodeHash, mth, verifyInclusion, verifyConsistency, sha256, hex, fromHex, tagged },
};
})();
