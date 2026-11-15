// The receipt verifier for the browser, shared by the home page and the Range: the Rust verifier as
// WebAssembly first, and if it cannot load or run (file missing, blocked, old browser) the JavaScript
// fallback, which can prove a receipt INVALID but never calls one VALID (see fallback.js).
// A classic script, so it also works from a file:// page. Sets window.HCVerify.
(function () {
"use strict";

const fromDisk = location.protocol === "file:";

let wasm = null;
let wasmFailure = null; // why WebAssembly is unavailable here, once known: one attempt, one console line

function bytesOfB64(text) {
  const bin = atob(text);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function loadScript(src) {
  return new Promise((resolve, reject) => {
    const s = document.createElement("script");
    s.src = src;
    s.onload = resolve;
    s.onerror = () => reject(new Error(`could not load ${src}`));
    document.head.append(s);
  });
}

// From a file:// page the browser forbids fetch() of a neighbouring file, so the verifier and the
// samples travel in offline-data.js (base64), loaded only then.
async function offlineData() {
  if (!window.HC_OFFLINE) await loadScript("offline-data.js");
  return window.HC_OFFLINE;
}

async function verifier() {
  if (wasm) return wasm;
  if (wasmFailure) throw wasmFailure;
  try {
    let bytes;
    if (fromDisk) {
      bytes = bytesOfB64((await offlineData()).wasm);
    } else {
      // Relative to this page, so it works at the site root and under any folder it is served from.
      const response = await fetch("verifier.wasm");
      if (!response.ok) throw new Error(`verifier.wasm answered HTTP ${response.status}`);
      bytes = new Uint8Array(await response.arrayBuffer());
    }
    if (bytes.length < 8 || bytes[0] !== 0 || bytes[1] !== 0x61 || bytes[2] !== 0x73 || bytes[3] !== 0x6d) {
      throw new Error("verifier.wasm is not a WebAssembly file");
    }
    const { instance } = await WebAssembly.instantiate(bytes, {});
    wasm = instance.exports;
  } catch (error) {
    wasmFailure = error;
    throw error;
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
async function verifyWasm(receiptBytes, keysBytes) {
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

// WebAssembly first. If it cannot load or run (file missing, blocked, old browser), the JavaScript
// fallback checks the cryptographic core instead and the page says so: it can prove a receipt
// INVALID but never calls one VALID (see fallback.js).
async function verify(receiptBytes, keysBytes) {
  try {
    const report = await verifyWasm(receiptBytes, keysBytes);
    report.engine = "wasm";
    return report;
  } catch (error) {
    const report = await window.HCFallback.verifyReceipt(receiptBytes, keysBytes);
    report.engine = "javascript";
    report.fallback_reason = String((error && error.message) || error);
    return report;
  }
}

window.HCVerify = { verify, bytesOfB64, offlineData, fromDisk };
})();
