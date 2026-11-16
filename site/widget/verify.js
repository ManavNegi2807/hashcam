// "Check a HashCam receipt": a small drop box another website can include with ONE script tag.
//
//   <div data-hashcam-verify></div>
//   <script src="https://hashcam.vercel.app/widget/verify.js" async></script>
//
// It checks a dropped .abbreceipt (and its .keys.json) with the real HashCam verifier, compiled to WebAssembly, and
// shows VALID, INVALID, INCOMPLETE or UNREADABLE. What it does and does not do:
//   * It loads from the HashCam site only: this file and verifier.wasm. Nothing else is fetched.
//   * It sends nothing anywhere. The receipt is read and checked inside the visitor's page.
//   * It shows fixed words only, never text taken from the receipt, so a receipt cannot put markup or a link on
//     the host page.
//   * It lives in a shadow root, so the host page's styles cannot break it and it cannot restyle the host page.
//     Its styles are a constructable stylesheet, which a strict host Content Security Policy (no inline styles)
//     does not block.
//   * A VALID receipt means the record has not changed since it was signed. It does not mean the agent was honest.
// The host page's Content Security Policy needs: script-src https://hashcam.vercel.app 'wasm-unsafe-eval'; connect-src https://hashcam.vercel.app
// (see the About page of the HashCam site).
(() => {
"use strict";

const script = document.currentScript;
if (!script || !script.src) return; // loaded in a way that cannot be placed: do nothing rather than guess
const ORIGIN = new URL(script.src).origin; // where this file came from: the only place it fetches from
const MAX_BYTES = 8 * 1048576;

const WORDS = {
  VALID: "The record has not changed since it was signed. That does not mean the agent was honest.",
  INVALID: "Something in this receipt was changed or does not add up. Do not trust it.",
  INCOMPLETE: "Part of this receipt could not be checked.",
  UNREADABLE: "This file is not a receipt this verifier can read.",
};

const CSS = `
:host { all: initial; display: block; font: 14px/1.45 system-ui, -apple-system, "Segoe UI", sans-serif; color: #e6e9ef; }
.box { box-sizing: border-box; max-width: 420px; padding: 16px; background: #101624; border: 1px solid #2a3350; border-radius: 12px; }
.title { margin: 0 0 4px; font-weight: 700; font-size: 15px; }
.hint { margin: 0 0 10px; color: #9aa4b8; font-size: 13px; }
.drop { border: 1px dashed #4a5578; border-radius: 10px; padding: 12px; }
.drop.over { border-color: #f59e0b; }
input[type="file"] { max-width: 100%; color: #e6e9ef; font: inherit; }
.out { margin: 10px 0 0; min-height: 1.4em; overflow-wrap: anywhere; }
.out b { display: block; font: 700 18px ui-monospace, Consolas, monospace; letter-spacing: .06em; }
.ok b { color: #34d399; } .bad b { color: #fb7185; } .warn b { color: #fbbf24; }
.foot { margin: 10px 0 0; font-size: 12px; color: #9aa4b8; }
.foot a { color: #fbbf24; }
`;

let engine = null; // the verifier's exports, loaded once

async function load() {
  if (engine) return engine;
  const response = await fetch(ORIGIN + "/verifier.wasm", { mode: "cors", credentials: "omit" });
  if (!response.ok) throw new Error("the verifier did not load");
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes.length < 8 || bytes[0] !== 0 || bytes[1] !== 0x61 || bytes[2] !== 0x73 || bytes[3] !== 0x6d) throw new Error("the verifier is not a WebAssembly file");
  engine = (await WebAssembly.instantiate(bytes, {})).instance.exports;
  return engine;
}

function put(x, bytes) {
  if (!bytes.length) return 0;
  const ptr = x.abb_alloc(bytes.length);
  new Uint8Array(x.memory.buffer, ptr, bytes.length).set(bytes);
  return ptr;
}

// The same call as `abb verify --json`. Returns only the overall verdict word.
async function verdict(receipt, keys) {
  const x = await load();
  const rp = put(x, receipt), kp = put(x, keys);
  const packed = x.abb_verify(rp, receipt.length, kp, keys.length, 0);
  x.abb_free(rp, receipt.length);
  x.abb_free(kp, keys.length);
  const ptr = Number(packed >> 32n), len = Number(packed & 0xffffffffn);
  const json = new TextDecoder().decode(new Uint8Array(x.memory.buffer, ptr, len).slice());
  x.abb_free(ptr, len);
  let overall = "";
  try { overall = String(JSON.parse(json).overall || ""); } catch { /* fall through to UNREADABLE */ }
  return Object.hasOwn(WORDS, overall) ? overall : "UNREADABLE";
}

function build(host) {
  const root = host.attachShadow({ mode: "open" });
  try {
    const sheet = new CSSStyleSheet();
    sheet.replaceSync(CSS);
    root.adoptedStyleSheets = [sheet];
  } catch { /* an old browser: it works, only unstyled */ }
  const el = (tag, cls, text) => {
    const node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text) node.textContent = text;
    return node;
  };
  const box = el("div", "box");
  const drop = el("div", "drop");
  const input = el("input");
  input.type = "file";
  input.multiple = true;
  input.accept = ".abbreceipt,.json";
  input.setAttribute("aria-label", "A HashCam receipt (.abbreceipt) and, if you have it, its keys (.keys.json)");
  const out = el("p", "out");
  out.setAttribute("role", "status");
  out.setAttribute("aria-live", "polite");
  const link = el("a", "", "HashCam");
  link.href = ORIGIN + "/";
  link.target = "_blank";
  link.rel = "noopener noreferrer";
  const foot = el("p", "foot", "Checked with ");
  foot.append(link);
  drop.append(input);
  box.append(el("p", "title", "Check a HashCam receipt"),
    el("p", "hint", "Drop the .abbreceipt (and its .keys.json if you have it). It is checked in this page; nothing is uploaded."),
    drop, out, foot);
  root.append(box);

  const show = (cls, word, text) => {
    out.className = "out " + cls;
    out.textContent = "";
    if (word) out.append(el("b", "", word));
    out.append(document.createTextNode(text));
  };

  async function check(files) {
    const list = [...files];
    const receipt = list.find((f) => /\.abbreceipt$/i.test(f.name));
    const keys = list.find((f) => /\.keys\.json$/i.test(f.name));
    if (!receipt) { show("warn", "", "Drop the .abbreceipt file."); return; }
    if (list.length > 4 || list.some((f) => f.size > MAX_BYTES)) { show("warn", "", "Too much to check: at most 4 files, each under 8 MB."); return; }
    show("", "", "Checking…");
    try {
      const result = await verdict(new Uint8Array(await receipt.arrayBuffer()), keys ? new Uint8Array(await keys.arrayBuffer()) : new Uint8Array());
      const missing = result === "INCOMPLETE" && !keys ? " Drop its .keys.json too." : "";
      show(result === "VALID" ? "ok" : result === "INVALID" ? "bad" : "warn", result, " " + WORDS[result] + missing);
    } catch {
      show("warn", "", "Could not check: the verifier did not load here, so nothing was checked.");
    }
  }

  input.addEventListener("change", () => check(input.files));
  drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
  drop.addEventListener("dragleave", () => drop.classList.remove("over"));
  drop.addEventListener("drop", (e) => {
    e.preventDefault();
    drop.classList.remove("over");
    if (e.dataTransfer && e.dataTransfer.files.length) check(e.dataTransfer.files);
  });
}

function start() {
  let hosts = [...document.querySelectorAll("[data-hashcam-verify]")];
  if (!hosts.length) { // no placeholder: put one right after the script tag
    const host = document.createElement("div");
    host.setAttribute("data-hashcam-verify", "");
    script.after(host);
    hosts = [host];
  }
  for (const host of hosts) {
    if (host.shadowRoot || host.hasAttribute("data-hashcam-ready")) continue;
    host.setAttribute("data-hashcam-ready", "");
    build(host);
  }
}

if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start, { once: true });
else start();
})();
