#!/usr/bin/env node
// Score an agent's record against a HashCam Range level from the command line, for a build or a CI job.
//
//   node tools/range_score.mjs --level <id or number> <record> [more files]
//   node tools/range_score.mjs --level 3 run.html
//   node tools/range_score.mjs --level hidden-instruction run.abbreceipt run.abbreceipt.keys.json
//
// A sandbox level takes the .html receipt the Gatekeeper Sandbox exported; an extension level takes the
// .abbreceipt and its .keys.json. The record is VERIFIED FIRST (the sandbox's hash chain and signatures, or the
// HashCam verifier for a receipt); one that does not check out is never scored.
//
// It is the website's own code: this file loads site/chain.js, verify.js, fallback.js, pro/records.js,
// range/scenarios.js and range/score.js in a sandbox and calls them, so there is ONE copy of the rules.
// Nothing is sent anywhere; no package is needed (Node 18 or newer).
//
// Exit codes:  0 PASSED   1 FAILED or INCOMPLETE   2 the record does not check out or cannot be read
//              3 cannot run: bad arguments, or a level that needs a Pro licence
//
// Licence: levels 9 to 16 are Pro. Put a key in the HASHCAM_LICENSE environment variable. Without a valid key
// only levels 1 to 6 are scored, and the output says so. (The check runs on your machine: it is not enforced
// by a server.)
import fs from "node:fs";
import path from "node:path";
import vm from "node:vm";
import { fileURLToPath } from "node:url";

let SITE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "site");
const MAX_BYTES = 8 * 1048576;

const USAGE = `Usage: node tools/range_score.mjs --level <id or number> [--site-host HOST] [--json] <record> [keys.json]
  --level      the Range level, by id (first-flight) or number (1)
  --site-host  for the extension levels: the host the agent was told to stay on (default hashcam.vercel.app)
  --json       print the result as JSON
  --site       use another copy of the site's files (for example a self-hosted copy) instead of ./site
Exit codes: 0 PASSED, 1 FAILED or INCOMPLETE, 2 record does not check out or cannot be read, 3 cannot run.
Levels 9 to 16 need a Pro licence key in the HASHCAM_LICENSE environment variable.`;

// Output is written first and the exit code is only SET, never forced with process.exit(): on some systems an
// immediate exit loses output that is still queued on a pipe.
class Stop extends Error {
  constructor(code) { super(`exit ${code}`); this.code = code; }
}
const say = (text) => process.stdout.write(text + "\n");
const fail = (code, text) => { process.stderr.write(text + "\n"); throw new Stop(code); };

function parse(argv) {
  const out = { files: [], json: false, siteHost: "hashcam.vercel.app", level: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--help" || a === "-h") { say(USAGE); throw new Stop(0); }
    else if (a === "--json") out.json = true;
    else if (a === "--level" || a === "--site-host" || a === "--site") {
      const value = argv[++i];
      if (!value || value.startsWith("--")) fail(3, `${a} needs a value.\n${USAGE}`);
      if (a === "--level") out.level = value;
      else if (a === "--site") SITE = path.resolve(value);
      else out.siteHost = value.toLowerCase();
    } else if (a.startsWith("--")) fail(3, `Unknown option ${a}.\n${USAGE}`);
    else out.files.push(a);
  }
  if (!out.level) fail(3, `--level is required.\n${USAGE}`);
  if (!out.files.length) fail(3, `Give the record to score.\n${USAGE}`);
  return out;
}

// The site's own scripts, in a sandbox with just the browser features they use.
function loadSite() {
  const fetchLocal = async (name) => {
    const file = path.resolve(SITE, String(name));
    if (path.basename(file) !== "verifier.wasm" || path.dirname(file) !== SITE) throw new Error("only verifier.wasm may be read");
    const bytes = fs.readFileSync(file);
    return { ok: true, status: 200, arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) };
  };
  const sandbox = {
    crypto: globalThis.crypto, TextEncoder, TextDecoder, Blob, Response, DecompressionStream, atob, btoa, URL,
    WebAssembly, console, location: { protocol: "http:" }, fetch: fetchLocal,
  };
  sandbox.window = sandbox;
  sandbox.self = sandbox;
  vm.createContext(sandbox);
  for (const name of ["chain.js", "fallback.js", "verify.js", "readable.js", "pro/records.js", "range/scenarios.js",
    "range/limits.js", "range/score.js", "pro/pubkey.js", "pro/license.js"]) {
    vm.runInContext(fs.readFileSync(path.join(SITE, name), "utf8"), sandbox, { filename: name });
  }
  return sandbox;
}

// A file the way the site's scripts expect one: a name, a size and the bytes or the text.
function asFile(filePath) {
  let stat;
  try { stat = fs.statSync(filePath); } catch { fail(2, `Cannot read ${filePath}: no such file.`); }
  if (!stat.isFile() || stat.size > MAX_BYTES) fail(2, `Cannot read ${filePath}: it is not a file, or it is over ${MAX_BYTES / 1048576} MB.`);
  const bytes = fs.readFileSync(filePath);
  return {
    name: path.basename(filePath),
    size: bytes.length,
    text: async () => bytes.toString("utf8"),
    arrayBuffer: async () => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength),
  };
}

async function planFrom(site) {
  const token = (process.env.HASHCAM_LICENSE || "").trim();
  const key = site.HCProKey && site.HCProKey.publicKeyHex;
  if (!token) return { plan: "anonymous", note: "No HASHCAM_LICENSE set: scoring levels 1 to 6 only." };
  if (!key) return { plan: "anonymous", note: "This copy of the site has no licence checking set up, so the key was not used: scoring levels 1 to 6 only." };
  const result = await site.HCLicense.verifyLicense(token, key);
  if (result.ok) return { plan: "pro", note: `Pro licence for ${result.licence.name}.` };
  return { plan: "anonymous", note: `The licence key was not accepted (${result.reason}) Scoring levels 1 to 6 only.` };
}

async function main() {
  const args = parse(process.argv.slice(2));
  const site = loadSite();
  const R = site.HCRecords, S = site.HCScore;
  const levels = site.HCRangeData.levels;
  const level = levels.find((l) => l.id === args.level || String(l.n) === args.level);
  if (!level) fail(3, `No such level: ${args.level}. Levels: ${levels.map((l) => `${l.n} ${l.id}`).join(", ")}.`);

  const { plan, note } = await planFrom(site);
  if (!site.HCLimits.allowed(plan, level.id) && level.n > 6) {
    fail(3, `Level ${level.n} (${level.title}) needs a Pro licence. ${note}`);
  }

  const files = args.files.map(asFile);
  let result, engine;
  try {
    if (level.source === "sandbox") {
      const file = files.find(R.isSandboxFile);
      if (!file) fail(3, "Give the .html receipt exported from the Gatekeeper Sandbox.");
      const checked = await R.checkSandbox(file);
      if (!checked.ok) fail(2, R.explain(checked.failure, "scored"));
      const custom = R.policyRefusal(checked.events);
      if (custom) fail(2, custom);
      result = S.scoreSandbox(level, checked.events);
      engine = "The sandbox record's fingerprints and signatures were re-computed and match. That shows it was not edited, not where it came from.";
    } else {
      const receipt = files.find(R.isReceiptFile);
      if (!receipt) fail(3, "Give the .abbreceipt your extension saved (and its .keys.json).");
      const checked = await R.checkReceipt(receipt, files.find(R.isKeys));
      if (!checked.ok) fail(2, R.explain(checked.failure, "scored"));
      result = S.scoreReceipt(level, checked.events, { siteHost: args.siteHost });
      engine = `Verdict VALID from ${checked.via}.`;
    }
  } catch (error) {
    if (error instanceof Stop) throw error;
    fail(2, String((error && error.message) || error));
  }

  const summary = `Level ${level.n} · ${level.title}: ${result.overall} (${result.tally.pass} of ${result.tally.total} checks passed)`;
  if (args.json) {
    say(JSON.stringify({
      level: level.id, n: level.n, title: level.title, overall: result.overall, tally: result.tally, engine, plan,
      criteria: result.criteria.map((c) => ({ id: c.id, label: c.label, status: c.status, evidence: c.evidence })),
    }, null, 2));
  } else {
    say(summary);
    for (const c of result.criteria) say(`  ${c.status.padEnd(7)} ${c.label} - ${c.evidence}`);
    say(engine);
    say("A score is a summary, not a proof. " + note);
  }
  throw new Stop(result.overall === "PASSED" ? 0 : 1);
}

main().catch((error) => {
  if (error instanceof Stop) { process.exitCode = error.code; return; }
  process.stderr.write(String((error && error.message) || error) + "\n");
  process.exitCode = 2;
});
