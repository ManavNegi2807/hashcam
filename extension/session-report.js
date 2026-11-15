// A sealed session as a locked PDF report: what the agent did well, what went wrong and what to do next,
// in the plain words the panel already uses. It is written and locked here (lockedpdf.js: AES-256, a new
// random password each time), never uploaded.
//
// Nothing is shown that the panel would hide: every line goes through describe() (secrets masked, URL
// query strings cut, paths left out for an agent marked sensitive), and a sensitive agent's task is
// withheld. It decides nothing: the verdict is the offline verifier's, copied as it was.
//
// No extension API calls, so it runs (and is tested) as a plain module.

import { describe, scrub, verdictText } from "./readable.js";
import { buildLockedPdf } from "./lockedpdf.js";
import { reportArt } from "./report-art.js";

const MAX_ROWS = 40; // per section: a long session says "and 120 more" instead of filling the file

const TONE = { ok: "good", stop: "bad", hold: "warn" };

function rows(list, limit = MAX_ROWS) {
  const out = list.slice(0, limit);
  if (list.length > limit) {
    out.push({ style: "small", text: `...and ${list.length - limit} more. The saved receipt has every step.` });
  }
  return out;
}

// The facts the report is made from: counted once, so the sections and the advice agree.
function facts(view) {
  const ctx = { sensitive: view.sensitive === true };
  const lines = [];
  for (const e of view.timeline || []) {
    if (e.kind === "SESSION" || e.kind === "SEALED") continue;
    lines.push({ e, said: describe(e, ctx) });
  }
  const good = lines.filter((l) => l.said.tone === "ok" || l.said.tone === "note");
  const bad = lines.filter((l) => l.said.tone === "stop");
  const held = lines.filter((l) => l.said.tone === "hold");
  const headsUp = lines.flatMap((l) => l.said.notes.map((note) => ({ note, where: l.said.where })));
  const drift = lines.filter((l) => l.e.drift).length;
  const tripwire = lines.filter((l) => l.e.tripwire).length;
  return { lines, good, bad, held, headsUp, drift, tripwire };
}

const row = (l) => ({
  style: "row",
  chip: l.said.badge,
  tone: TONE[l.said.tone] || "soft",
  lead: `${l.said.title}.`.replace(/\.\.$/, "."),
  text: l.said.why,
});

export function reportDoc(view, receiptSha256) {
  const sensitive = view.sensitive === true;
  const overall = String((view.verdict && view.verdict.overall) || "UNREADABLE");
  const f = facts(view);
  const when = new Date((view.started || Date.now() / 1000) * 1000).toISOString().slice(0, 10);
  const agent = scrub(view.agent || "Browser agent");
  const task = sensitive ? "The task is withheld: this agent is marked sensitive." : `Its task: ${scrub(view.task || "not given")}`;

  const blocks = [{
    style: "verdict",
    overall,
    tone: overall === "VALID" ? "good" : overall === "INVALID" ? "bad" : "warn",
    title: `Session of ${agent}`,
    text: task,
    score: String(f.lines.length),
    scoreNote: "steps recorded",
  }];

  blocks.push({ style: "h", text: "What your agent did well" });
  if (!f.good.length) blocks.push({ style: "p", text: "Nothing was allowed in this session." });
  blocks.push(...rows(f.good.map(row)));

  blocks.push({ style: "h", text: "What went wrong" });
  if (!f.bad.length && !f.headsUp.length) blocks.push({ style: "p", text: "Nothing was blocked and nothing looked off." });
  blocks.push(...rows(f.bad.map(row)));
  blocks.push(...rows(f.headsUp.map((h) => ({ style: "row", chip: "Heads-up", tone: "warn", lead: `${h.where || "A page"}.`, text: h.note.replace(/^Heads-up:\s*/, "") }))));

  if (f.held.length) {
    blocks.push({ style: "h", text: "Still waiting for a person" });
    blocks.push(...rows(f.held.map(row)));
  }

  blocks.push({ style: "h", text: "What to do next" });
  const next = [];
  if (overall !== "VALID") {
    next.push({ lead: "Do not rely on this record.", text: "The offline verifier did not call it VALID. Run the agent again and save a fresh receipt." });
  }
  if (f.bad.length) {
    next.push({ lead: "Look at each blocked step.", text: "If the agent was right to try it, add that site to its passport. If not, make its task more specific." });
  }
  if (f.drift) {
    next.push({ lead: "It went to sites the task does not mention.", text: "Name the sites the agent should use in its task, so a stray visit stands out." });
  }
  if (f.tripwire) {
    next.push({ lead: "A page tried to steer the agent.", text: "Check which page it was, and keep this agent away from it." });
  }
  if (f.held.length) {
    next.push({ lead: "A step was left waiting.", text: "Approve or refuse held steps before the time runs out, or the agent cannot finish." });
  }
  if (!next.length) next.push({ text: "Nothing needs fixing. Keep the receipt and its key manifest: they are the proof." });
  else next.push({ text: "Keep the receipt and its key manifest: they are the proof." });
  blocks.push(...next.map((n) => ({ style: "step", ...n })));

  blocks.push({ style: "h", text: "How this was checked" });
  blocks.push({ style: "p", text: `The offline verifier says ${overall}. ${verdictText(overall)}` });
  if (receiptSha256) blocks.push({ style: "small", text: `Receipt: ${scrub(view.receipt || "receipt")} - SHA-256 ${receiptSha256}` });
  if (sensitive) {
    blocks.push({ style: "small", text: "This agent is marked sensitive: its task, its paths and its raw records are left out of this report." });
  }
  blocks.push({ style: "small", text: "A report is a summary, not a proof. If someone shows you this one, ask for the receipt and check it yourself." });

  blocks.push({ style: "h", text: "About the lock on this file" });
  blocks.push({ style: "b", text: "This PDF is locked with AES-256. It opens only with the password the panel showed when it was made." });
  blocks.push({ style: "b", text: "The password was made by the browser's secure random source. It was shown once and is not stored anywhere." });
  blocks.push({ style: "b", text: "Never send the password in the same message as the file." });

  return {
    brand: ["HashCam", "Recorder"],
    kicker: "Agent session report",
    date: when,
    running: `Session of ${agent}`,
    footer: "HashCam Recorder - a report is a summary, not a proof. Ask for the receipt.",
    chip: 78,
    blocks,
  };
}

export async function makeSessionReport(view, receiptSha256) {
  return buildLockedPdf(reportDoc(view, receiptSha256), reportArt);
}
