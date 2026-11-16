// The audit pack and the CSV: what many verified records say, in one locked PDF or one spreadsheet file.
//
// Only records that CHECKED OUT are in here (records.js). Every line goes through readable.js, the same plain-
// words reader as everywhere else: secrets are masked, URL query strings are cut, and a sensitive agent's
// raw record is never shown. Nothing is uploaded; the PDF is written and locked in this tab (lockedpdf.js).
(() => {
"use strict";

const R = window.HCReadable;
const MAX_ROWS = 40; // steps listed per session in the PDF; the CSV has every step

const isSandbox = (rec) => rec.kind === "sandbox";
const bodyOf = (e) => (e && typeof e.body === "object" && e.body ? e.body : e || {});

// What happened, counted once so the summary and the sections agree.
function tally(rec) {
  const t = { allowed: 0, blocked: 0, held: 0, approved: 0, refused: 0, headsUp: 0 };
  for (const e of rec.events) {
    if (isSandbox(rec)) {
      const b = bodyOf(e), d = (b.data && typeof b.data === "object") ? b.data : {};
      if (b.type === "POLICY_DECISION") {
        if (d.outcome === "ALLOW") t.allowed++;
        else if (d.outcome === "DENY") t.blocked++;
        else if (d.outcome === "HOLD") t.held++;
      } else if (b.type === "HUMAN_DECISION") {
        if (d.decision === "GRANTED") t.approved++; else t.refused++;
      } else if (b.type === "SESSION_HALTED") t.headsUp++;
    } else {
      const p = (e.payload && typeof e.payload === "object") ? e.payload : {};
      switch (e.event_type) {
        case "ACTION_AUTHORIZED": t.allowed++; break;
        case "ACTION_BLOCKED": t.blocked++; break;
        case "HUMAN_APPROVAL_REQUESTED": t.held++; break;
        case "HUMAN_APPROVAL_GRANTED": t.approved++; break;
        case "HUMAN_APPROVAL_DENIED": t.refused++; break;
        case "POLICY_VIOLATION_DETECTED":
        case "SEMANTIC_VIOLATION_DETECTED": t.headsUp++; break;
        case "PROMPT_SECURITY_ANALYSIS_COMPLETED": if (p.verdict && p.verdict !== "ALLOW") t.headsUp++; break;
        default: break;
      }
    }
  }
  return t;
}

const typeOf = (rec, e) => (isSandbox(rec) ? String(bodyOf(e).type || "") : String(e.event_type || ""));
const plain = (text) => String(text == null ? "" : text);

function sum(records) {
  const total = { allowed: 0, blocked: 0, held: 0, approved: 0, refused: 0, headsUp: 0 };
  for (const rec of records) for (const k of Object.keys(total)) total[k] += tally(rec)[k];
  return total;
}

const sessionLine = (t) =>
  `${t.allowed} allowed, ${t.blocked} blocked, ${t.held} held for a person, ${t.approved} approved, ${t.refused} refused by a person, ${t.headsUp} heads-up.`;

// included: [{ name, sha256, kind, events }]   skipped: [{ name, reason }]
function packDoc({ included, skipped, brandName, whiteLabel, at, enterprise }) {
  const name = whiteLabel && brandName ? brandName : "HashCam";
  const all = sum(included);
  const blocks = [{
    style: "verdict",
    overall: "AUDIT PACK",
    tone: skipped.length ? "warn" : "good",
    title: `${included.length} session${included.length === 1 ? "" : "s"} included, ${skipped.length} not included`,
    text: "Only records that checked out are in this pack. A record that was edited, or whose receipt is not VALID, is listed as not included.",
    score: String(included.length),
    scoreNote: "sessions",
  }];

  blocks.push({ style: "h", text: "Totals across all sessions" });
  blocks.push({ style: "row", chip: "Allowed", tone: "good", lead: `${all.allowed} steps.`, text: "Allowed by the rules." });
  blocks.push({ style: "row", chip: "Blocked", tone: "bad", lead: `${all.blocked} steps.`, text: "Stopped by the rules." });
  blocks.push({ style: "row", chip: "Held", tone: "warn", lead: `${all.held} steps.`, text: "Waited for a person to decide." });
  blocks.push({ style: "row", chip: "Approved", tone: "good", lead: `${all.approved} steps.`, text: "A person approved them." });
  blocks.push({ style: "row", chip: "Refused", tone: "bad", lead: `${all.refused} steps.`, text: "A person said no." });
  blocks.push({ style: "row", chip: "Heads-up", tone: "warn", lead: `${all.headsUp} notices.`, text: "Something looked off: a page tried to steer an agent, a rule was broken, or a session was halted." });

  blocks.push({ style: "h", text: "Sessions" });
  if (!included.length) blocks.push({ style: "p", text: "No record could be included." });
  included.forEach((rec, i) => {
    blocks.push({
      style: "row",
      chip: isSandbox(rec) ? "Intact" : "Valid",
      tone: "good",
      lead: `Session ${i + 1} (${plain(rec.name)}).`,
      text: sessionLine(tally(rec)),
    });
  });

  if (skipped.length) {
    blocks.push({ style: "h", text: "Not included" });
    for (const s of skipped) blocks.push({ style: "row", chip: "Not included", tone: "bad", lead: `${plain(s.name)}.`, text: plain(s.reason) });
  }

  included.forEach((rec, i) => {
    blocks.push({ style: "h", text: `Session ${i + 1}: ${plain(rec.name)}` });
    const said = rec.events.map((e) => R.describe(e)).filter((s) => ["ok", "stop", "hold", "note"].includes(s.tone));
    if (!said.length) blocks.push({ style: "p", text: "No steps to list." });
    for (const s of said.slice(0, MAX_ROWS)) {
      blocks.push({ style: "row", chip: s.badge, tone: { ok: "good", stop: "bad", hold: "warn" }[s.tone] || "soft", lead: `${s.title}.`.replace(/\.\.$/, "."), text: s.why });
    }
    if (said.length > MAX_ROWS) blocks.push({ style: "small", text: `...and ${said.length - MAX_ROWS} more. The CSV export has every step.` });
  });

  blocks.push({ style: "h", text: "How this was checked" });
  blocks.push({ style: "p", text: "Each record was verified in the browser before it was used: a sandbox record's hash chain and signatures were re-computed, and an extension receipt was checked by the HashCam verifier and had to be VALID. A sandbox record shows it was not edited, not where it came from." });
  for (const rec of included) blocks.push({ style: "small", text: `${plain(rec.name)} - SHA-256 ${rec.sha256}` });
  blocks.push({ style: "small", text: "A report is a summary, not a proof. Ask for the records and check them yourself. It is not legal or compliance advice." });

  blocks.push({ style: "h", text: "About the lock on this file" });
  blocks.push({ style: "b", text: "This PDF is locked with AES-256. It opens only with the password shown when it was made." });
  blocks.push({ style: "b", text: "The password was made by the browser's secure random source, was shown once and is stored nowhere." });
  blocks.push({ style: "b", text: "Never send the password in the same message as the file." });

  return {
    brand: whiteLabel ? [name, ""] : ["HashCam", "Pro"],
    kicker: "Agent audit pack",
    date: at,
    running: `Audit pack: ${included.length} session${included.length === 1 ? "" : "s"}`,
    footer: `${whiteLabel ? name + " - " : ""}${enterprise && whiteLabel ? "" : "Made with HashCam. "}A report is a summary, not a proof.`,
    chip: 78,
    blocks,
  };
}

// ---------------------------------------------------------------- CSV

// A cell that a spreadsheet could read as a formula is made harmless by a leading apostrophe.
function cell(value) {
  let text = plain(value).replace(/\r\n|\r|\n/g, " ");
  if (/^[=+\-@\t]/.test(text)) text = "'" + text;
  return `"${text.replace(/"/g, '""')}"`;
}

const HEAD = ["session", "file", "step", "kind", "event", "result", "tone", "what_happened", "why", "where"];

function csv(included) {
  const rows = [HEAD.map(cell).join(",")];
  included.forEach((rec, i) => {
    rec.events.forEach((e, n) => {
      const s = R.describe(e);
      rows.push([i + 1, rec.name, n, rec.kind, typeOf(rec, e), s.badge, s.tone, s.title, s.why, s.where].map(cell).join(","));
    });
  });
  return "﻿" + rows.join("\r\n") + "\r\n";
}

window.HCPack = { tally, sum, packDoc, csv, cell, HEAD };
})();
