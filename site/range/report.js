// The Range report: what a run did well, what went wrong and what to do next, as a PDF that only opens with
// a password. The PDF itself (the layout, the AES-256 lock, the random password) is lockedpdf.js, the one
// source the extension shares; this file only says what the Range's report says. Everything happens in this
// tab: nothing is uploaded, and the password is shown once and stored nowhere.
(() => {
"use strict";

const { buildLockedPdf, newPassword, hash2B } = window.HCLockedPdf; // lockedpdf.js

const toneOf = (overall) => ({ PASSED: "good", FAILED: "bad", INCOMPLETE: "warn" })[overall] || "soft";
const chipTone = { PASS: "good", FAIL: "bad", UNKNOWN: "warn" };

// ------------------------------------------------------------------ what the report says

const ADVICE = {
  FAIL: "Change your agent so this holds, then run the level again.",
  UNKNOWN: "The record cannot show this either way. Read why above, then decide whether a different run would show it.",
};

// run: { level: {n, title, goal}, result: {scored, overall, reason, criteria, tally, source}, engine, files: [{name, sha256}], at }
function blocksFor(run) {
  const { level, result } = run;
  const out = [{
    style: "verdict", overall: result.overall, tone: toneOf(result.overall), text: `The goal: ${level.goal}`,
    title: `Level ${level.n}: ${level.title}`,
    score: result.scored ? `${result.tally.pass} / ${result.tally.total}` : "", scoreNote: result.scored ? "checks passed" : "",
  }];
  if (!result.scored) {
    out.push({ style: "h", text: "What went wrong" });
    out.push({ style: "p", text: result.reason || "The record could not be scored." });
    out.push({ style: "h", text: "What to do next" });
    out.push({ style: "step", text: "Run the level again and export a fresh record. Do not open and save the record in another program before you drop it." });
    out.push({ style: "step", text: "For an extension receipt, drop the .keys.json file together with the .abbreceipt." });
    out.push({ style: "step", text: "A record that was changed after the run is never scored. That is the point of it." });
  } else {
    const by = (status) => result.criteria.filter((c) => c.status === status);
    const good = by("PASS"), bad = by("FAIL"), open = by("UNKNOWN");
    const row = (c) => ({ style: "row", chip: c.status, tone: chipTone[c.status], lead: `${c.label}.`, text: c.evidence });

    out.push({ style: "h", text: "What your agent did well" });
    if (!good.length) out.push({ style: "p", text: "Nothing passed in this run." });
    out.push(...good.map(row));

    out.push({ style: "h", text: "What went wrong" });
    if (!bad.length) out.push({ style: "p", text: "Nothing failed in this run." });
    out.push(...bad.map(row));

    if (open.length) {
      out.push({ style: "h", text: "What could not be confirmed" });
      out.push(...open.map(row));
    }

    if (run.compare) {
      const cmp = run.compare;
      out.push({ style: "h", text: "What changed since the earlier run" });
      out.push({ style: "p", text: `Before: ${cmp.before.line}. After: ${cmp.after.line}.` });
      for (const r of cmp.rows) {
        out.push({ style: "row", chip: r.change, tone: { better: "good", worse: "bad", same: "soft" }[r.change], lead: `${r.label}.`, text: window.HCCompare.rowText(r) });
      }
      out.push({ style: "p", text: cmp.summary });
    }

    out.push({ style: "h", text: "What to do next" });
    for (const c of bad) out.push({ style: "step", lead: `Fix: ${c.label}.`, text: ADVICE.FAIL });
    for (const c of open) out.push({ style: "step", lead: `Look at: ${c.label}.`, text: ADVICE.UNKNOWN });
    if (!bad.length && !open.length) {
      out.push({ style: "step", text: "This level is done. Try the next level: each one tests a different habit." });
      out.push({ style: "step", text: "Run it a second time. An agent that passes once by luck is not the same as one that passes every time." });
    } else {
      out.push({ style: "step", text: "Change one thing at a time and run the level again, so you can see what made the difference." });
    }
    out.push({ style: "step", text: "Remember what a pass means: your agent behaved on this test, in this run. It does not mean the agent is safe everywhere." });
  }

  out.push({ style: "h", text: "How this was checked" });
  if (run.engine) out.push({ style: "p", text: run.engine });
  for (const f of run.files || []) out.push({ style: "small", text: `Record: ${f.name} - SHA-256 ${f.sha256}` });
  out.push({ style: "small", text: "The fingerprint above ties this report to one record. If someone shows you this report, ask for the record and check it yourself." });

  out.push({ style: "h", text: "About the lock on this file" });
  out.push({ style: "b", text: "This PDF is locked with AES-256. It opens only with the password the page showed when it was made." });
  out.push({ style: "b", text: "The password was made by the browser's secure random source. It was shown once and is not stored anywhere." });
  out.push({ style: "b", text: "Never send the password in the same message as the file." });
  return out;
}

// With a valid Pro licence and a saved company name or logo (site/pro/brand.js) the header is the buyer's own;
// the footer still says it was made with HashCam.
async function build(run) {
  const pro = window.HCLicense && await window.HCLicense.isPro();
  const brand = pro && window.HCBrand ? window.HCBrand.forReport() : null;
  const white = Boolean(brand && brand.whiteLabel);
  const doc = {
    brand: white && brand.name ? [brand.name, ""] : ["HashCam", "Range"],
    kicker: "Agent test report",
    date: run.at,
    running: `Level ${run.level.n}: ${run.level.title}`,
    footer: white
      ? `${brand.name ? brand.name + " - " : ""}Made with HashCam. A report is a summary, not a proof. Ask for the record.`
      : "HashCam Range - a report is a summary, not a proof. Ask for the record.",
    blocks: blocksFor(run),
  };
  return buildLockedPdf(doc, white ? brand.art : window.HCReportArt);
}

window.HCReport = { build, blocksFor, newPassword, hash2B };
})();
