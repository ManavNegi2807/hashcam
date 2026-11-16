// Compare two runs of the same level: what got better, what got worse, what stayed the same. Pure: it only reads
// two scored results (each from a record that was verified first) and says exactly what changed, in words.
//
// It never calls a run "better overall": if any check got worse, the summary says so first and says nothing
// that reads as an overall improvement. Not scored (an edited or unverified record) means no comparison.
(() => {
"use strict";

const RANK = { FAIL: 0, UNKNOWN: 1, PASS: 2 };
const plural = (n, word) => `${n} ${word}${n === 1 ? "" : "s"}`;
const word = { PASS: "passed", FAIL: "failed", UNKNOWN: "could not be confirmed" };

function refusal(which, result) {
  const why = result && result.reason ? ` ${result.reason}` : "";
  return { ok: false, reason: `The ${which} run was not scored, so there is nothing to compare.${why}` };
}

// before, after: results from HCScore (scored: true, criteria: [{ label, status, evidence }], tally, overall).
function compare(before, after) {
  if (!before || !before.scored) return refusal("before", before);
  if (!after || !after.scored) return refusal("after", after);
  const a = before.criteria, b = after.criteria;
  if (a.length !== b.length || a.some((c, i) => c.label !== b[i].label)) {
    return { ok: false, reason: "These two runs were scored on different checks, so they cannot be compared. Use the same level for both." };
  }
  const rows = a.map((c, i) => {
    const was = c.status, now = b[i].status;
    const change = RANK[now] > RANK[was] ? "better" : RANK[now] < RANK[was] ? "worse" : "same";
    return { label: c.label, was, now, change, evidence: b[i].evidence, wasEvidence: c.evidence };
  });
  const counts = { better: 0, worse: 0, same: 0 };
  for (const r of rows) counts[r.change]++;
  let summary, verdict;
  if (counts.worse) {
    verdict = "worse";
    summary = `${plural(counts.worse, "check")} got worse${counts.better ? ` and ${plural(counts.better, "check")} got better` : ""}. Look at the ones marked worse first.`;
  } else if (counts.better) {
    verdict = "better";
    summary = `${plural(counts.better, "check")} got better and none got worse.`;
  } else {
    verdict = "same";
    summary = "Nothing changed: every check has the same result.";
  }
  const line = (r) => `${r.overall}, ${r.tally.pass} of ${r.tally.total} checks passed`;
  return {
    ok: true, rows, counts, verdict, summary,
    before: { overall: before.overall, line: line(before) },
    after: { overall: after.overall, line: line(after) },
  };
}

// One row in words, for the page and the report.
const rowText = (r) => r.change === "same"
  ? `Still ${word[r.now]}. ${r.evidence}`
  : `Was ${word[r.was]}, now ${word[r.now]}. ${r.evidence}`;

window.HCCompare = { compare, rowText };
})();
