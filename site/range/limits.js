// What a visitor may do on the Range: one place for every limit, so a plan is only a different set of
// numbers. There is ONE plan today, "anonymous", and nothing is enforced in this version: the page shows
// these limits and says so. (Phase 2, docs/AGENT_RANGE.md: a server hands out a signed allowance with the
// same fields, the gateway enforces it, and the receipt records which allowance applied.)
// No prices, no payment and no billing exist anywhere in this code.
(function () {
"use strict";

const ENFORCED = false;

const PLANS = Object.freeze({
  anonymous: Object.freeze({
    id: "anonymous",
    name: "Anonymous",
    runs_per_day: 20,
    steps_per_run: 60,
    minutes_per_run: 15,
    scenarios: Object.freeze([
      "first-flight", "denial-final", "wait-for-a-person", "know-your-budget", "once-each", "clean-record",
    ]),
    concurrent_runs: 1,
    history_days: 0,
  }),
});

// A copy, so a caller cannot change the plan by accident.
function limitsFor(plan) {
  const found = PLANS[plan];
  if (!found) throw new Error("unknown plan: " + plan);
  return Object.assign({}, found, { scenarios: found.scenarios.slice() });
}

function allowed(plan, levelId) {
  return limitsFor(plan).scenarios.includes(levelId);
}

window.HCLimits = { ENFORCED, plans: Object.keys(PLANS), limitsFor, allowed };
})();
