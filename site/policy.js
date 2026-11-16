// The sandbox's policy: the standard rules, the rule engine, and what a custom policy may be. A classic script
// (it works from file://), shared by the Gatekeeper Sandbox and the Policy Studio so there is ONE copy of the
// rules. Everything is checked here, in the page, and nothing is sent anywhere.
//
// A custom policy is four things: a budget, the amount a person must approve above, an optional amount above
// which a step is refused outright, and the host names the agent may use. Every field is validated; bad input is
// refused with a plain message and never quietly "fixed". (Host names are lower-cased and trimmed, which does not
// change what they mean.) This is a SANDBOX policy: it is not the real gateway's policy or mandate format.
(() => {
"use strict";

const money = (cents) => "$" + (Number(cents) / 100).toFixed(2);

const STANDARD = Object.freeze({
  id: "sandbox-policy/1",
  budget_cents: 10000,
  auto_limit_cents: 1000,
  allow_domains: Object.freeze(["docs.github.com", "api.gpu-cloud.example", "tokens.example-bank.test"]),
});
const CUSTOM_ID = "custom-policy/1";

// The sandbox's four test flights (the Studio previews what a policy does to each).
const FLIGHTS = Object.freeze([
  { key: "docs", label: "Read Repo Docs", amount_cents: 0, domain: "docs.github.com" },
  { key: "webhook", label: "Sync External Webhook", amount_cents: 0, domain: "hooks.partner-sync.example" },
  { key: "gpu", label: "Provision Sandbox GPU", amount_cents: 3500, domain: "api.gpu-cloud.example" },
  { key: "bulk", label: "Bulk Token Purchase", amount_cents: 25000, domain: "tokens.example-bank.test" },
]);

// ------------------------------------------------------------------ the rules

// Pure: no clock, no randomness, no network. The first matching rule wins; a deny is final.
function decide(a, spentCents, policy) {
  const remaining = policy.budget_cents - spentCents;
  if (!policy.allow_domains.includes(a.domain)) {
    return { rule_id: "R1", rule: "DOMAIN_NOT_ALLOWED", outcome: "DENY", domain_check: "FAIL",
      trigger_reason: a.domain + " is not on the allow-list" };
  }
  if (a.amount_cents > remaining) {
    return { rule_id: "R2", rule: "OVER_BUDGET", outcome: "DENY", domain_check: "PASS",
      trigger_reason: money(a.amount_cents) + " is more than the " + money(remaining) + " left in escrow" };
  }
  if (policy.refuse_over_cents != null && a.amount_cents > policy.refuse_over_cents) {
    return { rule_id: "R6", rule: "OVER_AMOUNT_LIMIT", outcome: "DENY", domain_check: "PASS",
      trigger_reason: money(a.amount_cents) + " is more than the " + money(policy.refuse_over_cents) + " allowed for one step" };
  }
  if (a.amount_cents === 0) {
    return { rule_id: "R3", rule: "FREE_ACTION", outcome: "ALLOW", domain_check: "PASS", trigger_reason: "no money moves" };
  }
  if (a.amount_cents <= policy.auto_limit_cents) {
    return { rule_id: "R4", rule: "AUTO_SMALL_SPEND", outcome: "ALLOW", domain_check: "PASS",
      trigger_reason: money(a.amount_cents) + " is within the " + money(policy.auto_limit_cents) + " the agent may spend alone" };
  }
  return { rule_id: "R5", rule: "HUMAN_SIGNOFF_REQUIRED", outcome: "HOLD", domain_check: "PASS",
    trigger_reason: money(a.amount_cents) + " is more than the " + money(policy.auto_limit_cents) + " the agent may spend alone" };
}

// What a policy does to each test flight, spending nothing before it.
function preview(policy) {
  return FLIGHTS.map((f) => ({ ...f, ...decide(f, 0, policy) }));
}

// The policy as rows of a table (rule, when, outcome), in the order the rules are tried.
function rules(policy) {
  const rows = [
    ["R1 DOMAIN_NOT_ALLOWED", `the host is not on the allow-list (${policy.allow_domains.join(", ")})`, "DENY"],
    ["R2 OVER_BUDGET", `the amount is more than what is left of the ${money(policy.budget_cents)} cap`, "DENY"],
  ];
  if (policy.refuse_over_cents != null) {
    rows.push(["R6 OVER_AMOUNT_LIMIT", `the amount is more than ${money(policy.refuse_over_cents)} for one step`, "DENY"]);
  }
  rows.push(
    ["R3 FREE_ACTION", "no money moves", "ALLOW"],
    ["R4 AUTO_SMALL_SPEND", `the amount is ${money(policy.auto_limit_cents)} or less`, "ALLOW"],
    ["R5 HUMAN_SIGNOFF_REQUIRED", "anything else", "HOLD until a person signs"],
  );
  return rows;
}

// ------------------------------------------------------------------ checking a policy

const MONEY = /^\d{1,7}(\.\d{1,2})?$/;
const HOST = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/;
const MIN_BUDGET = 100; // $1.00
const MAX_BUDGET = 1000000; // $10,000.00
const MAX_HOSTS = 20;
const KEYS = ["id", "budget_cents", "auto_limit_cents", "refuse_over_cents", "allow_domains"];

function centsOf(text) {
  const t = String(text == null ? "" : text).trim();
  if (!MONEY.test(t)) return null;
  const [whole, frac = ""] = t.split(".");
  return Number(whole) * 100 + Number((frac + "00").slice(0, 2));
}

// Host names from a pasted list (commas, spaces or new lines between them): lower-cased and trimmed, nothing else.
function hostsOf(text) {
  return String(text == null ? "" : text).split(/[\s,;]+/).filter(Boolean).map((h) => h.toLowerCase());
}

// The rules every policy must follow, given as cents and a host list. Returns { errors } with a message per field.
function problems({ budget, auto, refuse, hosts }) {
  const errors = {};
  if (!Number.isInteger(budget)) errors.budget = "Enter the budget in dollars, such as 100 or 100.50 (at most two decimals).";
  else if (budget < MIN_BUDGET || budget > MAX_BUDGET) errors.budget = "The budget must be between $1.00 and $10,000.00.";
  if (!Number.isInteger(auto)) errors.autoLimit = "Enter the amount in dollars, such as 10 or 10.50 (at most two decimals).";
  else if (Number.isInteger(budget) && auto > budget) errors.autoLimit = "The approval limit cannot be more than the budget.";
  if (refuse !== null) {
    if (!Number.isInteger(refuse)) errors.refuseOver = "Leave this empty, or enter the amount in dollars, such as 50 or 50.25.";
    else if (Number.isInteger(auto) && refuse < auto) errors.refuseOver = "The refusal limit cannot be less than the approval limit.";
    else if (Number.isInteger(budget) && refuse > budget) errors.refuseOver = "The refusal limit cannot be more than the budget: it would never apply.";
  }
  if (!Array.isArray(hosts) || !hosts.length) errors.hosts = "Add at least one host name.";
  else if (hosts.length > MAX_HOSTS) errors.hosts = `Too many hosts: the most is ${MAX_HOSTS}.`;
  else {
    const seen = new Set();
    for (const h of hosts) {
      if (typeof h !== "string" || h.length > 253 || !HOST.test(h) || !/\.[a-z][a-z0-9-]*$/.test(h)) {
        errors.hosts = `"${String(h).slice(0, 60)}" is not a plain host name. Use names like docs.github.com: no http://, no port, no path, no spaces.`;
        break;
      }
      if (seen.has(h)) { errors.hosts = `"${h}" is listed twice.`; break; }
      seen.add(h);
    }
  }
  return errors;
}

// From the form's text boxes. { ok: true, policy } or { ok: false, errors: { budget?, autoLimit?, refuseOver?, hosts? } }.
function fromForm({ budget, autoLimit, refuseOver, hosts }) {
  const refuseText = String(refuseOver == null ? "" : refuseOver).trim();
  const parsed = {
    budget: centsOf(budget),
    auto: centsOf(autoLimit),
    refuse: refuseText === "" ? null : (centsOf(refuseText) ?? Number.NaN), // text that is not an amount is an error, never "empty"
    hosts: hostsOf(hosts),
  };
  const errors = problems(parsed);
  if (Object.keys(errors).length) return { ok: false, errors };
  return { ok: true, policy: make(parsed.budget, parsed.auto, parsed.refuse, parsed.hosts) };
}

function make(budget, auto, refuse, hosts) {
  return Object.freeze({
    id: CUSTOM_ID,
    budget_cents: budget,
    auto_limit_cents: auto,
    refuse_over_cents: refuse,
    allow_domains: Object.freeze(hosts.slice()),
  });
}

// A policy that arrived as data (a link, a file): untrusted, so every field and every key is checked.
function check(value) {
  const bad = (message) => ({ ok: false, errors: { policy: message } });
  if (!value || typeof value !== "object" || Array.isArray(value)) return bad("That is not a policy.");
  const keys = Object.keys(value);
  if (keys.some((k) => !KEYS.includes(k))) return bad("That policy has fields this sandbox does not know.");
  if (value.id !== CUSTOM_ID) return bad("That policy is not a sandbox policy this page can read.");
  const refuse = value.refuse_over_cents === undefined ? null : value.refuse_over_cents;
  const errors = problems({
    budget: value.budget_cents, auto: value.auto_limit_cents,
    refuse: refuse === null ? null : refuse, hosts: value.allow_domains,
  });
  if (Object.keys(errors).length) return { ok: false, errors };
  return { ok: true, policy: make(value.budget_cents, value.auto_limit_cents, refuse, value.allow_domains) };
}

// ------------------------------------------------------------------ carrying a policy in a link or a file

const toB64u = (text) => btoa(Array.from(new TextEncoder().encode(text), (b) => String.fromCharCode(b)).join(""))
  .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const fromB64u = (text) => new TextDecoder("utf-8", { fatal: true }).decode(
  Uint8Array.from(atob(text.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (text.length % 4)) % 4)), (c) => c.charCodeAt(0)));

const plain = (policy) => ({
  id: policy.id, budget_cents: policy.budget_cents, auto_limit_cents: policy.auto_limit_cents,
  refuse_over_cents: policy.refuse_over_cents, allow_domains: policy.allow_domains.slice(),
});

// "#policy=…" for the sandbox's address. The fragment stays in the browser: it is never sent to a server.
const hashFor = (policy) => "#policy=" + toB64u(JSON.stringify(plain(policy)));

// What the sandbox was asked to run: { state: "none" } | { state: "ok", policy } | { state: "bad", reason }.
function fromHash(hash) {
  const text = String(hash || "");
  if (!text.startsWith("#policy=")) return { state: "none" };
  const m = /^#policy=([A-Za-z0-9_-]{1,3000})$/.exec(text);
  if (!m) return { state: "bad", reason: "the link's policy is damaged" };
  let value;
  try { value = JSON.parse(fromB64u(m[1])); } catch { return { state: "bad", reason: "the link's policy could not be read" }; }
  const checked = check(value);
  if (!checked.ok) return { state: "bad", reason: Object.values(checked.errors)[0] };
  return { state: "ok", policy: checked.policy };
}

// A file a person can keep: honest about what it is.
const FILE_FORMAT = "hashcam-sandbox-policy/1";
function toFile(policy) {
  return JSON.stringify({
    format: FILE_FORMAT,
    scope: "sandbox policy only",
    note: "This is the Gatekeeper Sandbox's policy. It is not the real HashCam gateway's policy or mandate format, and the real gateway cannot read it.",
    policy: plain(policy),
  }, null, 2) + "\n";
}
function fromFile(text) {
  const bad = (message) => ({ ok: false, errors: { file: message } });
  if (typeof text !== "string" || text.length > 20000) return bad("That file is too big to be a policy.");
  let data;
  try { data = JSON.parse(text); } catch { return bad("That file could not be read as a policy."); }
  if (!data || data.format !== FILE_FORMAT) return bad("That is not a sandbox policy file made here.");
  return check(data.policy);
}

window.HCPolicy = { STANDARD, CUSTOM_ID, FLIGHTS, decide, preview, rules, fromForm, check, hashFor, fromHash, toFile, fromFile, money, centsOf, hostsOf, MAX_HOSTS };
})();
