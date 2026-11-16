// The Policy Studio page. A classic script (works from file://). Everything stays in this tab: the form is checked by
// policy.js, "Try it" only changes the address (the policy rides in the #fragment, which is never sent to a server),
// and Pro's export and import read and write files on this computer.
(async function () {
"use strict";

const P = window.HCPolicy;
const L = window.HCLicense;
const $ = (id) => document.getElementById(id);
const el = (tag, attrs = {}, ...kids) => {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) { if (k === "class") node.className = v; else node.setAttribute(k, v); }
  for (const kid of kids) if (kid != null) node.append(kid instanceof Node ? kid : String(kid));
  return node;
};

const FIELDS = { budget: "polBudget", autoLimit: "polAuto", refuseOver: "polRefuse", hosts: "polHosts" };
const ERRORS = { budget: "errBudget", autoLimit: "errAuto", refuseOver: "errRefuse", hosts: "errHosts" };
let current = null; // the policy the form holds right now, or null while it has a problem

const dollars = (cents) => (cents / 100).toFixed(2).replace(/\.00$/, "");

function read() {
  return { budget: $("polBudget").value, autoLimit: $("polAuto").value, refuseOver: $("polRefuse").value, hosts: $("polHosts").value };
}

function paintPreview(policy) {
  const body = $("previewBody");
  body.textContent = "";
  for (const row of P.preview(policy)) {
    const tone = row.outcome === "ALLOW" ? "ok" : row.outcome === "DENY" ? "no" : "hold";
    body.append(el("tr", { class: tone },
      el("td", {}, row.label),
      el("td", {}, el("code", {}, row.domain)),
      el("td", {}, row.amount_cents ? P.money(row.amount_cents) : "free"),
      el("td", { class: "pl-out" }, row.outcome === "HOLD" ? "HOLD for a person" : row.outcome),
      el("td", {}, row.trigger_reason)));
  }
  const rules = $("rulesList");
  rules.textContent = "";
  for (const r of P.rules(policy)) rules.append(el("li", {}, el("code", {}, r[0]), ` — ${r[1]}: `, el("b", {}, r[2])));
}

function validate() {
  const result = P.fromForm(read());
  for (const key of Object.keys(ERRORS)) {
    const message = result.ok ? "" : (result.errors[key] || "");
    $(ERRORS[key]).textContent = message;
    $(FIELDS[key]).setAttribute("aria-invalid", message ? "true" : "false");
  }
  current = result.ok ? result.policy : null;
  $("polTry").disabled = !current;
  $("preview").hidden = !current;
  $("polNote").textContent = current ? "This policy checks out." : "Fix the fields marked above to see what this policy does.";
  if (current) paintPreview(current);
  $("polExport").disabled = !current || !proOn;
  return result;
}

let proOn = false;
async function paintPlan() {
  proOn = (await L.ready()).plan === "pro";
  $("proPol").disabled = !proOn;
  $("proPolNote").textContent = proOn
    ? "Pro is on."
    : "Export and import turn on with a valid Pro licence key.";
  $("polExport").disabled = !current || !proOn;
}

for (const id of Object.values(FIELDS)) $(id).addEventListener("input", validate);

$("polReset").addEventListener("click", () => {
  const s = P.STANDARD;
  $("polBudget").value = dollars(s.budget_cents);
  $("polAuto").value = dollars(s.auto_limit_cents);
  $("polRefuse").value = "";
  $("polHosts").value = s.allow_domains.join("\n");
  validate();
});

$("polTry").addEventListener("click", () => {
  const result = validate();
  if (!result.ok) return;
  location.href = "sandbox.html" + P.hashFor(result.policy);
});

// ------------------------------------------------------------------ Pro: export and import a policy file

$("polExport").addEventListener("click", async () => {
  if (!(await L.isPro()) || !current) return;
  const link = el("a", { href: URL.createObjectURL(new Blob([P.toFile(current)], { type: "application/json" })), download: "hashcam-sandbox-policy.json" });
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(link.href), 4000);
  $("fileNote").textContent = "Saved. This file is a sandbox policy only: the real gateway cannot read it.";
});

$("polImport").addEventListener("click", async () => {
  if (!(await L.isPro())) return;
  const file = $("polImportFile").files[0];
  const note = $("fileNote");
  if (!file) { note.textContent = "Choose a policy file first."; return; }
  if (file.size > 20000) { note.textContent = "That file is too big to be a policy."; return; }
  const result = P.fromFile(await file.text());
  if (!result.ok) { note.textContent = Object.values(result.errors)[0]; return; }
  const p = result.policy;
  $("polBudget").value = dollars(p.budget_cents);
  $("polAuto").value = dollars(p.auto_limit_cents);
  $("polRefuse").value = p.refuse_over_cents == null ? "" : dollars(p.refuse_over_cents);
  $("polHosts").value = p.allow_domains.join("\n");
  validate();
  note.textContent = "Imported. Check the fields, then try it.";
});

// A link back from the sandbox can carry the policy it was running: fill the form from it.
(function fromAddress() {
  const asked = P.fromHash(location.hash);
  if (asked.state !== "ok") return;
  const p = asked.policy;
  $("polBudget").value = dollars(p.budget_cents);
  $("polAuto").value = dollars(p.auto_limit_cents);
  $("polRefuse").value = p.refuse_over_cents == null ? "" : dollars(p.refuse_over_cents);
  $("polHosts").value = p.allow_domains.join("\n");
})();

validate();
await paintPlan();
if (window.HCMotion) window.HCMotion.init();
})();
