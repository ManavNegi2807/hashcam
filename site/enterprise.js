// The company console. A classic script (works from file://). Everything stays in this tab: the access keys are checked
// here (pro/org.js), records are verified here (pro/records.js, pro/insights.js), and what the company's people write is
// kept in THIS browser under the company's own prefix. There is no server, so none of it is enforced.
(async function () {
"use strict";

const O = window.HCOrg;
const I = window.HCInsights;
const P = window.HCPolicy;
const $ = (id) => document.getElementById(id);
const el = (tag, attrs = {}, ...kids) => {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) { if (k === "class") node.className = v; else node.setAttribute(k, v); }
  for (const kid of kids) if (kid != null) node.append(kid instanceof Node ? kid : String(kid));
  return node;
};
const today = () => new Date().toISOString().slice(0, 10);
const clip = (s, n) => String(s == null ? "" : s).replace(/[\u0000-\u001f\u007f]/g, " ").trim().slice(0, n);

let session = null;
let store = null;

const can = (scope) => O.has(session, scope);
const isBoss = () => Boolean(session && session.ok && session.member.role === "boss");

// ---------------------------------------------------------------- the badge and what each role may touch
function paintShell() {
  const on = Boolean(session && session.ok);
  $("signin").hidden = on;
  $("work").hidden = !on;
  $("entNav").hidden = !on;
  $("orgCard").hidden = !on;
  const badge = $("entBadge");
  if (!on) { badge.textContent = "NOT SIGNED IN"; badge.setAttribute("data-role", "none"); return; }
  const role = session.member.role;
  badge.textContent = `ORG: ${session.org.org_name} • ROLE: ${role === "boss" ? "BOSS (ADMIN)" : "MEMBER (MAINTAINER)"}`;
  badge.setAttribute("data-role", role);
  $("orgName").textContent = session.org.org_name;
  $("whoName").textContent = `${session.member.name} (${session.member.member_id})`;
  // a fieldset that is [disabled] locks every control inside it; the note says why
  const lock = [["fsMembers", "members", "lockMembers"], ["fsPolicy", "policy", "lockPolicy"], ["fsImport", "verify", null]];
  for (const [fs, scope, note] of lock) {
    $(fs).disabled = !can(scope);
    if (note) $(note).hidden = can(scope);
  }
  $("lockHold").hidden = can("approve");
  $("lockInsights").hidden = can("insights");
  document.body.setAttribute("data-role", role);
}

// ---------------------------------------------------------------- sign in
async function signIn() {
  $("signinMsg").textContent = "Checking…";
  const result = await O.signIn($("accessKey").value);
  if (!result.ok) { $("signinMsg").textContent = result.reason; return; }
  $("accessKey").value = "";
  $("signinMsg").textContent = "";
  await start(result);
}

async function start(result) {
  session = result;
  store = O.storeFor(session.org.org_id);
  // note this person in the company's roster (so a Boss can assign issues to them)
  const roster = store.get("roster", []);
  if (!roster.some((m) => m.member_id === session.member.member_id)) {
    roster.push({ member_id: session.member.member_id, name: session.member.name, role: session.member.role });
    store.set("roster", roster);
  }
  paintShell();
  paintAll();
}

// ---------------------------------------------------------------- customer issues: verify first
async function checkFiles() {
  const files = $("bundleFiles").files;
  if (!files || !files.length) { $("bundleMsg").textContent = "Choose some files first."; return; }
  $("bundleMsg").textContent = "Checking…";
  const items = await I.analyze(files);
  const known = store.get("analysis", {});
  const issues = store.get("issues", []);
  for (const item of items) {
    known[item.name] = { name: item.name, status: item.status, category: item.category, reason: clip(item.reason, 300), note: item.note };
    if (item.status === "VERIFIED" && !issues.some((i) => i.id === item.name)) {
      issues.push({ id: item.name, title: item.note || item.name, category: item.category, assignee: null, status: "open", notes: [] });
    }
  }
  store.set("analysis", known);
  store.set("issues", issues);
  const s = I.summarize(items);
  $("bundleMsg").textContent = `${s.verified} verified, ${s.notIncluded} not included.`;
  paintAll();
}

function paintBundles() {
  const list = $("bundleList");
  list.textContent = "";
  for (const item of Object.values(store.get("analysis", {}))) {
    const ok = item.status === "VERIFIED";
    list.append(el("li", { class: ok ? "ok" : "no" },
      el("b", { class: ok ? "st-ok" : "st-no" }, item.status), " ", el("span", { class: "ent-cat" }, item.category), " ", item.name,
      el("span", { class: "muted small" }, " · " + item.reason)));
  }
}

// ---------------------------------------------------------------- issues: assigned to me, or all (Boss)
function paintIssues() {
  const issues = store.get("issues", []);
  const roster = store.get("roster", []);
  const mine = isBoss() ? issues : issues.filter((i) => i.assignee === session.member.member_id);
  const list = $("issueList");
  list.textContent = "";
  if (!mine.length) list.append(el("li", { class: "muted" }, isBoss() ? "No issues yet. Check some customer files above." : "Nothing is assigned to you yet."));
  for (const issue of mine) {
    const li = el("li", { class: "ent-issue", "data-id": issue.id });
    li.append(el("div", { class: "ent-issue-head" }, el("b", {}, issue.title), " ", el("span", { class: "ent-cat" }, issue.category), " ", el("span", { class: "tag " + issue.status }, issue.status.toUpperCase())));
    if (can("members")) {
      const sel = el("select", { class: "ent-input", "aria-label": "Assign to" }, el("option", { value: "" }, "Unassigned"));
      for (const m of roster) sel.append(el("option", { value: m.member_id }, `${m.name} (${m.role})`));
      sel.value = issue.assignee || "";
      sel.addEventListener("change", () => update(issue.id, (i) => { i.assignee = sel.value || null; }));
      li.append(el("label", { class: "ent-field" }, "Assigned to", sel));
    } else {
      li.append(el("p", { class: "muted small" }, "Assigned to you."));
    }
    for (const n of issue.notes) li.append(el("p", { class: "ent-note" }, el("b", {}, n.by), ` · ${n.at}: ${n.text}`));
    if (can("notes")) {
      const box = el("input", { class: "ent-input", type: "text", maxlength: "300", placeholder: "Diagnostic note", "aria-label": "Diagnostic note" });
      const save = el("button", { class: "btn small", type: "button" }, "Save note");
      save.addEventListener("click", () => { const t = clip(box.value, 300); if (t) update(issue.id, (i) => { i.notes.push({ by: session.member.name, at: today(), text: t }); }); });
      li.append(el("div", { class: "ent-row" }, box, save));
    }
    const actions = el("div", { class: "ent-row" });
    if (can("reproduce")) actions.append(el("a", { class: "btn small ghost", href: "sandbox.html" }, "Reproduce in the sandbox"));
    if (can("triage") && issue.status === "open") {
      const esc = el("button", { class: "btn small", type: "button" }, "Escalate to a Boss (POLICY_HOLD)");
      esc.addEventListener("click", () => update(issue.id, (i) => { i.status = "escalated"; }));
      actions.append(esc);
    }
    li.append(actions);
    list.append(li);
  }
}

function update(id, change) {
  const issues = store.get("issues", []);
  const issue = issues.find((i) => i.id === id);
  if (issue) { change(issue); store.set("issues", issues); }
  paintAll();
}

// ---------------------------------------------------------------- members and keys (Boss)
function paintRoster() {
  const list = $("rosterList");
  list.textContent = "";
  const revoked = store.get("revoked-ids", []);
  for (const m of store.get("roster", [])) {
    const isRevoked = revoked.includes(m.member_id);
    const li = el("li", { class: isRevoked ? "no" : "ok", "data-member": m.member_id },
      el("b", {}, m.name), ` · ${m.role} · `, el("code", {}, m.member_id), " ", el("span", { class: "tag " + (isRevoked ? "revoked" : "built") }, isRevoked ? "REVOKED" : "ACTIVE"));
    const btn = el("button", { class: "btn small ghost", type: "button" }, "Prepare revoke command");
    btn.addEventListener("click", () => {
      const ids = store.get("revoked-ids", []);
      if (!ids.includes(m.member_id)) { ids.push(m.member_id); store.set("revoked-ids", ids); }
      showCmd(`python tools/make_license.py revoke --org-id ${session.org.org_id} --member-id ${m.member_id}`);
      paintRoster();
    });
    li.append(btn);
    list.append(li);
  }
}
function showCmd(text) { const out = $("cmdOut"); out.hidden = false; out.textContent = text; }

function prepareCommand() {
  const name = clip($("memName").value, 80);
  if (!name) { showCmd("Type the person's name first."); return; }
  const role = $("memRole").value === "boss" ? "boss" : "member";
  showCmd(`python tools/make_license.py member --org-id ${session.org.org_id} --role ${role} --name "${name.replace(/["\\$`]/g, "")}"`);
}

async function importRevocations() {
  const result = await O.importRevocations(session, $("revText").value);
  $("revMsg").textContent = result.ok ? `Imported: ${result.revoked.length} revoked key(s).` : result.reason;
  if (result.ok) { store.set("revoked-ids", result.revoked); paintRoster(); }
}

// ---------------------------------------------------------------- policy defaults (Boss writes, everyone reads)
function paintPolicy() {
  const saved = store.get("policy", null);
  if (saved) { $("polBudget").value = saved.budget; $("polAuto").value = saved.autoLimit; $("polRefuse").value = saved.refuseOver; $("polHosts").value = saved.hosts; }
  const r = P.fromForm(readPolicy());
  $("polTry").setAttribute("href", "sandbox.html" + (r.ok && saved ? P.hashFor(r.policy) : ""));
}
const readPolicy = () => ({ budget: $("polBudget").value, autoLimit: $("polAuto").value, refuseOver: $("polRefuse").value, hosts: $("polHosts").value });
function savePolicy() {
  if (!can("policy")) return;
  const r = P.fromForm(readPolicy());
  if (!r.ok) { $("polMsg").textContent = Object.values(r.errors)[0]; return; }
  store.set("policy", readPolicy());
  $("polMsg").textContent = "Saved as this company's default.";
  paintPolicy();
}

// ---------------------------------------------------------------- escalated holds (Boss decides)
function paintHolds() {
  const list = $("holdList");
  list.textContent = "";
  const held = store.get("issues", []).filter((i) => ["escalated", "approved", "rejected"].includes(i.status));
  if (!held.length) list.append(el("li", { class: "muted" }, "No escalated holds."));
  for (const issue of held) {
    const li = el("li", { class: "ent-issue", "data-id": issue.id }, el("b", {}, issue.title), " ", el("span", { class: "tag " + issue.status }, issue.status.toUpperCase()));
    if (issue.decided) li.append(el("span", { class: "muted small" }, ` · ${issue.decided}`));
    if (issue.status === "escalated") {
      for (const [label, status] of [["Approve", "approved"], ["Reject", "rejected"]]) {
        const b = el("button", { class: "btn small" + (status === "rejected" ? " ghost" : ""), type: "button" }, label);
        if (!can("approve")) b.setAttribute("disabled", "");
        b.addEventListener("click", () => { if (can("approve")) update(issue.id, (i) => { i.status = status; i.decided = `${status} by ${session.member.name} on ${today()}`; }); });
        li.append(" ", b);
      }
    }
    list.append(li);
  }
}

// ---------------------------------------------------------------- insights (Boss)
function paintInsights() {
  const body = $("insightsBody");
  body.textContent = "";
  if (!can("insights")) return;
  const items = Object.values(store.get("analysis", {}));
  const s = I.summarize(items);
  if (!items.length) { body.append(el("p", { class: "muted" }, "No customer files have been checked yet.")); return; }
  const table = el("table", { class: "ent-table" }, el("thead", {}, el("tr", {}, ...["Category", "Verified", "NOT INCLUDED"].map((h) => el("th", { scope: "col" }, h)))));
  const tbody = el("tbody");
  for (const r of s.rows) tbody.append(el("tr", { "data-cat": r.category }, el("th", { scope: "row" }, r.category), el("td", { class: "n-ok" }, String(r.verified)), el("td", { class: "n-no" }, String(r.notIncluded))));
  table.append(tbody);
  body.append(table);
  const rank = el("ol", { class: "ent-rank", "aria-label": "Top recurring bottlenecks" });
  for (const r of s.ranking) rank.append(el("li", { "data-cat": r.category }, el("b", {}, `${r.category} (${r.count})`), el("span", { class: "muted" }, " " + r.next)));
  body.append(el("h3", {}, "Top recurring bottlenecks and the next fix"), s.ranking.length ? rank : el("p", { class: "muted" }, "Nothing verified yet, so nothing is ranked."));
}

function paintAll() { paintBundles(); paintIssues(); paintRoster(); paintPolicy(); paintHolds(); paintInsights(); }

// ---------------------------------------------------------------- go
$("signInBtn").addEventListener("click", signIn);
$("signOut").addEventListener("click", () => { O.signOut(); session = null; store = null; paintShell(); });
$("bundleGo").addEventListener("click", checkFiles);
$("memCmd").addEventListener("click", prepareCommand);
$("revGo").addEventListener("click", importRevocations);
$("polSave").addEventListener("click", savePolicy);

const first = await O.current();
if (first.ok) await start(first);
else { paintShell(); if (first.reason) $("signinMsg").textContent = first.reason; }
if (window.HCMotion) window.HCMotion.init();
})();
