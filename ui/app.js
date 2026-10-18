// The audit view. It only DISPLAYS what `abb verify --json` returned.
// It never hashes, checks a signature, or works out whether a receipt is valid.
// Every piece of receipt content goes in through textContent, never as markup.
"use strict";

const STATUS = {
  PASS: { cls: "ok", label: "PASS", icon: "check" },
  FAIL: { cls: "fail", label: "FAIL", icon: "cross" },
  UNKNOWN: { cls: "unknown", label: "UNKNOWN", icon: "question" },
  NOT_INDEPENDENT: { cls: "notind", label: "NOT INDEPENDENT", icon: "split" },
  NOT_APPLICABLE: { cls: "na", label: "NOT APPLICABLE", icon: "dash" },
};

const OVERALL = {
  VALID: {
    cls: "ok", icon: "check",
    text: "Everything this profile requires checked out. That says the history has not changed since it was signed. It does not say the task was safe or correct.",
  },
  PARTIAL: {
    cls: "unknown", icon: "question",
    text: "Everything required checked out, but something optional is missing or not independent. Read the dimensions below.",
  },
  INCOMPLETE: {
    cls: "unknown", icon: "question",
    text: "Something this profile requires could not be checked. Missing evidence is not a pass.",
  },
  INVALID: {
    cls: "fail", icon: "cross",
    text: "A check failed. The findings below say which one and, where possible, which event.",
  },
  UNSUPPORTED: {
    cls: "na", icon: "dash",
    text: "This build does not understand the receipt's protocol or schema version.",
  },
  UNREADABLE: {
    cls: "fail", icon: "cross",
    text: "The file could not be read as a receipt.",
  },
};

const DIMENSION_LABEL = {
  evidence_integrity: "Evidence integrity",
  checkpoint_signatures: "Checkpoint signatures",
  consistency: "Consistency between checkpoints",
  global_log_inclusion: "Global log inclusion",
  artifact_manifest_integrity: "Artifact manifest integrity",
  artifact_availability: "Artifact availability",
  witness_quorum: "Witness quorum",
  anchor_match: "Anchor match",
  observation_coverage: "Observation coverage",
  policy_assessment: "Policy assessment",
  mandate_compliance: "Mandate compliance",
  semantic_assessment: "Semantic assessment",
  prompt_security_assessment: "Prompt-security assessment",
  behavior_anomaly_assessment: "Behavior anomaly assessment",
  ml_assessment: "ML assessment (aggregate)",
  execution_outcome: "Execution outcome (the run's own claim)",
};

// The five channels of R-UI-02, shown separately. Grouping only; no logic.
const CHANNELS = [
  ["policy_assessment", "Policy", "Deterministic allow, deny and approval decisions. The only channel that can block."],
  ["semantic_assessment", "Semantic", "Hand-written invariants over the events. Advisory."],
  ["prompt_security_assessment", "Prompt security", "Deterministic injection checks on text the agent read. Advisory; not a complete defence."],
  ["behavior_anomaly_assessment", "Behavior anomaly", "Rules over run behavior. Advisory; a signal, not proof of malice."],
  ["evidence_integrity", "Evidence integrity", "Whether the recorded events still match the signed tree."],
];

const COUNTS_AS = {
  required: "Required for this profile",
  optional: "Optional",
  informational: "Shown, never changes the result",
};

const SVG_NS = "http://www.w3.org/2000/svg";
const ICON_PATHS = {
  check: "M4 12.5l5 5L20 6.5",
  cross: "M6 6l12 12M18 6L6 18",
  question: "M9.5 9a2.5 2.5 0 1 1 3.5 2.3c-.7.4-1 .9-1 1.7M12 17.5v.01",
  split: "M7 7a4 4 0 1 0 0 8M17 9a4 4 0 1 1 0 8M10 11h4",
  dash: "M6 12h12",
};

function icon(name) {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "2.5");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  const path = document.createElementNS(SVG_NS, "path");
  path.setAttribute("d", ICON_PATHS[name]);
  svg.appendChild(path);
  return svg;
}

function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) {
    if (key === "class") node.className = value;
    else node.setAttribute(key, value);
  }
  for (const child of children) {
    if (child === null || child === undefined) continue;
    node.appendChild(typeof child === "string" ? document.createTextNode(child) : child);
  }
  return node;
}

function chip(status) {
  const known = STATUS[status] || { cls: "unknown", label: String(status), icon: "question" };
  // An unrecognized status is shown as unknown, never as a pass.
  return el("span", { class: "chip " + known.cls }, icon(known.icon), known.label);
}

const $ = (id) => document.getElementById(id);
const say = (message) => { $("status").textContent = message; };

function show(id, visible) { $(id).hidden = !visible; }

function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

// ----------------------------------------------------------------- rendering

function renderOverall(report, origin) {
  const body = $("overall-body");
  clear(body);
  const info = OVERALL[report.overall] || { cls: "unknown", icon: "question", text: "Unrecognized result." };
  const banner = el("div", { class: "banner " + info.cls },
    el("div", { class: "big" }, icon(info.icon), String(report.overall)),
    el("p", {}, info.text));
  if (report.run_id) banner.appendChild(el("p", { class: "mono" }, "Run " + report.run_id));
  const meta = [];
  if (report.profile) meta.push("profile " + report.profile);
  if (report.declared_coverage) meta.push("declared coverage " + report.declared_coverage);
  if (meta.length) banner.appendChild(el("p", {}, meta.join(" · ")));
  if (report.keys_supplied === false) {
    banner.appendChild(el("p", {}, "No key manifest was given, so signatures could not be judged. Those dimensions are unknown, not passed."));
  }
  if (report.message) banner.appendChild(el("p", {}, report.message));
  if (origin) banner.appendChild(el("p", { class: "muted" }, origin));
  body.appendChild(banner);
  show("overall", true);
}

function renderChannels(report) {
  const body = $("channels-body");
  clear(body);
  const dims = report.dimensions || {};
  const details = report.details || [];
  for (const [key, title, blurb] of CHANNELS) {
    const card = el("div", { class: "card" },
      el("h3", {}, title),
      el("p", {}, chip(dims[key] || "UNKNOWN")),
      el("p", { class: "muted" }, blurb));
    for (const d of details.filter((x) => x.dimension === key).slice(0, 2)) {
      card.appendChild(el("p", {}, d.message));
    }
    body.appendChild(card);
  }
  show("channels", true);
}

function renderDimensions(report) {
  const tbody = $("dims-table").querySelector("tbody");
  clear(tbody);
  const order = { required: 0, optional: 1, informational: 2 };
  const reqs = report.requirements || {};
  const names = Object.keys(report.dimensions || {});
  names.sort((a, b) => (order[reqs[a]] ?? 3) - (order[reqs[b]] ?? 3) || a.localeCompare(b));
  for (const name of names) {
    tbody.appendChild(el("tr", {},
      el("th", { scope: "row" }, DIMENSION_LABEL[name] || name),
      el("td", {}, chip(report.dimensions[name])),
      el("td", {}, COUNTS_AS[reqs[name]] || "Not stated in this report")));
  }
  show("dimensions", true);
}

function renderFindings(report) {
  const list = $("findings-list");
  clear(list);
  const details = report.details || [];
  for (const d of details) {
    const status = (report.dimensions || {})[d.dimension];
    const known = STATUS[status] || STATUS.UNKNOWN;
    const item = el("li", {},
      el("div", {}, chip(status || "UNKNOWN"), " ", el("strong", {}, DIMENSION_LABEL[d.dimension] || d.dimension)),
      el("div", {}, d.message));
    item.className = "finding " + known.cls;
    if (d.locator) item.appendChild(el("div", { class: "where mono" }, d.locator));
    list.appendChild(item);
  }
  show("findings", details.length > 0);
}

function kv(pairs) {
  const dl = el("dl", {});
  for (const [k, v] of pairs) {
    if (v === null || v === undefined || v === "") continue;
    dl.appendChild(el("dt", {}, k));
    dl.appendChild(el("dd", { class: "mono" }, String(v)));
  }
  return dl;
}

function renderRun(summary, report) {
  const body = $("run-body");
  clear(body);
  const run = summary.run || {};
  const policy = summary.policy || {};
  body.appendChild(el("div", { class: "card" }, el("h3", {}, "Run"), kv([
    ["Run id", run.run_id], ["Adapter", run.adapter_name + " " + (run.adapter_version || "")],
    ["Declared coverage", run.declared_coverage], ["Observed coverage", run.observed_coverage],
    ["Profile", run.profile], ["Events", summary.events_total], ["Checkpoints", summary.checkpoints],
  ])));
  body.appendChild(el("div", { class: "card" }, el("h3", {}, "Policy"), kv([
    ["Policy", policy.policy_id], ["Version", policy.policy_version], ["Digest", policy.body_digest],
  ])));

  const approvalCard = el("div", { class: "card" }, el("h3", {}, "Human approvals"));
  if (!summary.approvals.length) {
    approvalCard.appendChild(el("p", {}, "No signed approval in this receipt."));
  }
  for (const a of summary.approvals) {
    approvalCard.appendChild(el("p", {}, chip(a.decision === "GRANTED" ? "PASS" : "NOT_APPLICABLE"), " ",
      a.decision + " for " + a.action_id));
    approvalCard.appendChild(kv([["Approval", a.approval_id], ["Signed by key", a.key_id], ["Expires at (claim)", a.expires_at]]));
  }
  approvalCard.appendChild(el("p", { class: "muted" },
    "The verifier's policy result is " + ((report.dimensions || {}).policy_assessment || "UNKNOWN") +
    ". A valid signature shows that a key signed, not which person held it. Approving happens on the approver's own device with abb approve; this page cannot sign."));
  body.appendChild(approvalCard);

  if (summary.mandate) {
    const m = summary.mandate;
    body.appendChild(el("div", { class: "card" }, el("h3", {}, "Signed mandate"), kv([
      ["Mandate", m.mandate_id], ["Subject", m.subject], ["Hosts", (m.allowed_hosts || []).join(", ")],
      ["Action types", (m.allowed_action_types || []).join(", ")], ["Max actions", m.max_actions],
      ["Spend limit", m.max_spend_minor_units === undefined ? "" : m.max_spend_minor_units + " " + (m.currency || "")],
      ["Compliance", (report.dimensions || {}).mandate_compliance || "UNKNOWN"],
    ])));
  }

  const g = summary.global_log || {};
  body.appendChild(el("div", { class: "card" }, el("h3", {}, "Global log, witnesses, anchors"), kv([
    ["Position", g.position], ["Global tree size", g.tree_size], ["Global checkpoints", g.checkpoints],
    ["Witness signatures", summary.witnesses], ["Anchors", summary.anchors],
    ["Witness quorum", (report.dimensions || {}).witness_quorum || "UNKNOWN"],
    ["Anchor match", (report.dimensions || {}).anchor_match || "UNKNOWN"],
  ])));
  show("run", true);
}

function preview(payload) {
  const text = JSON.stringify(payload);
  return text.length > 220 ? text.slice(0, 220) + "…" : text;
}

const SOURCE_WORDS = {
  reported_by_adapter: "The adapter's own report",
  observed_by_local_gateway: "Seen by this computer's gateway",
  verified_by_black_box: "Recorded by the black box",
};

const str = (value) => (typeof value === "string" ? value : "");

// One plain sentence per event. Display only: the raw event is always one click away.
function sentence(e) {
  const p = e.payload || {};
  switch (e.event_type) {
    case "RUN_STARTED": return "The run started" + (p.adapter ? " with the " + str(p.adapter) + " adapter" : "") + ".";
    case "COVERAGE_DECLARED": return "It declared how much could be observed: " + str(p.declared_coverage) + ". " + str(p.reason);
    case "ACTION_REQUESTED": return "The agent asked to do a " + str(p.action_type).replace(/_/g, " ") + (p.target ? " at " + str(p.target) : "") + ".";
    case "ACTION_AUTHORIZED": return "The policy said " + str(p.decision) + (p.policy_id ? " (" + str(p.policy_id) + " v" + str(p.policy_version) + ")" : "") +
      (Array.isArray(p.reason_codes) && p.reason_codes.length ? ": " + p.reason_codes.join(", ") : "") + ".";
    case "ACTION_BLOCKED": return "The policy blocked it" + (Array.isArray(p.reason_codes) && p.reason_codes.length ? ": " + p.reason_codes.join(", ") : "") + ".";
    case "ACTION_DISPATCHED": return "The request was sent.";
    case "ACTION_SUCCEEDED": return "The action reported success.";
    case "ACTION_FAILED": return "The action failed" + (p.error_code ? ": " + str(p.error_code) : "") + ".";
    case "OUTCOME_UNKNOWN": return "The outcome is unknown. " + str(p.reason);
    case "API_CALL_OBSERVED": {
      const u = p.usage || {};
      return "A call to " + str(p.host || "the provider") + " was recorded" +
        (typeof u.cents === "number" ? ", costing " + u.cents + " cent(s)" : "") +
        (typeof u.steps_billed === "number" ? " for " + u.steps_billed + " step(s)" : "") + ".";
    }
    case "BROWSER_OBSERVATION": return "The provider reported: " + str(p.text).slice(0, 160);
    case "RUN_FINISHED": return "The run ended as " + str(p.outcome) + ".";
    default: return e.event_type.toLowerCase().replace(/_/g, " ") + ".";
  }
}

function renderEvents(summary) {
  const tbody = $("events-table").querySelector("tbody");
  clear(tbody);
  for (const e of summary.events) {
    const raw = preview(e.payload) + (e.commitments.length ? "  [committed, hidden: " + e.commitments.join(", ") + "]" : "");
    tbody.appendChild(el("tr", {},
      el("td", {}, String(e.sequence)),
      el("td", {},
        el("p", { class: "what" }, sentence(e)),
        el("details", { class: "raw" }, el("summary", {}, e.event_type), el("p", { class: "mono" }, raw))),
      el("td", { class: "src" }, SOURCE_WORDS[e.source] || e.source || "")));
  }
  const shown = summary.events.length;
  $("events-note").textContent = shown < summary.events_total
    ? "Showing the first " + shown + " of " + summary.events_total + " events."
    : summary.events_total + " events. Hidden fields are committed to, not stored in the ledger.";
  show("events", true);
}

function renderAll(report, summary, origin) {
  renderOverall(report, origin);
  renderChannels(report);
  renderDimensions(report);
  renderFindings(report);
  if (summary) { renderRun(summary, report); renderEvents(summary); }
  else { show("run", false); show("events", false); show("graph", false); show("alerts", false); }
  // The result eases in first, then the cards one after another.
  fx.enter($("overall-body").firstChild);
  fx.stagger(document.querySelectorAll("#channels-body .card, #run-body .card"), 0.05);
  // Smooth scrolling and scroll-in effects for the sections that are showing now.
  fx.smooth();
  fx.reveal(document.querySelectorAll("main > section:not([hidden])"));
}

// ------------------------------------------------------------------ loading

async function getJson(url) {
  const response = await fetch(url, { headers: { Accept: "application/json" } });
  if (!response.ok) throw new Error("The server could not read that receipt.");
  return response.json();
}

// The sidebar list: the same runs as the dropdown, named by topic, newest first.
// Choosing one fills the dropdown and verifies it, so the dropdown stays the single source.
function renderPast(names, labels) {
  const list = $("past");
  clear(list);
  for (const name of names) {
    const label = labels[name] || {};
    const date = label.when ? new Date(label.when * 1000).toLocaleString(undefined, { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" }) : "";
    const here = $("receipt").value === name;
    const link = el("a", { href: "/?receipt=" + encodeURIComponent(name), title: label.title || "Earlier run", ...(here ? { "aria-current": "page" } : {}) },
      el("span", { class: "t" }, label.title || "Earlier run"), el("span", { class: "d" }, date));
    link.addEventListener("click", (event) => {
      event.preventDefault();
      $("receipt").value = name;
      verifySelected(new Event("submit")).then(() => $("events").scrollIntoView());
    });
    list.appendChild(el("li", {}, link));
  }
  if (!names.length) list.appendChild(el("li", { class: "none" }, "No runs yet"));
}

// A name people can read: the task title the run console saved, else "Run", then the date.
function readableName(name, label) {
  const when = label && label.when ? new Date(label.when * 1000) : null;
  const date = when ? when.toLocaleString(undefined, { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" }) : "";
  const title = label && label.title ? label.title : "Earlier run";
  if (!label || (!label.title && !when)) return "Earlier run";
  return date ? title + " · " + date : title;
}

let LABELS = {};

// The answer the run console saved beside the receipt, if any. Display only; not evidence.
function renderAnswer(name) {
  const text = (LABELS[name] || {}).answer;
  const holder = $("answer-text");
  clear(holder);
  if (text) holder.appendChild(renderRich(text));
  show("answer", Boolean(text));
}

async function loadList() {
  try {
    const { receipts, labels = {} } = await getJson("/api/receipts");
    LABELS = labels;
    const select = $("receipt");
    clear(select);
    // Newest first. The option's value stays the file name; only the text people read changes.
    const byDate = receipts.slice().sort((a, b) => ((labels[b] || {}).when || 0) - ((labels[a] || {}).when || 0));
    for (const name of byDate) select.appendChild(el("option", { value: name }, readableName(name, labels[name])));
    renderPast(byDate, labels);
    say(receipts.length ? receipts.length + " receipt(s) available. Choose one and press Verify." : "No receipts found in the served folder.");
    $("verify").disabled = receipts.length === 0;
  } catch (error) {
    say("Could not list receipts: this page needs the local server (tools/ui_server.py). You can still open a saved report.");
    $("verify").disabled = true;
  }
}

async function verifySelected(event) {
  event.preventDefault();
  const name = $("receipt").value;
  if (!name) return;
  $("verify").disabled = true;
  say("Running the offline verifier on " + name + " …");
  try {
    const query = "?name=" + encodeURIComponent(name);
    const [report, summary] = await Promise.all([getJson("/api/verify" + query), getJson("/api/receipt" + query)]);
    renderAll(report, summary, "Verified just now by abb verify.");
    renderAnswer(name);
    graphView.show(name);
    alertView.show(name);
    say("Done.");
    $("main").focus();
  } catch (error) {
    say(error.message);
  } finally {
    $("verify").disabled = false;
  }
}

function openReport(event) {
  const file = event.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    try {
      const report = JSON.parse(String(reader.result));
      if (typeof report !== "object" || report === null || typeof report.overall !== "string" || typeof report.dimensions !== "object") {
        throw new Error("not a verifier report");
      }
      renderAll(report, null, "From a saved report. This page has not re-verified anything.");
      say("Opened " + file.name + ".");
      $("main").focus();
    } catch (error) {
      say("That file is not a verifier report (abb verify --json).");
    }
  };
  reader.readAsText(file);
}

// A link to the task page, shown only when the server was started with --enable-runs.
async function showRunLink() {
  try {
    const response = await fetch("/api/run/info", { headers: { Accept: "application/json" } });
    if (response.ok) { $("run-link").hidden = false; $("run-link2").hidden = false; }
  } catch (error) {
    /* read-only server: no link */
  }
}

// /?receipt=<name> opens and verifies that receipt (used by the task page).
async function openFromQuery() {
  const name = new URLSearchParams(location.search).get("receipt");
  if (!name) return;
  await loadList();
  $("receipt").value = name;
  await verifySelected(new Event("submit"));
  // Straight to the log: what happened, in order.
  $("events").scrollIntoView();
}

$("controls").addEventListener("submit", verifySelected);
$("report-file").addEventListener("change", openReport);
loadList();
showRunLink();
openFromQuery();
// Smooth scrolling and scroll-in effects for what is already on the page (the limits notice).
fx.smooth();
fx.reveal(document.querySelectorAll("main > section:not([hidden])"));
// Logos, icons, title letters, card glow and button lean (decoration only).
fx.flair();
