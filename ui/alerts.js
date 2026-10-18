// The alert view, inside the audit page. It lists the alerts found in one receipt: how serious, why
// (each rule that fired, in words), what the web said about a link (TinyFish's own claim), and
// whether an analyst signed before an account was isolated. Everything shown was read out of the
// signed receipt by the server; this page scores nothing and decides nothing. It never says a
// person did wrong: an alert is a signal for review.
"use strict";

const alertView = (() => {
  const SEVERITY = { HIGH: "fail", MEDIUM: "unknown", REVIEW: "notind", LOW: "na" };
  const KIND = {
    url_click: "Clicked link", file_download: "File download", process_launch: "Program started",
    record_query: "Record queries",
  };
  const EVIDENCE = {
    DONE: ["ok", "TinyFish answered"], NOT_RUN: ["unknown", "Not asked (no TinyFish key)"],
    NOT_ASKED: ["na", "No link to ask about"], UNKNOWN: ["unknown", "No clear answer"],
    FAILED: ["fail", "Failed"], BLOCKED: ["fail", "Blocked"], WAITING: ["unknown", "Waiting"],
  };
  const ACCOUNT = {
    NOT_PROPOSED: ["na", "No account action proposed"],
    WAITING_FOR_APPROVAL: ["unknown", "Waiting for an analyst's signature"],
    APPROVED: ["ok", "Approved"], DENIED: ["fail", "Denied by the analyst: nothing was done"],
    ISOLATED_SIMULATED: ["ok", "Approved; isolation SIMULATED (no real account changed)"],
  };

  const el = (tag, attrs = {}, ...kids) => {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
    for (const kid of kids) if (kid !== null && kid !== undefined) node.append(kid);
    return node;
  };
  const chip = (kind, text) => el("span", { class: "chip " + kind }, text);

  // The learned model's opinion: a second, advisory view. Its reasons come from how far each fact
  // was from ordinary; it was trained on made-up data, so it is a signal and never a verdict.
  function modelBox(model) {
    if (!model) return null;
    return el("div", { class: "modelbox" },
      el("h4", {}, "Learned model (advisory)"),
      el("p", { class: "muted" }, "Isolation Forest score " + model.score_ppm.toLocaleString("en-US") + " against a threshold of " +
        model.threshold_ppm.toLocaleString("en-US") + ". Trained on synthetic ordinary events; a signal, not proof."),
      el("ul", { class: "signals" }, ...model.reasons.map((r) => el("li", {}, "Far from ordinary: " + r.text))));
  }

  function card(alert) {
    const report = (alert.subject && alert.subject.report) || {};
    const kind = KIND[alert.subject && alert.subject.kind] || "Event";
    const who = report.user ? report.user + (Number.isInteger(report.hour) ? " at " + String(report.hour).padStart(2, "0") + ":00" : "") : "";
    const shownScore = alert.score_ppm || (alert.model ? alert.model.score_ppm : 0);
    const pct = Math.round(shownScore / 10000);
    const bar = el("div", { class: "alertbar", role: "img", "aria-label": "Rule score " + pct + " percent of the maximum" });
    const fill = el("div", { class: "alertfill " + (SEVERITY[alert.severity] || "na") });
    fill.style.width = Math.max(2, pct) + "%";
    bar.append(fill);
    const signals = el("ul", { class: "signals" }, ...alert.signals.map((s) =>
      el("li", {}, el("strong", {}, s.rule_id.replace(/_/g, " ").toLowerCase()), " (+" + Math.round(s.weight_ppm / 10000) + ") ", s.text)));
    const part = (label, p) => {
      const e = EVIDENCE[p.status] || ["na", p.status];
      return el("div", { class: "evpart" },
        el("p", {}, el("strong", {}, label + ": "), chip(e[0], e[1])),
        p.text ? el("details", {}, el("summary", {}, "What TinyFish said (the provider's claim; nothing here checks it)"), el("p", { class: "evidence" }, p.text)) : null);
    };
    const account = ACCOUNT[alert.isolation.status] || ["na", alert.isolation.status];
    return el("article", { class: "alertcard", "aria-label": kind + " alert" },
      el("header", {}, chip(SEVERITY[alert.severity] || "na", alert.severity),
        el("h3", {}, kind + (who ? ": " + who : ""))),
      alert.subject && alert.subject.target ? el("p", { class: "mono" }, alert.subject.target) : null,
      bar,
      el("p", { class: "muted" }, alert.score_ppm
        ? "Rule score " + alert.score_ppm.toLocaleString("en-US") + " of 1,000,000. A rule sum, not a probability."
        : "No rule fired. Only the learned model flagged this one, so it is a lower tier to look at."),
      alert.signals.length ? el("h4", {}, "Why it was flagged") : null, alert.signals.length ? signals : null,
      modelBox(alert.model),
      el("h4", {}, "Web evidence"),
      part("Search (what web reports say)", alert.web_evidence.search),
      part("Fetch (the page itself)", alert.web_evidence.fetch),
      el("h4", {}, "Account action"), el("p", {}, chip(account[0], account[1])));
  }

  // Fetches the alerts for a receipt and fills the section. Never throws: a failure only hides it.
  async function show(name) {
    const section = document.getElementById("alerts");
    const body = document.getElementById("alerts-body");
    try {
      const response = await fetch("/api/alerts?name=" + encodeURIComponent(name), { headers: { Accept: "application/json" } });
      if (!response.ok) throw new Error("no alerts");
      const data = await response.json();
      if (!data.alerts.length) { section.hidden = true; return; }
      body.replaceChildren(...data.alerts.map(card));
      document.getElementById("alerts-note").textContent =
        data.alerts.length + " alert" + (data.alerts.length === 1 ? "" : "s") +
        " raised by the explainable rules, read from the signed receipt. The events were reported by a collector; the receipt does not prove they are true.";
      section.hidden = false;
      if (typeof fx === "object") { fx.icons(); fx.reveal([section]); }
    } catch (error) {
      section.hidden = true;
    }
  }

  return { show };
})();
