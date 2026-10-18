// The task page, laid out like a chat. It sends a person's task and the cost they confirmed,
// shows the server's log, and shows what the offline verifier said about the receipt.
// It never decides anything itself, and all text goes in through textContent.
"use strict";

const $ = (id) => document.getElementById(id);
const say = (message) => { $("status").textContent = message; };
function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
function el(tag, attrs, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs || {})) node.setAttribute(key, value);
  for (const child of children) {
    if (child === null || child === undefined) continue;
    node.appendChild(typeof child === "string" ? document.createTextNode(child) : child);
  }
  return node;
}

const SVG_NS = "http://www.w3.org/2000/svg";
const ICONS = {
  check: "M4 12.5l5 5L20 6.5",
  cross: "M6 6l12 12M18 6L6 18",
  question: "M9.5 9a2.5 2.5 0 1 1 3.5 2.3c-.7.4-1 .9-1 1.7M12 17.5v.01",
  spin: "M12 3a9 9 0 1 0 9 9",
};
function icon(name) {
  const svg = document.createElementNS(SVG_NS, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "2.4");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  const path = document.createElementNS(SVG_NS, "path");
  path.setAttribute("d", ICONS[name]);
  svg.appendChild(path);
  return svg;
}

// Class, word and explanation for each overall verifier result. Only a display table.
const VERDICT = {
  VALID: ["ok", "check", "VALID", "The record is unchanged since it was signed."],
  PARTIAL: ["warn", "question", "PARTIAL", "Required checks passed; something optional is missing or not independent."],
  INCOMPLETE: ["warn", "question", "INCOMPLETE", "Something required could not be checked. Missing evidence is not a pass."],
  INVALID: ["fail", "cross", "INVALID", "A check failed. Open the full receipt to see which one."],
  UNSUPPORTED: ["warn", "question", "UNSUPPORTED", "This build does not understand the receipt."],
  UNREADABLE: ["fail", "cross", "UNREADABLE", "The file could not be read as a receipt."],
};

let info = null;

function push(node) {
  $("hero").hidden = true;
  const thread = $("thread");
  thread.appendChild(node);
  fx.enter(node);
  thread.scrollTop = thread.scrollHeight;
  return node;
}

function currentMode() {
  const checked = document.querySelector("input[name=mode]:checked");
  return checked ? checked.value : "agent";
}

const ANSWER_MODES = ["search", "research"];
const GATED = ["guarded", "realsite", "pay", "endpoint"];

// What a mode costs at worst, in cents; null when unknown.
function costOf(mode) {
  if (!info) return null;
  if (mode === "agent") return info.estimate_cents;
  const entry = info.modes ? info.modes[mode] : null;
  return entry ? entry.estimate_cents : null;
}

function updateSend() {
  if (currentMode() === "endpoint") {
    // Simulated events and a simulated isolation: only the analyst's signing key is needed.
    $("task-run").disabled = !(info && info.endpoint && info.endpoint.approver_key_id);
    return;
  }
  if (currentMode() === "pay") {
    // Fake money only: a Stripe TEST key must be set on the server, and an approver key must exist.
    const ok = info && info.pay && info.pay.test_key && info.pay.approver_key_id;
    $("task-run").disabled = !ok;
    return;
  }
  if (currentMode() === "realsite") {
    // Uses no TinyFish credit: a real browser on this computer. The gate is the approval.
    const keyed = info && info.guarded && info.guarded.approver_key_id;
    $("task-run").disabled = !(keyed && $("task-goal").value.trim());
    return;
  }
  if (currentMode() === "guarded") {
    // Nothing here calls TinyFish, so there is no cost to confirm: the human gate is the approval.
    $("task-run").disabled = !(info && info.guarded && info.guarded.approver_key_id);
    return;
  }
  const mode = currentMode();
  const cost = costOf(mode);
  const ready = info && info.key_set && cost !== null;
  // A free mode needs no cost switch; anything that can cost money does.
  const agreed = cost === 0 || $("task-confirm").checked;
  $("task-run").disabled = !(ready && agreed && $("task-goal").value.trim());
}

function applyMode() {
  const mode = currentMode();
  const guarded = mode === "guarded";
  const realsite = mode === "realsite";
  const pay = mode === "pay";
  const endpoint = mode === "endpoint";
  const answers = ANSWER_MODES.includes(mode);
  const cost = costOf(mode);
  // Until the page knows the costs, show neither the start page nor the cost switch.
  $("field-url").hidden = guarded || realsite || pay || endpoint || answers || !info;
  $("field-confirm").hidden = guarded || realsite || pay || endpoint || cost === 0 || !info;
  $("task-cost").hidden = guarded || realsite || pay || endpoint || !info || !info.key_set || cost === null || cost === 0;
  $("task-goal").readOnly = guarded;
  // Pay bills may start with an empty box: it then runs the three example bills.
  $("task-goal").required = !pay && !endpoint;
  $("task-run-label").textContent = endpoint ? "Review events (simulated)" : pay ? "Pay (test money)" : realsite ? "Start (needs approval)" : guarded ? "Start demo task" : { search: "Search", research: "Start research" }[mode] || "Run task";
  $("task-goal").placeholder = endpoint
    ? "Pick a scenario in a few words: phishing link in chat, big download at night, record queries. Leave empty to review all the simulated events."
    : pay
    ? "Bills to pay, for example: Pay Acme Supplies 12.00 USD; Pay Cloud Hosting 180 USD. Leave empty for the three example bills."
    : realsite
    ? "A message to send through the form on httpbin.org, only if you approve"
    : answers
    ? "Ask anything, for example: what are the latest POCO phone prices?"
    : "Describe the task, for example: read the page and tell me its first sentence";
  if (guarded && info && info.guarded) {
    $("task-goal").value = info.guarded.task;
  } else if (!guarded && info && info.guarded && $("task-goal").value === info.guarded.task) {
    $("task-goal").value = "";
  }
  if (pay && info && info.pay && !info.pay.test_key) {
    runState("off", info.pay.key_set
      ? "Pay bills is off: the Stripe key is not a TEST key. Test keys start with sk_test_."
      : "Pay bills is off: STRIPE_TEST_KEY is not set where this server was started.");
  }
  updateSend();
}

function runState(kind, text) {
  const node = $("run-state");
  node.className = "run-state " + kind;
  node.textContent = text;
}

async function loadPast() {
  const list = $("past");
  clear(list);
  try {
    const response = await fetch("/api/receipts");
    const { receipts, labels = {} } = await response.json();
    // Newest first, named by what the task was, like a chat title. The file name is never shown.
    const when = (name) => (labels[name] || {}).when || 0;
    for (const name of receipts.slice().sort((a, b) => when(b) - when(a))) {
      const label = labels[name] || {};
      const date = label.when ? new Date(label.when * 1000).toLocaleString(undefined, { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" }) : "";
      const here = new URLSearchParams(location.search).get("receipt") === name;
      list.appendChild(el("li", {}, el("a", { href: "/run?receipt=" + encodeURIComponent(name), title: label.title || "Earlier run", ...(here ? { "aria-current": "page" } : {}) },
        el("span", { class: "t" }, label.title || "Earlier run"), el("span", { class: "d" }, date))));
    }
    if (!receipts.length) list.appendChild(el("li", { class: "none" }, "No runs yet"));
    fx.stagger(list.children);
  } catch (error) {
    list.appendChild(el("li", { class: "none" }, "Could not list runs"));
  }
}

async function loadInfo() {
  let loaded;
  try {
    const response = await fetch("/api/run/info", { headers: { Accept: "application/json" } });
    if (!response.ok) throw new Error("off");
    loaded = await response.json();
  } catch (error) {
    runState("off", "Runs are off: the server was started without --enable-runs.");
    return;
  }
  info = loaded;
  const sites = $("task-sites");
  clear(sites);
  for (const host of info.hosts) sites.appendChild(el("option", { value: "https://" + host }));
  if (!$("task-url").value && info.hosts.length) {
    // A page with real content, so a general question has somewhere to start.
    $("task-url").value = info.hosts.includes("en.wikipedia.org")
      ? "https://en.wikipedia.org/wiki/Main_Page"
      : "https://" + info.hosts[0];
  }
  const cost = $("task-cost");
  if (!info.key_set) {
    // The reason lives in the sidebar, not in the prompt box.
    cost.hidden = true;
    runState("off", "Runs are off: TINYFISH_API_KEY is not set where this server was started.");
  } else if (info.estimate_cents === null) {
    cost.hidden = true;
    runState("off", "Runs are off: the worst-case cost is unknown right now.");
  } else {
    runState("on", "Runs are on.");
    cost.hidden = false;
    cost.textContent = "Worst case about " + info.estimate_cents + " cents. Spent so far $" +
      (info.spent_cents / 100).toFixed(2) + " of $" + (info.ceiling_cents / 100).toFixed(2) + ".";
    $("task-confirm-text").textContent = "I agree to spend up to " + info.estimate_cents + " cents of my TinyFish credit.";
  }
  applyMode();
}

async function verdictFor(name) {
  const response = await fetch("/api/verify?name=" + encodeURIComponent(name));
  if (!response.ok) return null;
  return response.json();
}

function setHead(head, kind, iconName, text) {
  clear(head);
  head.className = "agent-head " + kind;
  head.appendChild(icon(iconName));
  head.appendChild(el("span", {}, text));
}

// The answer, said as a chat reply: plain text first, then one quiet line about the receipt.
function sayAnswer(reply, before, text, mode) {
  const note = mode === "search"
    ? "Top results from TinyFish Search. Open a link to read the page; this page does not check them."
    : mode === "research"
    ? "Research report from TinyFish. It lists its sources; this page does not check them."
    : mode === "realsite"
    ? "Result of the run on a real website. Your message went to httpbin.org only if you approved."
    : mode === "endpoint"
    ? "The events were SIMULATED. Alerts are rule scores for a person to review, not proof of wrongdoing. Open the audit view for the full alert cards."
    : mode === "pay"
    ? "Test money only (Stripe test mode). Nothing real moved. Small bills paid on their own; larger ones needed your signature; the largest were refused."
    : mode === "guarded"
    ? "Result of the guarded run. The portal and the data are fake."
    : "Answer from TinyFish. This page does not check that it is true.";
  const block = el("div", { class: "say" }, renderRich(text), el("p", { class: "meta" }, note));
  if (before) reply.insertBefore(block, before); else reply.appendChild(block);
}

function receiptLine(reply, overall, receipt) {
  const [cls, iconName, word, why] = VERDICT[overall] || ["warn", "question", overall, "Unrecognized result; treated as not a pass."];
  reply.appendChild(el("div", { class: "agent-foot" },
    el("span", { class: "vchip " + cls, title: why }, icon(iconName), word),
    el("span", { class: "meta" }, "Receipt: the record is unchanged since it was signed. That is not proof the answer is true."),
    el("a", { class: "linkbtn small", href: "/?receipt=" + encodeURIComponent(receipt) }, "View receipt")));
}

// An older run, opened from the sidebar, shown as the conversation it was.
async function showPast(name) {
  let label = {};
  try {
    const response = await fetch("/api/receipts");
    label = ((await response.json()).labels || {})[name] || {};
  } catch (error) {
    /* shown without a name */
  }
  const date = label.when ? new Date(label.when * 1000).toLocaleString(undefined, { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" }) : "";
  push(el("div", { class: "msg you" }, el("p", {}, label.goal || label.title || "An earlier run"),
    el("p", { class: "meta" }, [label.url ? "start at " + label.url : "", date].filter(Boolean).join(" · "))));
  const head = el("div", {});
  const reply = push(el("div", { class: "msg agent" }, head));
  if (label.answer) {
    setHead(head, "ok", "check", STATUS_DONE[label.mode] || "TinyFish answered.");
    sayAnswer(reply, null, label.answer, label.mode);
  } else {
    setHead(head, "run", "question", "No answer was saved for this run.");
    reply.appendChild(el("p", { class: "meta" }, "The receipt is still here. Open it to see what was recorded."));
  }
  const report = await verdictFor(name);
  receiptLine(reply, report ? String(report.overall) : "UNKNOWN", name);
}

let askedFor = "";

const RUNNING = {
  endpoint: "Reviewing the endpoint events… ",
  pay: "Paying the bills one at a time (test money)… ",
  guarded: "Running the demo task… ",
  realsite: "Measuring what can be claimed, then opening the real site (about a minute)… ",
  search: "Searching… ",
  research: "Researching on TinyFish (usually 5 to 20 minutes; keep this window open)… ",
};
const STATUS_DONE = {
  endpoint: "The endpoint review finished.",
  pay: "The payment run finished.",
  guarded: "The demo run finished.",
  realsite: "The real-website run finished.",
  search: "Here is what the web search found.",
  research: "TinyFish wrote a research report.",
};

// "form_submit https://portal.example/vendor/42/bank params=…" said in words. Display only:
// what gets signed is always the exact text, shown underneath.
function plainSummary(summary) {
  const match = /^(\w+) (\S+)/.exec(summary);
  if (!match) return summary;
  const what = { form_submit: "submit a form", navigate: "open a page", payment: "make a payment",
    download: "download a file", api_call: "call an API", form_fill: "fill in a form" }[match[1]] || match[1].replace(/_/g, " ");
  const bank = /\/bank/.test(match[2]) ? " This changes where a vendor's money is sent." : "";
  // A payment's summary also carries the amount and who is paid, in words the approver can read.
  const isolate = /\| (ISOLATE .+)$/.exec(summary);
  if (isolate) return "The analyst is asked to approve: " + isolate[1];
  const pays = /\| PAY (.+)$/.exec(summary);
  if (pays) return "The agent wants to pay " + pays[1] + " (test money, Stripe test mode).";
  return "The agent wants to " + what + " at " + match[2] + "." + bank;
}

// The approval card: shows exactly what will be signed. A click signs it, nothing else does.
function approvalCard(job, pending, reply, before, mode, typed) {
  const keyId = info && info.guarded ? info.guarded.approver_key_id : null;
  const status = el("p", { class: "meta", role: "status" }, "");
  const decide = async (decision) => {
    for (const b of card.querySelectorAll("button")) b.disabled = true;
    status.textContent = "Signing…";
    try {
      const response = await fetch("/api/run/approve", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-ABB-Token": info.token },
        body: JSON.stringify({ job, decision, summary_digest: pending.summary_digest }),
      });
      const body = await response.json();
      if (!response.ok) throw new Error(body.error || "Could not sign.");
      status.textContent = (decision === "GRANTED" ? "Approved" : "Denied") + " and signed with key " + body.key_id.slice(0, 22) + "…";
      for (const b of card.querySelectorAll("button")) b.remove();
    } catch (error) {
      status.textContent = error.message;
      for (const b of card.querySelectorAll("button")) b.disabled = false;
    }
  };
  const approve = el("button", { type: "button", class: "approve" }, "Approve");
  const deny = el("button", { type: "button", class: "deny" }, "Deny");
  approve.addEventListener("click", () => decide("GRANTED"));
  deny.addEventListener("click", () => decide("DENIED"));
  const card = el("div", { class: "approval", role: "group", "aria-label": "Approval needed" },
    el("div", { class: "approval-h" }, "Approval needed"),
    el("p", { class: "approval-what" }, plainSummary(pending.summary)),
    el("details", { class: "raw" }, el("summary", {}, "The exact text you are signing"),
      el("p", { class: "mono" }, pending.summary)),
    typed ? el("p", { class: "approval-what" }, "Your message: " + typed) : null,
    el("p", { class: "meta" }, mode === "endpoint"
      ? "Policy holds any account action until a key signs a grant. The account is made up and the isolation is simulated: nothing real changes."
      : mode === "pay"
      ? "Policy held this payment back because it is over the limit a company agent may pay on its own. It is paid only if a key signs a grant. This is Stripe test mode: fake money, no real card or bank account."
      : mode === "realsite"
      ? "Policy held this step back. It is sent only if a key signs a grant. This goes to a real public test site, httpbin.org, which will see your message."
      : "Policy held this step back. It is sent only if a key signs a grant. The portal and the data are fake; no money moves."),
    el("p", { class: "meta" }, keyId ? "You will sign with approver key " + keyId.slice(0, 22) + "… (a key signs, not a named person)." : "No approver key is available."),
    el("div", { class: "actions" }, approve, deny), status);
  reply.insertBefore(card, before);
  fx.pop(card);
}

async function runTask(event) {
  event.preventDefault();
  const mode = currentMode();
  const goal = mode === "guarded" ? info.guarded.task : $("task-goal").value;
  const url = mode === "agent" ? $("task-url").value : "";
  $("task-run").disabled = true;
  push(el("div", { class: "msg you" }, el("p", {}, goal), el("p", { class: "meta" }, { guarded: "demo task on a fake portal", realsite: "real form on httpbin.org", pay: "payments in Stripe test mode (fake money)", endpoint: "simulated endpoint events", search: "search", research: "research" }[mode] || "start at " + url)));
  const head = el("div", {});
  setHead(head, "run", "spin", "Starting the run…");
  const track = el("div", { class: "bar-track", "aria-hidden": "true" }, el("div", { class: "bar-fill" }));
  const log = el("pre", { class: "log", tabindex: "0", "aria-label": "Run log" });
  const details = el("details", {}, el("summary", {}, "Show the log"), log);
  const reply = push(el("div", { class: "msg agent" }, head, track, details));
  try {
    const response = await fetch("/api/run/start", {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-ABB-Token": info.token },
      body: JSON.stringify({ goal, url, confirm_cents: GATED.includes(mode) ? 0 : costOf(mode), mode }),
    });
    const body = await response.json();
    if (!response.ok) throw new Error(body.error || "The server refused the run.");
    if (mode !== "guarded") $("task-goal").value = "";
    askedFor = "";
    let status;
    for (;;) {
      await new Promise((resolve) => setTimeout(resolve, 1000));
      const poll = await fetch("/api/run/status?id=" + encodeURIComponent(body.job));
      if (!poll.ok) throw new Error("Lost track of the run.");
      status = await poll.json();
      log.textContent = status.lines.join("\n");
      log.scrollTop = log.scrollHeight;
      if (status.pending && askedFor !== status.pending.summary_digest) {
        askedFor = status.pending.summary_digest;
        approvalCard(body.job, status.pending, reply, details, mode, mode === "realsite" ? goal : "");
      }
      setHead(head, "run", "spin", status.pending ? "Waiting for your approval…" : (RUNNING[mode] || "Running on TinyFish… ") + status.seconds + " s");
      $("thread").scrollTop = $("thread").scrollHeight;
      if (status.state !== "running") break;
    }
    track.remove();
    if (status.state === "done" && status.receipt) {
      const report = await verdictFor(status.receipt);
      const overall = report ? String(report.overall) : "UNKNOWN";
      if (status.result) {
        setHead(head, "ok", "check", STATUS_DONE[mode] || "TinyFish answered.");
        sayAnswer(reply, details, status.result, mode);
      } else if (status.outcome === "SUCCEEDED") {
        setHead(head, "ok", "check", "TinyFish finished the run but sent back no text.");
        reply.insertBefore(el("p", { class: "meta" },
          "It may not have found the answer on that start page. Try a start page that has the information, such as Wikipedia."), details);
      } else {
        setHead(head, "fail", "cross", "The run did not complete" + (status.outcome ? " (" + status.outcome + ")" : "") + ". The receipt records that honestly.");
        details.open = true;
      }
      receiptLine(reply, overall, status.receipt);
    } else {
      setHead(head, "fail", "cross", "The run did not finish cleanly.");
      details.open = true;
    }
  } catch (error) {
    track.remove();
    setHead(head, "fail", "cross", error.message);
  } finally {
    $("task-confirm").checked = false;
    await Promise.all([loadInfo(), loadPast()]);
    updateSend();
  }
}

$("task-form").addEventListener("submit", runTask);
for (const radio of document.querySelectorAll("input[name=mode]")) radio.addEventListener("change", applyMode);
$("task-confirm").addEventListener("change", updateSend);
$("task-goal").addEventListener("input", updateSend);
$("task-goal").addEventListener("keydown", (event) => {
  if (event.key === "Enter" && !event.shiftKey) {
    event.preventDefault();
    if (!$("task-run").disabled) $("task-form").requestSubmit();
  }
});
for (const button of document.querySelectorAll(".idea")) {
  button.addEventListener("click", () => {
    $("task-goal").value = button.dataset.text;
    if (button.dataset.url) $("task-url").value = button.dataset.url;
    $("task-goal").focus();
    updateSend();
  });
}
applyMode();
loadPast();
loadInfo();
// The first screen eases in, and buttons answer a press.
// The sidebar's list of what the console can do: one click picks that task type and jumps to the box.
function buildModesNav() {
  const nav = $("modes-nav");
  if (!nav) return;
  for (const radio of document.querySelectorAll("input[name=mode]")) {
    const label = radio.parentElement.querySelector("b");
    if (!label) continue;
    const button = el("button", { type: "button", class: "modebtn", "data-mode": radio.value }, label.textContent.trim());
    const mark = typeof fx === "object" ? fx.modeIcon(radio.value) : null;
    if (mark) button.prepend(mark);
    button.addEventListener("click", () => {
      radio.checked = true;
      radio.dispatchEvent(new Event("change", { bubbles: true }));
      $("task-goal").focus();
      $("task-form").scrollIntoView({ block: "end" });
    });
    nav.appendChild(el("li", {}, button));
  }
}

// One line under the box: which task type is picked and what it does. On wide screens the sidebar
// list picks the type and the grid of cards is hidden, so the descriptions live here.
function syncModeCaption() {
  const caption = $("mode-caption");
  const radio = document.querySelector("input[name=mode]:checked");
  if (!caption || !radio) return;
  const label = radio.parentElement;
  const name = label.querySelector("b");
  const words = (label.querySelector("span").textContent || "").replace(name ? name.textContent : "", "").trim();
  caption.replaceChildren(el("strong", {}, (name ? name.textContent : radio.value).trim()), " " + words);
}

// Mark the task type that is picked now, so the list shows where you are.
function syncModesNav() {
  const mode = currentMode();
  syncModeCaption();
  for (const button of document.querySelectorAll("#modes-nav .modebtn")) {
    if (button.dataset.mode === mode) button.setAttribute("aria-current", "true");
    else button.removeAttribute("aria-current");
  }
}

buildModesNav();
syncModesNav();
for (const radio of document.querySelectorAll("input[name=mode]")) radio.addEventListener("change", syncModesNav);
fx.stagger(document.querySelectorAll("#hero > *"), 0.07);
fx.press("button, .idea, .newrun, .linkbtn");
// /run?receipt=<name> opens an earlier run as the conversation it was.
const wanted = new URLSearchParams(location.search).get("receipt");
if (wanted) showPast(wanted);
// Logos, icons, title letters, card glow and button lean (decoration only).
fx.flair();
