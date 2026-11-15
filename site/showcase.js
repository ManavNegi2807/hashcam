// The telemetry bus, the four-step walkthrough and the quickstart on the HashCam site.
// A classic script (works from a file:// page). Nothing here contacts any server.
(function () {
"use strict";

const C = window.HCChain;
const $ = (id) => document.getElementById(id);

// ================================================================== a real sample chain
// Built in this browser a moment ago: real SHA-256 hashes and a real ECDSA P-256 signature, from a
// key that exists only in this tab's memory. It is the sandbox's simplified chain, not abb/1.

const TITLES = ["1. SHA-256 Chain", "2. Deterministic Policy", "3. Fake-Money Gate", "4. Human Sign-Off"];
let sample = null;

async function buildSample() {
  const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, false, ["sign", "verify"]);
  const jwk = await crypto.subtle.exportKey("jwk", pair.publicKey);
  const pub = { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };
  const keyId = (await C.sha256hex(C.canon(pub))).slice(0, 16);
  const events = [];
  let prev = C.ZERO;
  async function add(type, data) {
    const body = { v: 1, n: events.length, ts: Date.now(), type, data };
    const hash = await C.eventHash(prev, body);
    const ev = { body, prev, hash };
    events.push(ev);
    prev = hash;
    return ev;
  }
  await add("SESSION_STARTED", { policy: "sandbox-policy/1", budget_cents: 10000, key_id: keyId });
  const request = await add("ACTION_REQUESTED", {
    action: "provision_sandbox_gpu", label: "Provision Sandbox GPU", amount_cents: 3500, domain: "api.gpu-cloud.example",
  });
  const decision = await add("POLICY_DECISION", {
    rule_id: "R5", rule: "HUMAN_SIGNOFF_REQUIRED", outcome: "HOLD", domain_check: "PASS",
    request_hash: request.hash, trigger_reason: "$35.00 is more than the $10.00 the agent may spend alone",
  });
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" }, pair.privateKey, C.approvalBytes("GRANTED", request.hash));
  const human = await add("HUMAN_DECISION", {
    decision: "GRANTED", request_hash: request.hash, key_id: keyId, signature: C.toB64(new Uint8Array(signature)),
  });
  await add("ACTION_DISPATCHED", { request_hash: request.hash, amount_cents: 3500, escrow_after_cents: 6500 });
  const check = await C.verifyChain(events, pub);
  return { events, request, decision, human, check, keyId };
}

const R = window.HCReadable;
const short = (hash) => hash.slice(0, 10) + "…";

// What each stop shows: one sentence of context, the events in plain words (each with its raw record
// behind a closed "Technical details" opener) and a few labelled facts. No JSON is printed.
function plain(i) {
  const s = sample;
  const wrap = (ev) => ({ prev: ev.prev, hash: ev.hash, body: ev.body });
  switch (i) {
    case 0: return {
      lede: "Each event's fingerprint (a SHA-256 hash) covers the fingerprint of the event before it. Change anything that already happened and every fingerprint after it stops matching.",
      events: [wrap(s.events[0]), wrap(s.events[1])],
      facts: [
        ["Event 1 fingerprint", short(s.events[0].hash)],
        ["Event 2 carries it as", short(s.events[1].prev)],
        ["So", "editing event 1 later would break event 2, and every event after it"],
      ],
    };
    case 1: return {
      lede: "A fixed rule, not a model. The same request always gets the same answer, so you can re-run it and check.",
      events: [wrap(s.decision)],
      facts: [
        ["Rule that applied", "R5: a person must sign anything over $10.00"],
        ["Site on the allow-list", "Yes"],
        ["Same input, same answer", "Yes: no model and no randomness"],
      ],
    };
    case 2: return {
      lede: "The money is fake: a local mock gateway, so nothing real is ever charged.",
      events: [wrap(s.request)],
      facts: [
        ["Asked to spend", R.money(3500)],
        ["The agent may spend alone", "up to " + R.money(1000)],
        ["Budget cap", R.money(10000)],
        ["More than what is left", "refused, even if someone approves"],
      ],
    };
    default: return {
      lede: "The person's decision is signed over the fingerprint of the exact request that was shown to them.",
      events: [wrap(s.human)],
      facts: [
        ["Signed with", "a key made in this tab a moment ago (ECDSA P-256)"],
        ["Re-checked just now", s.check.ok ? "chain intact, " + s.check.rows.length + " events" : "chain broken"],
      ],
    };
  }
}

function fill(host, i) {
  const v = plain(i);
  const lede = document.createElement("p");
  lede.className = "lede";
  lede.textContent = v.lede;
  host.replaceChildren(lede);
  for (const ev of v.events) host.append(R.storyNode(document, R.describe(ev), R.technical(ev, {})));
  const list = document.createElement("dl");
  list.className = "facts";
  for (const [label, value] of v.facts) {
    const dt = document.createElement("dt");
    dt.textContent = label;
    const dd = document.createElement("dd");
    window.HCMotion.hexify(dd, value, "fact-" + label);
    list.append(dt, dd);
  }
  host.append(list);
}

// ================================================================== the telemetry bus

function selectStop(i) {
  for (const node of document.querySelectorAll("#busSvg .bus-node")) {
    const on = Number(node.dataset.i) === i;
    node.classList.toggle("on", on);
    node.setAttribute("aria-pressed", String(on));
  }
  $("busTitle").textContent = TITLES[i];
  if (sample) fill($("busPlain"), i); else $("busPlain").textContent = "Computing a real sample…";
}

for (const node of document.querySelectorAll("#busSvg .bus-node")) {
  const pick = () => selectStop(Number(node.dataset.i));
  node.addEventListener("click", pick);
  node.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); pick(); }
  });
}

// ================================================================== the four-step walkthrough

function showStep(i) {
  for (const li of document.querySelectorAll(".stage-list li")) li.classList.toggle("on", Number(li.dataset.i) === i);
  for (const li of document.querySelectorAll(".story-step")) li.classList.toggle("on", Number(li.dataset.i) === i);
  if (sample) fill($("storyPlain"), i);
}

if ("IntersectionObserver" in window) {
  // A step counts as "reached" while it crosses the middle band of the screen.
  const observer = new IntersectionObserver((entries) => {
    for (const entry of entries) {
      if (entry.isIntersecting) showStep(Number(entry.target.dataset.i));
    }
  }, { rootMargin: "-42% 0px -42% 0px", threshold: 0 });
  for (const step of document.querySelectorAll(".story-step")) observer.observe(step);
}

// ================================================================== the quickstart tabs

const tabs = [...document.querySelectorAll(".qs-tab")];
function selectTab(i, focus) {
  tabs.forEach((tab, n) => {
    const on = n === i;
    tab.setAttribute("aria-selected", String(on));
    tab.tabIndex = on ? 0 : -1;
    $(tab.getAttribute("aria-controls")).hidden = !on;
    if (on && focus) tab.focus();
  });
}
tabs.forEach((tab, i) => {
  tab.addEventListener("click", () => selectTab(i, false));
  tab.addEventListener("keydown", (e) => {
    if (e.key === "ArrowRight") { e.preventDefault(); selectTab((i + 1) % tabs.length, true); }
    else if (e.key === "ArrowLeft") { e.preventDefault(); selectTab((i + tabs.length - 1) % tabs.length, true); }
    else if (e.key === "Home") { e.preventDefault(); selectTab(0, true); }
    else if (e.key === "End") { e.preventDefault(); selectTab(tabs.length - 1, true); }
  });
});

async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // No clipboard API (or no permission): the old way, through a selected text area.
    const area = document.createElement("textarea");
    area.value = text;
    area.setAttribute("readonly", "");
    area.className = "offscreen";
    document.body.append(area);
    area.select();
    let ok = false;
    try { ok = document.execCommand("copy"); } catch { ok = false; }
    area.remove();
    return ok;
  }
}

for (const button of document.querySelectorAll(".copy")) {
  button.addEventListener("click", async () => {
    const code = button.parentElement.querySelector("code").textContent;
    const ok = await copyText(code);
    button.textContent = ok ? "Copied ✓" : "Select and copy";
    button.classList.toggle("done", ok);
    setTimeout(() => { button.textContent = "Copy"; button.classList.remove("done"); }, 1800);
  });
}

// ================================================================== start

if (!window.crypto || !crypto.subtle) {
  $("busPlain").textContent = "This browser has no Web Crypto in this context, so a live sample cannot be made here.";
} else {
  buildSample().then((built) => {
    sample = built;
    selectStop(0);
    showStep(0);
  }).catch((error) => {
    $("busPlain").textContent = `Could not build a sample: ${error.message}`;
  });
}
})();
