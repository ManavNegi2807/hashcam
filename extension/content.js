// Runs in the agent's tab (isolated world). Three jobs:
//  1. hold every form submission until the background says the person decided;
//  2. turn a typed password or card number into a salted commitment (the value never leaves);
//  3. hand the page's text (including hidden text, where injected instructions hide) to the
//     background for the prompt-injection tripwire.
(() => {
  if (window.__hashcamContent) return;
  window.__hashcamContent = true;
  let isAgent = false;

  chrome.runtime.sendMessage({ type: "hello" }).then((answer) => {
    isAgent = Boolean(answer && answer.agent);
    if (!isAgent) return;
    document.documentElement.dataset.hashcamAgent = "1";
    badge("REC", "recording");
    if (document.readyState === "complete") sendPageText();
    else window.addEventListener("load", sendPageText, { once: true });
  }).catch(() => {});

  // ------------------------------------------------------------ badge

  let badgeEl = null;
  function badge(label, mode, detail = "") {
    if (!document.body) {
      document.addEventListener("DOMContentLoaded", () => badge(label, mode, detail), { once: true });
      return;
    }
    if (!badgeEl) {
      badgeEl = document.createElement("div");
      badgeEl.setAttribute("data-hashcam-badge", "");
      badgeEl.style.cssText = [
        "position:fixed", "top:10px", "right:10px", "z-index:2147483647",
        "font:600 12px/1.2 ui-monospace,Consolas,monospace", "padding:7px 11px",
        "border-radius:999px", "background:#0E0B09", "color:#FFF5EC",
        "border:1px solid #FF7A2E", "box-shadow:0 4px 18px rgba(0,0,0,.35)", "pointer-events:none",
      ].join(";");
      document.body.appendChild(badgeEl);
    }
    const dot = mode === "held" ? "#FFD27A" : mode === "blocked" ? "#FF6B6B" : "#FF3B30";
    badgeEl.textContent = "";
    const d = document.createElement("span");
    d.textContent = "● ";
    d.style.color = dot;
    badgeEl.append(d, `HashCam ${label}${detail ? " · " + detail : ""}`);
  }

  // ------------------------------------------------------------ form submissions

  window.addEventListener("submit", async (event) => {
    if (!isAgent) return;
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) return;
    if (form.dataset.hashcamPass === "1") {
      delete form.dataset.hashcamPass; // the one approved submission goes through
      return;
    }
    event.preventDefault();
    event.stopImmediatePropagation();
    const submitter = event.submitter || null;
    const action = new URL(form.getAttribute("action") || location.href, location.href).href;
    const fields = [...form.elements]
      .map((el) => el.name || el.id || "")
      .filter(Boolean)
      .slice(0, 12);
    badge("HELD", "held", "waiting for your approval");
    let answer = { decision: "DENY" };
    try {
      answer = await chrome.runtime.sendMessage({ type: "submit", url: action, fields });
    } catch { /* worker gone: stays held, nothing sent */ }
    if (answer && answer.decision === "ALLOW") {
      badge("REC", "recording", "approved, sending");
      form.dataset.hashcamPass = "1";
      form.requestSubmit(submitter && submitter.form === form ? submitter : undefined);
    } else {
      const why = answer && answer.decision === "TIMED_OUT" ? "nobody answered" : "not sent";
      badge("BLOCKED", "blocked", why);
    }
  }, true);

  // ------------------------------------------------------------ secret shield

  const CARD_HINT = /(card|cc-?num|cardnumber|pan)\b/i;
  function luhn(digits) {
    let sum = 0;
    for (let i = 0; i < digits.length; i++) {
      let d = Number(digits[digits.length - 1 - i]);
      if (i % 2) { d *= 2; if (d > 9) d -= 9; }
      sum += d;
    }
    return sum % 10 === 0;
  }
  function secretKind(el) {
    if (!(el instanceof HTMLInputElement) || !el.value) return null;
    if (el.type === "password") return "password";
    const digits = el.value.replace(/[\s-]/g, "");
    const hinted = el.autocomplete === "cc-number" || CARD_HINT.test(el.name || "") || CARD_HINT.test(el.id || "");
    if (/^\d{13,19}$/.test(digits) && (hinted || luhn(digits))) return "card";
    return null;
  }
  async function commit(value) {
    // A fresh random salt per value, then thrown away: the commitment shows that something was
    // typed into a secret field, and its bytes reveal nothing. It cannot be opened later.
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const hex = (b) => [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
    const data = new TextEncoder().encode(`${hex(salt)}:${value}`);
    return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", data)));
  }
  document.addEventListener("change", async (event) => {
    if (!isAgent) return;
    const kind = secretKind(event.target);
    if (!kind) return;
    const commitment = await commit(event.target.value);
    chrome.runtime.sendMessage({
      type: "secret", url: location.href, fieldKind: kind, commitment,
    }).catch(() => {});
  }, true);

  // ------------------------------------------------------------ page text for the tripwire

  // Sent by the page itself once it has loaded, with its own address, so the text can never be
  // mixed up with a later page the agent moved on to.
  function sendPageText() {
    // textContent, not innerText: hidden elements are exactly where injected instructions hide.
    const text = (document.body ? document.body.textContent : "").replace(/\s+/g, " ").trim();
    chrome.runtime.sendMessage({
      type: "pageLoaded", url: location.href, text: text.slice(0, 200000),
    }).catch(() => {});
  }
})();
