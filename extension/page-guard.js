// Runs in the page's own world. An agent's script can call form.submit(), which skips the
// submit event the content script listens for. In the agent's tab, submit() is routed through
// requestSubmit(), which fires that event, so the submission is held like any other.
// Requests a script sends itself (fetch, XHR, WebSocket) are NOT caught; the receipt's
// coverage (STEP_OBSERVED) says so.
(() => {
  if (window.__hashcamGuard) return;
  window.__hashcamGuard = true;
  const original = HTMLFormElement.prototype.submit;
  HTMLFormElement.prototype.submit = function submit() {
    if (document.documentElement.dataset.hashcamAgent === "1" && this.dataset.hashcamPass !== "1") {
      return this.requestSubmit();
    }
    return original.call(this);
  };
})();
