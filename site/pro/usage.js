// A usage meter that lives in this browser: it counts scored runs per day (a date and a number, nothing about the
// records) so the Range can show "X of Y runs today". It never blocks anything. It is NOT enforced: clearing the
// browser's data, a private window or another device starts again at zero, and the page says so.
(() => {
"use strict";
const STORE = "hashcam-usage";
const today = () => new Date().toISOString().slice(0, 10);

function read() {
  try {
    const v = JSON.parse(localStorage.getItem(STORE) || "null");
    if (v && v.date === today() && Number.isInteger(v.n) && v.n >= 0 && v.n < 1e9) return v.n;
  } catch { /* unreadable: start again */ }
  return 0;
}
function write(n) { try { localStorage.setItem(STORE, JSON.stringify({ date: today(), n })); } catch { /* not remembered */ } }

window.HCUsage = {
  today: read,
  add() { const n = read() + 1; write(n); return n; },
  reset() { try { localStorage.removeItem(STORE); } catch { /* fine */ } },
};
})();
