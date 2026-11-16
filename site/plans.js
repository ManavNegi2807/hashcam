(async function () {
"use strict";
const $ = (id) => document.getElementById(id);
const safe = (u) => /^https:\/\/[^\s]+$/.test(u) || /^mailto:[^\s]+$/.test(u);
const cfg = window.HCProConfig || {};
const prices = cfg.prices || {};
for (const [id, key] of [["priceFree", "free"], ["pricePro", "pro"], ["priceEnt", "enterprise"]]) {
  const text = String(prices[key] || "").trim();
  $(id).textContent = text && text.length <= 60 ? text : "Ask";
}
const contact = String(cfg.enterpriseContact || "#");
if (safe(contact)) $("entContact").setAttribute("href", contact); else $("planNote").textContent = "The Enterprise contact link has not been set up yet.";
await window.HCLicense.ready();
if (window.HCMotion) window.HCMotion.init();
})();
