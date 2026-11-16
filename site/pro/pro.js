// The Pro page. A classic script (works from file://) with no libraries. Everything happens in this tab: the key,
// the logo and the records are read here, checked here, and never sent anywhere.
(async function () {
"use strict";

const L = window.HCLicense;
const R = window.HCRecords;
const B = window.HCBrand;
const P = window.HCPack;
const $ = (id) => document.getElementById(id);
const el = (tag, attrs = {}, ...kids) => {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) { if (k === "class") node.className = v; else node.setAttribute(k, v); }
  for (const kid of kids) if (kid != null) node.append(kid instanceof Node ? kid : String(kid));
  return node;
};
const today = () => new Date().toISOString().slice(0, 10);
const MAX_FILES = 20;
const MAX_BYTES = 8 * 1048576;

// ------------------------------------------------------------------ the "Get a licence" link: one constant

(function setLink() {
  const url = String((window.HCProConfig && window.HCProConfig.getLicenseUrl) || "#");
  const ok = /^https:\/\/[^\s]+$/.test(url) || /^mailto:[^\s]+$/.test(url);
  if (ok) $("getLicense").setAttribute("href", url);
  else $("getNote").textContent = "The link to get a licence has not been set up yet.";
})();

// ------------------------------------------------------------------ licence

async function paintLicence() {
  const st = await L.ready();
  const text = {
    none: "No licence on this device: the free plan.",
    valid: "Pro licence active.",
    expired: st.reason || "That licence has ended.",
    invalid: st.reason || "The saved key does not check out.",
    unsupported: st.reason || "This browser cannot check licence keys.",
    "not-configured": st.reason || "Licence checking is not set up on this site yet.",
  }[st.state] || "";
  $("licState").textContent = text;
  const lic = st.licence;
  $("licName").textContent = lic ? lic.name : "-";
  $("licPlan").textContent = st.plan === "pro" ? "Pro" : "Free";
  $("licExpires").textContent = lic ? (lic.expires || "no end date") : "-";
  const pro = st.plan === "pro";
  $("proTools").disabled = !pro;
  $("tools").classList.toggle("locked", !pro);
  $("toolsNote").textContent = pro
    ? "Pro is on. Everything below works."
    : "These tools turn on with a valid licence key. You can see what each does.";
  $("licenseRemove").disabled = st.state === "none" || st.state === "not-configured";
  paintBrand();
}

$("licenseCheck").addEventListener("click", async () => {
  const note = $("licenseNote");
  const key = $("licenseKey").value.trim();
  if (!key) { note.textContent = "Paste your key first."; return; }
  note.textContent = "Checking…";
  const st = await L.save(key);
  if (st.state === "valid") {
    $("licenseKey").value = "";
    note.textContent = "Saved on this device.";
  } else {
    note.textContent = st.reason || "That key could not be used.";
  }
  await paintLicence();
});
$("licenseRemove").addEventListener("click", async () => {
  L.remove();
  $("licenseNote").textContent = "Removed from this device.";
  await paintLicence();
});

// ------------------------------------------------------------------ name and logo

function paintBrand() {
  const brand = B.read();
  $("brandName").value = brand.name;
  const img = $("brandPreview");
  if (brand.logo) { img.src = "data:image/jpeg;base64," + brand.logo; img.hidden = false; } else { img.removeAttribute("src"); img.hidden = true; }
}
$("brandSave").addEventListener("click", async () => {
  if (!(await L.isPro())) return;
  const note = $("brandNote");
  const name = B.cleanName($("brandName").value);
  const saved = B.read();
  let { logo, mark } = saved;
  const file = $("brandLogo").files[0];
  try {
    if (file) ({ logo, mark } = await B.logoFromFile(file));
  } catch (error) {
    note.textContent = String((error && error.message) || error);
    return;
  }
  note.textContent = B.write({ name, logo, mark }) ? "Saved on this device." : "This browser would not keep it (a private window?).";
  $("brandLogo").value = "";
  paintBrand();
});
$("brandClear").addEventListener("click", () => {
  B.clear();
  $("brandLogo").value = "";
  $("brandNote").textContent = "Cleared.";
  paintBrand();
});

// ------------------------------------------------------------------ audit pack and CSV

let included = [];
let skipped = [];

function paintPack() {
  const list = $("packList");
  list.textContent = "";
  for (const rec of included) {
    list.append(el("li", { class: "ok" }, el("span", { class: "pr-st" }, "INCLUDED"), el("span", {}, el("b", {}, rec.name), ` ${P.tally(rec).allowed} allowed, ${P.tally(rec).blocked} blocked, ${P.tally(rec).held} held`)));
  }
  for (const s of skipped) {
    list.append(el("li", { class: "no" }, el("span", { class: "pr-st" }, "NOT INCLUDED"), el("span", {}, el("b", {}, s.name), " " + s.reason)));
  }
  $("packPdf").disabled = !included.length;
  $("packCsv").disabled = !included.length;
}

$("packBtn").addEventListener("click", async () => {
  if (!(await L.isPro())) return;
  const note = $("packNote");
  const files = [...$("packFiles").files];
  if (!files.length) { note.textContent = "Choose or drop the records first."; return; }
  if (files.length > MAX_FILES || files.some((f) => f.size > MAX_BYTES)) {
    note.textContent = `Too much to check: at most ${MAX_FILES} files, each under ${MAX_BYTES / 1048576} MB.`;
    return;
  }
  note.textContent = "Checking the records…";
  $("packBtn").disabled = true;
  included = [];
  skipped = [];
  $("packKey").hidden = true;
  const keys = files.find(R.isKeys);
  for (const file of files.filter((f) => !R.isKeys(f))) {
    const name = file.name.slice(0, 80);
    try {
      let checked;
      if (R.isReceiptFile(file)) checked = await R.checkReceipt(file, keys);
      else if (R.isSandboxFile(file)) checked = await R.checkSandbox(file);
      else { skipped.push({ name, reason: "This is not a record the pack understands (.html, .json or .abbreceipt). It is not included." }); continue; }
      if (!checked.ok) { skipped.push({ name, reason: R.explain(checked.failure, "included") }); continue; }
      included.push({ name, sha256: await R.sha256Hex(file), kind: R.isReceiptFile(file) ? "receipt" : "sandbox", events: checked.events });
    } catch (error) {
      skipped.push({ name, reason: `${String((error && error.message) || error)} It is not included.` });
    }
  }
  note.textContent = `${included.length} included, ${skipped.length} not included.`;
  $("packBtn").disabled = false;
  paintPack();
});

function saveFile(data, name, type) {
  const link = el("a", { href: URL.createObjectURL(new Blob([data], { type })), download: name });
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(link.href), 4000);
}

$("packPdf").addEventListener("click", async () => {
  if (!(await L.isPro()) || !included.length) return;
  const note = $("packNote");
  $("packPdf").disabled = true;
  note.textContent = "Writing and locking the pack…";
  try {
    const brand = B.forReport();
    const doc = P.packDoc({ included, skipped, brandName: brand.name, whiteLabel: brand.whiteLabel, at: today() });
    const { bytes, password } = await window.HCLockedPdf.buildLockedPdf(doc, brand.art);
    saveFile(bytes, "hashcam-audit-pack.pdf", "application/pdf");
    $("packPass").textContent = password; // shown once, on this page only: not stored, not sent
    $("packKey").hidden = false;
    note.textContent = "Saved. Each pack gets its own new password.";
  } catch (error) {
    note.textContent = `The pack could not be made: ${String((error && error.message) || error)}`;
  } finally {
    $("packPdf").disabled = !included.length;
  }
});
$("packCsv").addEventListener("click", async () => {
  if (!(await L.isPro()) || !included.length) return;
  saveFile(P.csv(included), "hashcam-steps.csv", "text/csv");
  $("packNote").textContent = "Saved.";
});
$("copyPackPass").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText($("packPass").textContent);
    $("packNote").textContent = "Password copied. Keep it apart from the file.";
  } catch {
    $("packNote").textContent = "Select the password and copy it yourself.";
  }
});

await paintLicence();
if (window.HCMotion) window.HCMotion.init();
})();
