// White-label settings for Pro reports: a company name and a logo. They live in localStorage on this device only
// and are used to write the PDF header. The logo a buyer picks is untrusted: it must really be a PNG or a JPEG
// (checked by its first bytes, not its name), is size-capped, and is RE-DRAWN in a canvas and re-encoded as a
// small JPEG, so nothing of the original file (metadata, odd formats, SVG) ever reaches the report.
(() => {
"use strict";

const STORE = "hashcam-pro-brand";
const MAX_FILE = 1048576; // 1 MB
const MAX_SIDE = 4000; // a picture bigger than this is refused before it is decoded to a canvas
const MIN_SIDE = 16;
const NAME_MAX = 24; // the header has room for about this many characters at full size
const BAND = "#080B12"; // the report's dark header colour

const B64 = /^[A-Za-z0-9+/]+={0,2}$/;
const isJpegB64 = (s) => typeof s === "string" && s.length > 100 && s.length < 80000 && s.startsWith("/9j/") && B64.test(s);

function cleanName(name) {
  const text = String(name == null ? "" : name).replace(/[\u0000-\u001f\u007f]/g, " ").replace(/\s+/g, " ").trim();
  return text.slice(0, NAME_MAX);
}

function read() {
  try {
    const saved = JSON.parse(localStorage.getItem(STORE) || "null");
    if (!saved || typeof saved !== "object") return { name: "", logo: "", mark: "" };
    return {
      name: cleanName(saved.name),
      logo: isJpegB64(saved.logo) ? saved.logo : "",
      mark: isJpegB64(saved.mark) ? saved.mark : "",
    };
  } catch { return { name: "", logo: "", mark: "" }; }
}
function write(brand) {
  try { localStorage.setItem(STORE, JSON.stringify(brand)); return true; } catch { return false; }
}
const clear = () => { try { localStorage.removeItem(STORE); } catch { /* fine */ } };

const startsWith = (bytes, sig) => sig.every((b, i) => bytes[i] === b);

// A picture file -> { logo, mark } as base64 JPEGs, or throws an Error with a plain message.
async function logoFromFile(file) {
  if (!file) throw new Error("Choose a picture first.");
  if (file.size > MAX_FILE) throw new Error("That picture is too big: the limit is 1 MB.");
  const head = new Uint8Array(await file.slice(0, 8).arrayBuffer());
  const png = startsWith(head, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  const jpeg = startsWith(head, [0xff, 0xd8, 0xff]);
  if (!png && !jpeg) throw new Error("The logo must be a PNG or a JPEG picture.");
  let bitmap;
  try { bitmap = await createImageBitmap(file); } catch { throw new Error("That file could not be read as a picture."); }
  try {
    if (bitmap.width > MAX_SIDE || bitmap.height > MAX_SIDE) throw new Error("That picture is too large: the limit is 4000 pixels on a side.");
    if (bitmap.width < MIN_SIDE || bitmap.height < MIN_SIDE) throw new Error("That picture is too small to use as a logo.");
    return { logo: await draw(bitmap, 144, BAND, 1), mark: await draw(bitmap, 480, "#ffffff", 0.1) };
  } finally {
    bitmap.close();
  }
}

// The picture, fitted inside a square, on a plain background, as a base64 JPEG.
async function draw(bitmap, size, background, alpha) {
  const canvas = document.createElement("canvas");
  canvas.width = size;
  canvas.height = size;
  const ctx = canvas.getContext("2d");
  ctx.fillStyle = background;
  ctx.fillRect(0, 0, size, size);
  const pad = Math.round(size * 0.08);
  const scale = Math.min((size - 2 * pad) / bitmap.width, (size - 2 * pad) / bitmap.height);
  const w = bitmap.width * scale, h = bitmap.height * scale;
  ctx.globalAlpha = alpha;
  ctx.drawImage(bitmap, (size - w) / 2, (size - h) / 2, w, h);
  const blob = await new Promise((resolve) => canvas.toBlob(resolve, "image/jpeg", alpha === 1 ? 0.9 : 0.75));
  if (!blob) throw new Error("That picture could not be prepared.");
  const bytes = new Uint8Array(await blob.arrayBuffer());
  let bin = "";
  for (let i = 0; i < bytes.length; i += 8192) bin += String.fromCharCode(...bytes.subarray(i, i + 8192));
  return btoa(bin);
}

// The art and the words for a report header. With no brand saved, HashCam's own.
function forReport() {
  const brand = read();
  const own = window.HCReportArt;
  const art = {
    logo: brand.logo ? { w: 144, h: 144, b64: brand.logo } : own.logo,
    mark: brand.mark ? { w: 480, h: 480, b64: brand.mark } : own.mark,
  };
  return { name: brand.name, art, whiteLabel: Boolean(brand.name || brand.logo) };
}

window.HCBrand = { read, write, clear, cleanName, logoFromFile, forReport, NAME_MAX };
})();
