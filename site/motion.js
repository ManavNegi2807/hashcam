// The site's motion, with no animation library. A classic script (works from a file:// page).
//
// One easing everywhere: an expo-out deceleration (fast start, long soft landing). Only transform,
// opacity and stroke-dashoffset are animated, so it runs on the compositor and causes no layout
// shift. Every piece has a still version under prefers-reduced-motion.
//
//   HCMotion.settle(node, text)        a digest scrambles through hex and locks left to right
//   HCMotion.hexify(node, text, key)   the same for every run of 8+ hex characters inside a sentence
//   HCMotion.reveal()                  staggered entrance for [data-reveal] elements
//   HCMotion.pointer()                 --mouse-x / --mouse-y on the hovered card and on the hero
//   HCMotion.tabs(selector)            a sliding underline under the selected tab
//   HCMotion.hero(heroElement)         the telemetry core, in place of the old REC circle
//   HCMotion.riskyStep(host)           "A risky step, from start to seal"
(function () {
"use strict";

const EASE = "cubic-bezier(0.16, 1, 0.3, 1)";
const NS = "http://www.w3.org/2000/svg";
const HEX = "0123456789abcdef";
const calm = () => matchMedia("(prefers-reduced-motion: reduce)").matches;
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function svg(tag, attrs, ...kids) {
  const node = document.createElementNS(NS, tag);
  for (const k of Object.keys(attrs || {})) node.setAttribute(k, String(attrs[k]));
  for (const kid of kids) if (kid != null) node.append(kid instanceof Node ? kid : String(kid));
  return node;
}
const go = (node, keyframes, options) => node.animate(keyframes, Object.assign({ easing: EASE, fill: "both" }, options));

// ------------------------------------------------------------------ hex-decode scramble

const running = new WeakMap();
const seen = new Map(); // key -> the digest last shown there, so an unchanged one does not replay

// Scramble `text` into `node` over about 320ms: every position shows a random hex digit until the
// scramble reaches it, then locks to the real one, left to right. Characters that are not hex
// (a "…", a space, a hyphen) are never scrambled. Under reduced motion it is set at once.
function settle(node, text) {
  text = String(text);
  const earlier = running.get(node);
  if (earlier) cancelAnimationFrame(earlier);
  if (calm() || !text) {
    node.textContent = text;
    running.delete(node);
    return Promise.resolve();
  }
  node.textContent = text; // the real value is in place before anything else (and for no-script readers)
  const chars = Array.from(text);
  const started = performance.now();
  const duration = 320;
  return new Promise((resolve) => {
    const frame = (now) => {
      const p = Math.min(1, (now - started) / duration);
      const locked = Math.floor(p * chars.length);
      let out = "";
      for (let i = 0; i < chars.length; i++) {
        out += i < locked || !/[0-9a-f]/i.test(chars[i]) ? chars[i] : HEX[(Math.random() * 16) | 0];
      }
      node.textContent = out;
      if (p < 1) {
        running.set(node, requestAnimationFrame(frame));
      } else {
        node.textContent = text;
        running.delete(node);
        resolve();
      }
    };
    running.set(node, requestAnimationFrame(frame));
  });
}

// `text` may be a sentence with digests in it ("it now works out to 3cea39527e00…"). Every run of
// eight or more hex characters becomes its own span and is scrambled only if it differs from what
// that place showed last time (`key` names the place).
function hexify(node, text, key) {
  text = String(text);
  node.textContent = "";
  const parts = text.split(/([0-9a-f]{8,64})/i);
  let n = 0;
  parts.forEach((part, i) => {
    if (i % 2 === 0) {
      if (part) node.append(document.createTextNode(part));
      return;
    }
    const span = document.createElement("span");
    span.className = "hex";
    node.append(span);
    const place = key + ":" + n++;
    if (seen.get(place) === part) span.textContent = part;
    else { seen.set(place, part); settle(span, part); }
  });
}

// ------------------------------------------------------------------ staggered entrance reveals

// Elements marked data-reveal start hidden (see motion.css) and, as they scroll into view, rise 14px
// and fade in with a 60ms stagger between those that arrive together.
function reveal() {
  const items = Array.from(document.querySelectorAll("[data-reveal]"));
  if (!items.length) return;
  if (calm() || !("IntersectionObserver" in window)) {
    for (const item of items) item.classList.add("in");
    return;
  }
  const io = new IntersectionObserver((entries) => {
    entries.filter((e) => e.isIntersecting).forEach((entry, rank) => {
      const item = entry.target;
      io.unobserve(item);
      item.classList.add("in");
      go(item, [{ opacity: 0, transform: "translateY(14px) scale(0.985)" }, { opacity: 1, transform: "none" }],
        { duration: 760, delay: Math.min(rank, 8) * 60, fill: "backwards" });
    });
  }, { rootMargin: "0px 0px -6% 0px", threshold: 0.06 });
  items.forEach((item) => io.observe(item));
}

// ------------------------------------------------------------------ cursor-tracking light

// One listener for the whole page. The pointer's place inside the card under it, and inside the hero,
// goes into --mouse-x / --mouse-y (in px) for the CSS to draw with.
function pointer() {
  if (calm()) return;
  let frame = 0;
  let last = null;
  const apply = () => {
    frame = 0;
    const e = last;
    const card = e.target && e.target.closest ? e.target.closest(".panel, .card, .spot") : null;
    if (card) {
      const r = card.getBoundingClientRect();
      card.style.setProperty("--mouse-x", e.clientX - r.left + "px");
      card.style.setProperty("--mouse-y", e.clientY - r.top + "px");
    }
    const hero = document.querySelector(".hero");
    if (hero) {
      const r = hero.getBoundingClientRect();
      if (e.clientY >= r.top && e.clientY <= r.bottom) {
        hero.style.setProperty("--mouse-x", e.clientX - r.left + "px");
        hero.style.setProperty("--mouse-y", e.clientY - r.top + "px");
      }
    }
  };
  addEventListener("pointermove", (e) => {
    last = e;
    if (!frame) frame = requestAnimationFrame(apply);
  }, { passive: true });
}

// ------------------------------------------------------------------ tabs with a sliding underline

function tabs(selector) {
  for (const list of document.querySelectorAll(selector)) {
    const bar = document.createElement("span");
    bar.className = "tab-ind";
    bar.setAttribute("aria-hidden", "true");
    list.append(bar);
    const place = () => {
      const tab = list.querySelector('[aria-selected="true"]');
      if (!tab) return;
      bar.style.setProperty("--x", tab.offsetLeft + "px");
      bar.style.setProperty("--s", String(tab.offsetWidth / 100));
    };
    place();
    new MutationObserver(place).observe(list, { subtree: true, attributes: true, attributeFilter: ["aria-selected"] });
    if ("ResizeObserver" in window) new ResizeObserver(place).observe(list);
    addEventListener("resize", place);
  }
}

// ------------------------------------------------------------------ the telemetry core (hero)

function arc(cx, cy, r, from, to, cls) {
  const at = (a) => [cx + r * Math.cos(a), cy + r * Math.sin(a)];
  const [x0, y0] = at(from);
  const [x1, y1] = at(to);
  const large = to - from > Math.PI ? 1 : 0;
  return svg("path", { class: cls, d: `M${x0.toFixed(2)} ${y0.toFixed(2)} A${r} ${r} 0 ${large} 1 ${x1.toFixed(2)} ${y1.toFixed(2)}`, pathLength: 100 });
}

// Hairline rings turning slowly in opposite directions, data-bus arcs whose dashes travel round
// them, and a REC indicator with a soft breathing glow, on a dark glass panel. Each moving part is
// its own layer so the browser turns whole layers instead of repainting an SVG every frame.
function core(host) {
  const C = 180;
  const stage = document.createElement("div");
  stage.className = "core-stage";
  const layer = (cls, ...kids) => {
    const root = svg("svg", { viewBox: "0 0 360 360", class: "core-svg", "aria-hidden": "true", focusable: "false" }, ...kids);
    const div = document.createElement("div");
    div.className = "core-layer " + cls;
    div.append(root);
    stage.append(div);
  };
  const ring = (r, cls) => svg("circle", { cx: C, cy: C, r, class: cls });
  layer("core-turn core-cw", ring(156, "core-hair"), ring(140, "core-ticks"), ring(118, "core-hair"));
  layer("core-turn core-ccw", ring(96, "core-dashes"), ring(76, "core-hair"));
  layer("core-bus",
    svg("defs", {}, svg("linearGradient", { id: "coreBus", x1: 0, y1: 0, x2: 1, y2: 1 },
      svg("stop", { offset: 0, "stop-color": "#38BDF8", "stop-opacity": 1 }),
      svg("stop", { offset: 1, "stop-color": "#38BDF8", "stop-opacity": 0.15 }))),
    arc(C, C, 156, -0.4, 2.6, "core-arc"), arc(C, C, 118, 2.4, 5.2, "core-arc core-arc-b"), arc(C, C, 96, 0.9, 3.4, "core-arc core-arc-c"));
  const glow = document.createElement("div");
  glow.className = "core-rec-glow";
  stage.append(glow);
  layer("core-hub",
    ring(48, "core-hub-ring"),
    svg("circle", { cx: 152, cy: 180, r: 4.5, class: "core-rec-dot" }),
    svg("text", { x: 163, y: 185, class: "core-rec-text" }, "REC"),
    svg("g", { class: "core-labels" },
      svg("text", { x: C, y: 22, "text-anchor": "middle" }, "SHA-256"),
      svg("text", { x: C, y: 345, "text-anchor": "middle" }, "ED25519")));
  host.append(stage);
}

// ------------------------------------------------------------------ the hero field

// A fine hairline grid that dissolves toward its edges: a still backdrop (it replaced the retro rolling
// perspective floor). The motion in the hero is the flight record below.
function field() {
  const root = document.createElement("div");
  root.className = "hero-field";
  root.setAttribute("aria-hidden", "true");
  const grid = document.createElement("div");
  grid.className = "hf-grid";
  root.append(grid);
  return root;
}

// ------------------------------------------------------------------ the flight record (hero)

// The site's story in one strip: the recorder (the REC core) writes each thing an agent does onto a
// tape as a small card (what happened in plain words, its kind, and its hash chained to the one before),
// and the tape drifts away like a chart recorder's paper. The hashes are real SHA-256: each is the hash
// of the one before it plus the words on its card. Only transform and opacity animate.
const RECORD = [
  ["ALLOWED", "cyan", "Opened shop.example/checkout"],
  ["SECRET", "violet", "Typed a password \u00b7 value withheld"],
  ["HELD", "gold", "Wants to send a form \u00b7 waiting for you"],
  ["SIGNED", "gold", "Approved with a passkey"],
  ["BLOCKED", "rose", "Stopped from opening bank.example"],
  ["SEALED", "paper", "Receipt sealed, signed, checkable offline"],
];
const TAPE_MS = 17000; // how long a card takes to drift away
const EVERY_MS = 2800; // a new card this often

const make = (tag, cls, text) => {
  const node = document.createElement(tag);
  node.className = cls;
  if (text != null) node.textContent = text;
  return node;
};

// Cards #1 and #2 are written silently when the page opens, so the first card on screen is #3 (the tail of
// the story) and the agent's own first step lands as #7: card number n always tells RECORD[(n - 1) % 6].
function recorder(host) {
  const root = make("div", "hero-record");
  root.setAttribute("aria-hidden", "true");
  const bolt = make("i", "");
  const strip = make("div", "rc-strip");
  const head = make("div", "rc-head");
  strip.append(make("div", "rc-line"), head);
  root.append(make("div", "rc-link"), strip);
  root.firstChild.append(bolt);
  host.append(root);

  let previous = "0".repeat(64);
  let count = 0;
  const live = new Set();
  let shown = true;
  const history = (async () => {
    for (const [, , words] of RECORD.slice(0, 2)) {
      previous = await digestOf(previous + words);
      count += 1;
    }
  })();
  const card = async (index, { age = 0, at = null } = {}) => {
    const [kind, tone, words] = RECORD[index];
    count += 1;
    const number = count;
    previous = await digestOf(previous + words);
    const x = head.offsetLeft + head.offsetWidth / 2;
    const chip = make("div", `rc-chip ${number % 2 ? "up" : "down"} tone-${tone}`);
    chip.style.left = (at == null ? x : at) + "px";
    const hash = make("span", "hex");
    const box = make("div", "rc-card");
    const top = make("span", "");
    top.append(make("b", "rc-kind", kind), make("span", "rc-words", words));
    const low = make("span", "rc-hash", `#${number} · `);
    low.append(hash);
    box.append(top, low);
    chip.append(make("i", "rc-stem"), make("i", "rc-dot"), box);
    strip.append(chip);
    if (at != null) { // the still version: laid out, not moving
      chip.style.opacity = "1";
      hash.textContent = previous.slice(0, 8);
      return;
    }
    const travel = x + 340;
    const run = chip.animate([
      { transform: "translateX(0)", opacity: 0, offset: 0 },
      { opacity: 1, offset: 0.04 },
      { opacity: 1, offset: 0.7 },
      { transform: `translateX(${-travel}px)`, opacity: 0, offset: 1 },
    ], { duration: TAPE_MS, easing: "linear", fill: "both" });
    if (age) { run.currentTime = age; hash.textContent = previous.slice(0, 8); } else settle(hash, previous.slice(0, 8));
    live.add(run);
    if (!shown) run.pause(); // written while the hero is out of view: it waits
    run.finished.then(() => { live.delete(run); chip.remove(); }, () => { /* cancelled */ });
  };
  let queue = Promise.resolve();
  const place = (index, options) => {
    queue = queue.then(() => history).then(() => card(index, options));
    return queue;
  };

  if (calm()) {
    const x = head.offsetLeft + head.offsetWidth / 2;
    [2, 3, 4, 5].forEach((index, i) => place(index, { at: x - (3 - i) * 210 }));
  } else {
    [2, 3, 4, 5].forEach((index, i) => place(index, { age: (3 - i) * 2800 + 600 }));
  }
  return {
    // the agent did something: a pulse runs from the recorder down to the tape, and a card is written
    emit(index) {
      go(bolt, [{ transform: "translateY(-100%)", opacity: 0 }, { opacity: 1, offset: 0.25 }, { transform: "translateY(260%)", opacity: 0 }], { duration: 650, fill: "none" });
      setTimeout(() => place(index), 480);
    },
    setVisible(on) {
      shown = on;
      live.forEach((a) => (on ? a.play() : a.pause()));
    },
  };
}

// ------------------------------------------------------------------ the agent being recorded (hero)

// A small browser window in a viewfinder, with REC and a timecode: an AI agent opens a shop's checkout, fills
// a form, is held for a passkey, is stopped at a site it may not use, and gets its receipt sealed. Each step
// writes its card onto the tape (see recorder) at the moment it happens. It is a scripted illustration.
const SCENE_URL = { shop: "shop.example/checkout", bank: "bank.example/transfer" };

function agent(panel, tape, host) {
  const root = make("div", "agent");
  root.setAttribute("aria-hidden", "true");
  const time = make("span", "ag-time", "00:00");
  const rec = make("span", "ag-rec");
  rec.append(make("i", ""), document.createTextNode("REC"));
  const top = make("div", "ag-top");
  top.append(rec, time, make("span", "ag-tag", "AGENT · BROWSER"));
  const bar = make("div", "ag-bar");
  const url = make("span", "ag-url", "");
  bar.append(make("i", ""), make("i", ""), make("i", ""), url);
  const field = (label) => {
    const box = make("div", "ag-field");
    const value = make("span", "ag-val", "");
    box.append(make("b", "", label), value);
    return [box, value];
  };
  const [emailBox, email] = field("Email");
  const [passwordBox, password] = field("Password");
  const lock = make("em", "ag-lock", "WITHHELD");
  passwordBox.append(lock);
  const button = make("div", "ag-btn", "Place order");
  const ripple = make("i", "ag-ripple");
  const ring = svg("svg", { viewBox: "0 0 24 24", class: "ag-ring", focusable: "false" },
    svg("circle", { class: "track", cx: 12, cy: 12, r: 9 }), svg("circle", { class: "arc", cx: 12, cy: 12, r: 9, pathLength: 1 }));
  const said = make("span", "", "");
  const over = make("div", "ag-over");
  over.append(ring, said);
  const cursor = svg("svg", { viewBox: "0 0 14 18", class: "ag-cursor", focusable: "false" },
    svg("path", { d: "M1.5 1.5v13l3.4-3.1 2.3 5 2.2-1-2.3-4.9H12z", fill: "#F1F5F9", stroke: "#080B12", "stroke-width": 1, "stroke-linejoin": "round" }));
  const page = make("div", "ag-page");
  page.append(emailBox, passwordBox, button, ripple, over, cursor);
  const win = make("div", "ag-win");
  win.append(bar, page);
  root.append(top, win, ...["tl", "tr", "bl", "br"].map((k) => make("i", `ag-br ${k}`)));
  panel.append(root);
  panel.classList.add("with-agent"); // the window stands where the core's own REC text was

  const fmt = (n) => `${String(Math.floor(n / 60)).padStart(2, "0")}:${String(n % 60).padStart(2, "0")}`;
  const say = (kind, text) => { over.className = `ag-over on ${kind}`; said.textContent = text; };
  const clear = () => { over.className = "ag-over"; };

  if (calm()) { // one still frame: the agent, recorded, with its last step approved
    url.textContent = SCENE_URL.shop;
    email.textContent = "agent@demo.test";
    password.textContent = "•".repeat(9);
    lock.classList.add("on");
    page.classList.add("on");
    time.textContent = fmt(7);
    say("ok", "Approved with your passkey");
    ring.querySelector(".arc").style.strokeDashoffset = "0";
    return;
  }

  let visible = true;
  let seconds = 0;
  const gate = async (ms) => {
    await sleep(ms);
    while (!visible) await sleep(300);
  };
  const type = async (node, text, ms) => {
    node.textContent = "";
    for (const ch of text) {
      node.textContent += ch;
      await gate(ms);
    }
  };
  let at = { x: 16, y: 150 };
  const move = async (target) => {
    const to = { x: target.offsetLeft + target.offsetWidth * 0.32, y: target.offsetTop + target.offsetHeight * 0.55 };
    const run = cursor.animate([{ transform: `translate(${at.x}px, ${at.y}px)` }, { transform: `translate(${to.x}px, ${to.y}px)` }], { duration: 760, easing: EASE, fill: "forwards" });
    await run.finished;
    cursor.style.transform = `translate(${to.x}px, ${to.y}px)`;
    run.cancel();
    at = to;
  };
  const click = () => {
    ripple.style.left = at.x + "px";
    ripple.style.top = at.y + "px";
    go(ripple, [{ transform: "scale(.3)", opacity: 0.9 }, { transform: "scale(2.6)", opacity: 0 }], { duration: 650, fill: "none" });
    button.classList.add("press");
    setTimeout(() => button.classList.remove("press"), 180);
  };
  let spin = null;
  const reset = () => {
    url.textContent = "";
    email.textContent = "";
    password.textContent = "";
    lock.classList.remove("on");
    page.classList.remove("on");
    clear();
    if (spin) spin.cancel();
    seconds = 0;
    time.textContent = fmt(0);
    at = { x: 16, y: 150 };
    cursor.style.transform = `translate(${at.x}px, ${at.y}px)`;
  };
  async function loop() {
    for (;;) {
      reset();
      cursor.style.opacity = "1";
      await gate(600);
      await type(url, SCENE_URL.shop, 42);
      page.classList.add("on");
      tape.emit(0);
      await gate(900);
      await move(emailBox);
      await type(email, "agent@demo.test", 48);
      await gate(350);
      await move(passwordBox);
      await type(password, "•".repeat(9), 70);
      lock.classList.add("on");
      tape.emit(1);
      await gate(800);
      await move(button);
      click();
      say("held", "Held · waiting for your passkey");
      spin = go(ring.querySelector(".arc"), [{ strokeDashoffset: 1 }, { strokeDashoffset: 0 }], { duration: 1500, easing: "linear" });
      tape.emit(2);
      await gate(1900);
      say("ok", "Approved with your passkey");
      tape.emit(3);
      await gate(1500);
      clear();
      await type(url, SCENE_URL.bank, 38);
      page.classList.remove("on");
      say("blocked", "Not on this agent’s passport");
      tape.emit(4);
      await gate(1900);
      say("sealed", "Receipt sealed");
      tape.emit(5);
      await gate(2400);
      clear();
    }
  }

  new IntersectionObserver((entries) => {
    visible = entries.some((e) => e.isIntersecting);
    tape.setVisible(visible);
  }, { threshold: 0.05 }).observe(host);
  setInterval(() => {
    if (!visible) return;
    seconds += 1;
    time.textContent = fmt(seconds);
  }, 1000);
  const wide = matchMedia("(min-width: 761px)");
  let started = false;
  const start = () => {
    if (!started && wide.matches) { started = true; loop(); }
  };
  start();
  wide.addEventListener("change", start);
}

function hero(host) {
  if (!host) return;
  const sky = host.querySelector(".synth-sky");
  if (sky) {
    const sun = sky.querySelector(".synth-sun");
    if (sun) sun.remove(); // the retro REC circle gives way to the core
    const spot = document.createElement("div");
    spot.className = "synth-spot";
    sky.append(field(), spot);
  }
  const holder = document.createElement("div");
  holder.className = "hero-core spot";
  holder.id = "core";
  host.append(holder);
  core(holder);
  agent(holder, recorder(host), host);
}

// ------------------------------------------------------------------ "A risky step, from start to seal"

async function digestOf(text) {
  try {
    const bytes = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
    return Array.from(new Uint8Array(bytes), (b) => b.toString(16).padStart(2, "0")).join("");
  } catch (_) {
    return "9f2c4a6e81b3d507";
  }
}

const STEPS = [
  "The agent asks to submit an order form.",
  "The gateway checks the rules: spending money needs a person.",
  "You hold your finger on the passkey. Only then is your key used.",
  "The step is sealed into a receipt anyone can check offline.",
];

// agent -> policy gateway -> passkey gate -> sealed receipt. A packet pulse travels each rail by
// animating stroke-dashoffset; the passkey hold fills a circular ring; an emerald seal snaps in; the
// receipt's real SHA-256 scrambles into place.
function riskyStep(host) {
  host.textContent = "";
  const Y = 96;
  const X = [88, 280, 480, 672];
  const L = 2 * Math.PI * 21; // the ring's circumference
  const root = svg("svg", { viewBox: "0 0 760 220", class: "flow", role: "img",
    "aria-label": "From left to right: an AI agent, the policy gateway, the passkey gate and the sealed receipt." });
  const names = ["AI agent", "Policy gateway", "Passkey gate", "Sealed receipt"];
  const nodes = X.map((x, i) => {
    const g = svg("g", { class: "flow-node" },
      svg("rect", { class: "flow-box", x: x - 66, y: Y - 44, width: 132, height: 88, rx: 14 }),
      svg("rect", { class: "flow-glow", x: x - 66, y: Y - 44, width: 132, height: 88, rx: 14 }),
      svg("text", { class: "flow-name", x, y: Y + 66, "text-anchor": "middle" }, names[i]));
    root.append(g);
    return g;
  });
  // The rails and the packets that ride them.
  const packets = [];
  const halos = [];
  for (let i = 0; i < 3; i++) {
    const d = `M${X[i] + 66} ${Y} H${X[i + 1] - 66}`;
    root.append(svg("path", { class: "flow-rail", d }));
    const halo = svg("path", { class: "flow-halo", d, pathLength: 100 });
    const packet = svg("path", { class: "flow-packet", d, pathLength: 100 });
    root.append(halo, packet);
    halos.push(halo);
    packets.push(packet);
  }
  // Agent: a small terminal head.
  nodes[0].append(svg("rect", { class: "flow-ico", x: X[0] - 15, y: Y - 17, width: 30, height: 24, rx: 6 }),
    svg("path", { class: "flow-ico", d: `M${X[0] - 7} ${Y - 9} l5 4 -5 4 M${X[0] + 2} ${Y + 1} h7` }));
  // Gateway: a shield.
  nodes[1].append(svg("path", { class: "flow-ico", d: `M${X[1]} ${Y - 20} l16 6 v10 c0 11 -8 17 -16 21 c-8 -4 -16 -10 -16 -21 v-10 z` }),
    svg("path", { class: "flow-ico", d: `M${X[1] - 6} ${Y - 2} l4 4 8 -8` }));
  // Passkey gate: a track, the hold ring, a fingerprint, the seal and its tick.
  const track = svg("circle", { class: "flow-track", cx: X[2], cy: Y - 4, r: 21 });
  const ring = svg("circle", { class: "flow-ring", cx: X[2], cy: Y - 4, r: 21 });
  ring.style.strokeDasharray = String(L);
  ring.style.strokeDashoffset = String(L);
  const finger = svg("path", { class: "flow-ico thin",
    d: `M${X[2] - 9} ${Y} q9 -17 18 0 M${X[2] - 5} ${Y + 3} q5 -11 10 0 M${X[2] - 1} ${Y + 5} v-8` });
  const seal = svg("g", { class: "flow-seal" },
    svg("circle", { cx: X[2], cy: Y - 4, r: 21, class: "flow-seal-disc" }),
    svg("path", { class: "flow-tick", d: `M${X[2] - 9} ${Y - 3} l6 6 12 -13`, pathLength: 1 }));
  const state = svg("text", { class: "flow-state", x: X[2], y: Y + 32, "text-anchor": "middle" }, "");
  nodes[2].append(track, ring, finger, seal, state);
  // Receipt: a sheet that draws itself, and its digest.
  const sheet = svg("path", { class: "flow-ico flow-sheet", pathLength: 1,
    d: `M${X[3] - 15} ${Y - 24} h20 l10 10 v32 h-30 z M${X[3] + 5} ${Y - 24} v10 h10` });
  // "sha256 " stays put; only the digest after it scrambles (the label has hex-looking letters).
  const hashLabel = svg("tspan", {}, "");
  const hash = svg("tspan", { class: "hex" }, "");
  nodes[3].append(sheet, svg("text", { class: "flow-hash", x: X[3], y: Y + 32, "text-anchor": "middle" }, hashLabel, hash));
  host.append(root);

  const list = document.createElement("ol");
  list.className = "flow-steps";
  const items = STEPS.map((text) => {
    const li = document.createElement("li");
    li.textContent = text;
    list.append(li);
    return li;
  });
  const replay = document.createElement("button");
  replay.type = "button";
  replay.className = "btn small ghost flow-replay";
  replay.textContent = "Replay";
  host.append(list, replay);

  let run = 0;
  let proof = "";
  const mark = (i) => {
    nodes[i].classList.add("on");
    items.forEach((li, n) => { li.classList.toggle("on", n === i); li.classList.toggle("done", n < i); });
  };
  const clear = () => {
    nodes.forEach((n) => n.classList.remove("on", "ok"));
    items.forEach((li) => li.classList.remove("on", "done"));
    for (const node of [...packets, ...halos, ring, seal, sheet, hash, state]) node.getAnimations().forEach((a) => a.cancel());
    ring.style.strokeDashoffset = String(L);
    state.textContent = "";
    hashLabel.textContent = "";
    settle(hash, ""); // also stops a scramble still running from the last play
  };
  const still = async () => {
    clear();
    nodes.forEach((n) => n.classList.add("on"));
    nodes[2].classList.add("ok");
    ring.style.strokeDashoffset = "0";
    seal.style.opacity = "1";
    seal.querySelector(".flow-tick").style.strokeDashoffset = "0";
    sheet.style.strokeDashoffset = "0";
    state.textContent = "AUTHORIZED";
    hashLabel.textContent = "sha256 ";
    hash.textContent = (proof || (await digestOf(STEPS.join(" ")))).slice(0, 16);
    items.forEach((li, n) => { li.classList.toggle("on", n === 3); li.classList.toggle("done", n < 3); });
  };
  const hop = (i) => Promise.all([halos[i], packets[i]].map((node) => go(node, [
    { strokeDashoffset: 14, opacity: 0 }, { opacity: 1, offset: 0.2 }, { opacity: 1, offset: 0.8 }, { strokeDashoffset: -100, opacity: 0 },
  ], { duration: 680 }).finished));

  async function play() {
    if (calm()) { await still(); return; }
    const me = ++run;
    const alive = () => me === run;
    clear();
    proof = proof || (await digestOf(STEPS.join(" ")));
    if (!alive()) return;
    mark(0); await sleep(320); if (!alive()) return;
    await hop(0); if (!alive()) return;
    mark(1); await sleep(380); if (!alive()) return;
    await hop(1); if (!alive()) return;
    mark(2);
    state.textContent = "HELD";
    await go(ring, [{ strokeDashoffset: L }, { strokeDashoffset: 0 }], { duration: 1500, easing: "cubic-bezier(0.65, 0, 0.35, 1)" }).finished;
    if (!alive()) return;
    state.textContent = "AUTHORIZED";
    nodes[2].classList.add("ok");
    go(seal, [{ opacity: 0, transform: "scale(1.5)" }, { opacity: 1, transform: "scale(1)" }], { duration: 340 });
    go(seal.querySelector(".flow-tick"), [{ strokeDashoffset: 1 }, { strokeDashoffset: 0 }], { duration: 420, delay: 80 });
    await sleep(520); if (!alive()) return;
    await hop(2); if (!alive()) return;
    mark(3);
    go(sheet, [{ strokeDashoffset: 1 }, { strokeDashoffset: 0 }], { duration: 640 });
    hashLabel.textContent = "sha256 ";
    settle(hash, proof.slice(0, 16));
    nodes[3].classList.add("ok");
  }

  replay.addEventListener("click", play);
  if (calm()) { replay.hidden = true; still(); }
  return { play };
}

// ------------------------------------------------------------------ start

function init() {
  reveal();
  pointer();
}

window.HCMotion = { EASE, settle, hexify, reveal, pointer, tabs, hero, riskyStep, init, calm };
})();
