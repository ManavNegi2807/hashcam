// HashCam's animation styles. Each has one job, and each has a still version for people who
// ask for reduced motion: the still version shows the same facts, never less.
//
// Nothing here decides anything. The verdict, statuses and counts drawn come from the verifier
// and the recorder; these functions only draw them.

const NS = "http://www.w3.org/2000/svg";
const gsap = () => window.gsap;
export const calm = () => matchMedia("(prefers-reduced-motion: reduce)").matches;

// Motion without a library: the Web Animations API with ONE easing everywhere, an expo-out
// deceleration (fast start, long soft landing). Only transform, opacity and stroke-dashoffset are
// animated, so it all runs on the compositor. The cartoon and signFormula below still use GSAP where
// the console and the extension load it; the site does not.
export const EASE = "cubic-bezier(0.16, 1, 0.3, 1)";
const go = (node, keyframes, options) => node.animate(keyframes, { easing: EASE, fill: "both", ...options });
// A digest that changed: the site's HCMotion scrambles it into place; elsewhere it is just set.
const settle = (node, text) => {
  if (window.HCMotion && window.HCMotion.settle) window.HCMotion.settle(node, text);
  else node.textContent = text;
};

function el(tag, attrs = {}, ...kids) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k === "style") node.style.cssText = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  for (const kid of kids) if (kid != null) node.append(kid instanceof Node ? kid : String(kid));
  return node;
}
function svg(tag, attrs = {}, ...kids) {
  const node = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, String(v));
  for (const kid of kids) if (kid != null) node.append(kid instanceof Node ? kid : String(kid));
  return node;
}

// Run `play` only while `node` is on screen (and the tab is visible); call `stop` otherwise.
export function whileVisible(node, play, stop) {
  let on = false;
  const set = (visible) => {
    if (visible && !on && !document.hidden) { on = true; play(); }
    else if ((!visible || document.hidden) && on) { on = false; stop(); }
  };
  const io = new IntersectionObserver((entries) => set(entries.some((e) => e.isIntersecting)));
  io.observe(node);
  document.addEventListener("visibilitychange", () => set(!document.hidden && node.getBoundingClientRect().bottom > 0));
  return () => io.disconnect();
}

// ===================================================================== 4. SYNTHWAVE (hero)
// A horizon grid rolling toward you, the REC light rising like a sun. Low intensity.
export function synthwave(host) {
  host.classList.add("synth");
  host.prepend(
    el("div", { class: "synth-sky", "aria-hidden": "true" },
      el("div", { class: "synth-sun" }, el("span", {}, "REC")),
      el("div", { class: "synth-grid" })),
  );
  if (calm()) { host.classList.add("still"); return; }
  whileVisible(host, () => host.classList.remove("paused"), () => host.classList.add("paused"));
}

// ===================================================================== 1. THE PATH OF AN ACTION (how it works)
// agent -> policy gateway -> ledger -> separate signer -> receipt: five cards joined by hairline rails.
// A light pulse travels the rails; every third request is refused at the gateway and goes no further.
// Only transform and opacity animate. (Cards turn into a column on a narrow screen.)
const STAGES = [
  { name: "AI agent", says: "Asks to do something.", tone: "cyan", chips: [["REQUEST"]],
    icon: [["rect", { x: 3, y: 4, width: 18, height: 16, rx: 3 }], ["path", { d: "M7 9.5l3 2.5-3 2.5M13 15h4" }]] },
  { name: "Policy gateway", says: "Checks it against your rules.", tone: "gold", chips: [["ALLOW"], ["DENY", "bad"]],
    icon: [["path", { d: "M12 3l7 3v5.2c0 4.6-3 7.8-7 9.8-4-2-7-5.2-7-9.8V6z" }], ["path", { d: "M9 12l2 2 4-4.2" }]] },
  { name: "Ledger", says: "Writes it into a chain no one can quietly edit.", tone: "cyan", chips: [["SHA-256 CHAIN"]],
    icon: [["rect", { x: 4, y: 4, width: 16, height: 4, rx: 1.5 }], ["rect", { x: 4, y: 10, width: 16, height: 4, rx: 1.5 }], ["rect", { x: 4, y: 16, width: 16, height: 4, rx: 1.5 }]] },
  { name: "Separate signer", says: "Signs the chain. Its key never leaves it.", tone: "gold", chips: [["ED25519"]],
    icon: [["circle", { cx: 8, cy: 12, r: 3.5 }], ["path", { d: "M11.5 12H21M17.5 12v3M20.5 12v2" }]] },
  { name: "Receipt", says: "Anyone can check it, offline.", tone: "paper", chips: [["VERIFIABLE"]],
    icon: [["path", { d: "M6 3h8.5L18 6.5V21H6z" }], ["path", { d: "M9 10h6M9 13.5h6M9 17h3.5" }]] },
];

export function pipeline(host) {
  host.textContent = "";
  const root = el("div", { class: "pipe", role: "group",
    "aria-label": "The path of every action: the AI agent asks, the policy gateway checks the request against your rules, the ledger writes it into a hash chain, a separate signer signs the chain, and a receipt anyone can check offline is sealed. A refused request stops at the gateway and the refusal is still recorded." });
  const nodes = [];
  const rails = [];
  STAGES.forEach((stage, i) => {
    const icon = svg("svg", { viewBox: "0 0 24 24", class: "pn-ico", "aria-hidden": "true", focusable: "false" },
      ...stage.icon.map(([tag, attrs]) => svg(tag, attrs)));
    const chips = el("div", { class: "pn-chips" },
      ...stage.chips.map(([text, tone]) => el("span", { class: `pn-chip${tone ? " " + tone : ""}` }, text)));
    const node = el("div", { class: `pipe-node spot tone-${stage.tone}` },
      el("span", { class: "pn-idx", "aria-hidden": "true" }, `0${i + 1}`), icon,
      el("b", { class: "pn-title" }, stage.name), el("span", { class: "pn-cap" }, stage.says), chips);
    nodes.push(node);
    root.append(node);
    if (i < STAGES.length - 1) {
      const pulse = el("span", { class: "pipe-pk" });
      root.append(el("div", { class: "pipe-rail", "aria-hidden": "true" }, pulse));
      rails.push(pulse);
    }
  });
  host.append(root);
  if (calm()) { nodes.forEach((n) => n.classList.add("on")); return; }

  const chipOf = (node, index = 0) => node.querySelectorAll(".pn-chip")[index];
  const vertical = () => matchMedia("(max-width: 820px)").matches;
  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  const travel = (pulse) => go(pulse, vertical()
    ? [{ transform: "translateY(-100%)" }, { transform: "translateY(100%)" }]
    : [{ transform: "translateX(-100%)" }, { transform: "translateX(100%)" }], { duration: 600, fill: "none" }).finished;
  const light = (node, how = "on") => {
    node.classList.add(how);
    setTimeout(() => node.classList.remove(how), 1300);
  };
  const stamp = (chip) => {
    chip.classList.add("hit");
    go(chip, [{ transform: "scale(1)" }, { transform: "scale(1.12)" }, { transform: "scale(1)" }], { duration: 480, fill: "none" });
    setTimeout(() => chip.classList.remove("hit"), 1300);
  };
  let count = 0;
  let timer = null;
  const send = async () => {
    count += 1;
    const refused = count % 3 === 0;
    try {
      light(nodes[0]); stamp(chipOf(nodes[0]));
      await travel(rails[0]);
      light(nodes[1], refused ? "stop" : "on");
      stamp(chipOf(nodes[1], refused ? 1 : 0));
      if (refused) return; // refused: it goes no further
      for (let i = 1; i < rails.length; i++) {
        await sleep(160);
        await travel(rails[i]);
        light(nodes[i + 1]);
        stamp(chipOf(nodes[i + 1]));
      }
    } catch { /* cancelled with the page */ }
  };
  whileVisible(host, () => { send(); timer = setInterval(send, 3200); }, () => clearInterval(timer));
}

// ===================================================================== 2. PAPER-CUT (receipts)
// Each event prints in as a cut strip of paper.
export function printStrip(list, strip, { prepend = false } = {}) {
  strip.classList.add("strip");
  if (prepend) list.prepend(strip); else list.append(strip);
  if (calm()) return strip;
  go(strip, [{ opacity: 0, transform: "translateY(-10px) scale(0.985)" }, { opacity: 1, transform: "none" }], { duration: 560, fill: "none" });
  return strip;
}

// ===================================================================== 3. EVENTS PER SESSION (live)
// One stacked bar per session: allowed / approved / blocked / tripwire. Flat, precise, readable.
const SEGMENTS = [
  ["allowed", "Allowed"], ["approved", "Approved"], ["blocked", "Blocked or unsent"], ["tripwire", "Tripwire"],
];
export function eventBars(host, sessions) {
  const shown = sessions.slice(0, 8);
  const count = (s, k) => Number(s.counts[k]) || 0;
  const total = (s) => SEGMENTS.reduce((t, [k]) => t + count(s, k), 0);
  // The live view calls this on every refresh: draw (and animate) again only when the numbers changed.
  const signature = JSON.stringify(shown.map((s) => [s.agent, SEGMENTS.map(([k]) => count(s, k))]));
  if (host.dataset.signature === signature && host.firstChild) return;
  host.dataset.signature = signature;
  host.textContent = "";
  host.classList.add("ebars");
  if (!shown.length) {
    host.append(el("p", { class: "eb-empty muted" }, "No sessions yet."));
    return;
  }
  const max = Math.max(1, ...shown.map(total));
  const chart = el("div", { class: "eb", role: "img",
    "aria-label": "Events per session: " + shown.map((s) => `${s.agent}: ` + SEGMENTS.map(([k, n]) => `${count(s, k)} ${n.toLowerCase()}`).join(", ")).join("; ") });
  shown.forEach((s, i) => {
    const fill = el("div", { class: "eb-fill", style: `width:${(total(s) / max) * 100}%` });
    for (const [k, name] of SEGMENTS) {
      if (count(s, k) > 0) fill.append(el("span", { class: `eb-seg seg-${k}`, style: `flex:${count(s, k)} 1 0`, title: `${name}: ${count(s, k)}` }));
    }
    chart.append(el("div", { class: "eb-row" },
      el("span", { class: "eb-name", title: s.agent }, s.agent),
      el("div", { class: "eb-track" }, fill),
      el("span", { class: "eb-n" }, String(total(s)))));
    if (!calm()) go(fill, [{ transform: "scaleX(0)" }, { transform: "scaleX(1)" }], { duration: 800, delay: i * 70, fill: "backwards" });
  });
  const sums = SEGMENTS.map(([k]) => shown.reduce((t, s) => t + count(s, k), 0));
  host.append(chart, el("ul", { class: "eb-legend" },
    ...SEGMENTS.map(([k, n], i) => el("li", {}, el("i", { class: `seg-${k}` }), n, el("b", {}, String(sums[i]))))));
}

// ===================================================================== 5 + 6. 3D MERKLE TREE + MATHS
// Edit one leaf and watch every hash above it change, up to the signed root. The hashes are real
// SHA-256 values computed in the page; it is an illustration of the idea (abb/1 hashes canonical
// JSON with domain tags, so its numbers differ).
const LEAVES = ["RUN_STARTED", "PAGE shop.test", "SECRET password", "SUBMIT form", "APPROVED", "DISPATCHED", "PAGE /thanks", "RUN_FINISHED"];
async function sha(text) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function levelsOf(leaves) {
  const levels = [await Promise.all(leaves.map((t) => sha(t)))];
  while (levels.at(-1).length > 1) {
    const prev = levels.at(-1);
    const next = [];
    for (let i = 0; i < prev.length; i += 2) next.push(await sha(prev[i] + prev[i + 1]));
    levels.push(next);
  }
  return levels; // levels[0] = leaf hashes ... levels[3] = [root]
}

export function merkle(host, mathsHost) {
  const leaves = [...LEAVES];
  const W = 640;
  const stage = el("div", { class: "mk-stage" });
  const tree = el("div", { class: "mk-tree" });
  stage.append(tree);
  const edges = svg("svg", { class: "mk-edges", viewBox: `0 0 ${W} 394`, "aria-hidden": "true" });
  tree.append(edges);
  const nodes = []; // nodes[level][i]
  const posOf = (level, i) => {
    const count = 8 >> level;
    // The root sits 88px below the top, leaving a clear band for the signature pill above it
    // (it grows when the text changes to "no longer matches: INVALID", and tilts with the tree).
    return { x: (W / count) * (i + 0.5), y: 364 - level * 92 };
  };
  for (let level = 0; level < 4; level++) {
    nodes.push([]);
    for (let i = 0; i < 8 >> level; i++) {
      const { x, y } = posOf(level, i);
      const label = level === 3 ? "root" : level === 0 ? `h${i + 1}` : `h${level}.${i + 1}`;
      const node = el("div", { class: `mk-node lv${level}`, style: `left:${x}px;top:${y}px` },
        el("b", {}, label), el("code", {}, "…"));
      nodes[level].push(node);
      tree.append(node);
      if (level > 0) {
        for (const c of [2 * i, 2 * i + 1]) {
          const a = posOf(level - 1, c);
          edges.append(svg("line", { x1: x, y1: y + 18, x2: a.x, y2: a.y - 18, pathLength: 1, "data-to": `${level - 1}-${c}` }));
        }
      }
    }
  }
  const seal = el("div", { class: "mk-seal" }, "σ = Ed25519(root)");
  tree.append(seal);

  // Leaf editors, in plain HTML under the tree: keyboard and screen-reader friendly.
  const editors = el("div", { class: "mk-editors" },
    ...leaves.map((text, i) => el("label", {}, `e${i + 1}`,
      el("input", { value: text, "aria-label": `Event ${i + 1}`, oninput: (ev) => { leaves[i] = ev.target.value; refresh(i); } }))));
  const status = el("p", { class: "mk-status", "aria-live": "polite" }, "Edit any event below.");
  host.append(stage, editors, status);

  // The maths, drawn as steps that light up in sync with the tree (style 6).
  const steps = [
    ["hᵢ = SHA-256(eᵢ)", "each event is hashed"],
    ["hₗ.ₖ = SHA-256(left ‖ right)", "pairs are hashed again"],
    ["root = SHA-256(h₂.₁ ‖ h₂.₂)", "one hash covers the whole run"],
    ["σ = Ed25519_sign(signer key, root)", "the separate signer signs the root"],
    ["verify(σ, root′) = false  ⇒  INVALID", "an edited event changes root′, so the signature fails"],
  ];
  const maths = el("ol", { class: "maths", "aria-label": "The maths, step by step" },
    ...steps.map(([f, why]) => el("li", {}, el("span", { class: "f" }, f), el("span", { class: "why" }, why))));
  mathsHost.append(maths);

  let original = null;
  let current = null;
  const paint = () => {
    for (let level = 0; level < 4; level++) {
      nodes[level].forEach((node, i) => {
        const code = node.querySelector("code");
        const digest = current[level][i].slice(0, 8);
        if (code.textContent !== digest) settle(code, digest);
        node.classList.toggle("changed", current[level][i] !== original[level][i]);
      });
    }
    for (const line of edges.querySelectorAll("line")) {
      const [lv, c] = line.dataset.to.split("-").map(Number);
      line.classList.toggle("changed", current[lv][c] !== original[lv][c]);
    }
    const broken = current[3][0] !== original[3][0];
    seal.classList.toggle("broken", broken);
    seal.textContent = broken ? "σ no longer matches: INVALID" : "σ = Ed25519(root) ✓";
  };
  const lightSteps = (upTo) => {
    maths.querySelectorAll("li").forEach((li, i) => li.classList.toggle("lit", i <= upTo));
  };
  async function refresh(changedLeaf) {
    current = await levelsOf(leaves);
    if (!original) original = current;
    paint();
    const broken = current[3][0] !== original[3][0];
    status.textContent = broken
      ? `Event ${changedLeaf + 1} changed: its hash, every hash above it and the root changed. The signature was made over the old root, so a verifier says INVALID.`
      : "All hashes match what was signed.";
    if (calm() || changedLeaf == null) { lightSteps(broken ? 4 : 3); return; }
    // Climb the tree level by level: each node pulses, the edge above it draws up to its parent.
    let i = changedLeaf;
    for (let level = 0; level < 4; level++) {
      const node = nodes[level][i];
      const at = level * 150;
      setTimeout(() => lightSteps(Math.min(level, 2)), at);
      go(node, [{ scale: 1 }, { scale: 1.12 }, { scale: 1 }], { delay: at, duration: 460, fill: "none" });
      i = Math.floor(i / 2);
    }
    for (const line of edges.querySelectorAll("line.changed")) {
      const lv = Number(line.dataset.to.split("-")[0]);
      go(line, [{ strokeDashoffset: 1 }, { strokeDashoffset: 0 }], { delay: lv * 150 + 60, duration: 420, fill: "backwards" });
    }
    setTimeout(() => lightSteps(broken ? 4 : 3), 4 * 150 + 120);
  }
  refresh(null);

  // Rotate by dragging (or with the arrow keys).
  let angleY = -18;
  let angleX = 14;
  // The tree is drawn 640px wide; scale it to fit the panel it sits in.
  const fit = () => Math.min(1, (stage.clientWidth - 16) / W);
  const apply = () => {
    tree.style.transform = `scale(${fit()}) rotateX(${angleX}deg) rotateY(${angleY}deg)`;
  };
  apply();
  new ResizeObserver(apply).observe(stage);
  stage.tabIndex = 0;
  stage.setAttribute("aria-label", "Merkle tree. Drag or use the arrow keys to rotate.");
  let drag = null;
  stage.addEventListener("pointerdown", (e) => { drag = { x: e.clientX, y: e.clientY, ay: angleY, ax: angleX }; stage.setPointerCapture(e.pointerId); });
  stage.addEventListener("pointermove", (e) => {
    if (!drag) return;
    angleY = Math.max(-60, Math.min(60, drag.ay + (e.clientX - drag.x) * 0.3));
    angleX = Math.max(-10, Math.min(40, drag.ax - (e.clientY - drag.y) * 0.2));
    apply();
  });
  stage.addEventListener("pointerup", () => { drag = null; });
  stage.addEventListener("keydown", (e) => {
    if (e.key === "ArrowLeft") angleY -= 6; else if (e.key === "ArrowRight") angleY += 6;
    else if (e.key === "ArrowUp") angleX += 4; else if (e.key === "ArrowDown") angleX -= 4; else return;
    e.preventDefault(); apply();
  });
}

// ===================================================================== 7. CARTOON EXPLAINER
// An agent tries to submit a form; a passkey guard holds up a sign; the person approves; a wax
// seal stamps the receipt. Captions carry the same story in words.
export function cartoon(host) {
  const captions = [
    "An AI agent fills in a form and reaches for Submit.",
    "HashCam's gateway holds it: this step needs a person.",
    "You read who, what and where, and approve with your passkey.",
    "Only then is the form sent.",
    "Everything is sealed into a signed receipt anyone can check.",
  ];
  const root = svg("svg", { viewBox: "0 0 520 240", class: "cartoon", role: "img", "aria-label": captions.join(" ") });
  const agent = svg("g", { class: "c-agent" },
    svg("rect", { x: 40, y: 110, width: 56, height: 62, rx: 14 }),
    svg("rect", { x: 48, y: 74, width: 40, height: 34, rx: 10, class: "head" }),
    svg("circle", { cx: 61, cy: 91, r: 4, class: "eye" }), svg("circle", { cx: 75, cy: 91, r: 4, class: "eye" }),
    svg("line", { x1: 68, y1: 74, x2: 68, y2: 62 }), svg("circle", { cx: 68, cy: 58, r: 5, class: "antenna" }));
  const form = svg("g", { class: "c-form" },
    svg("rect", { x: 150, y: 70, width: 110, height: 120, rx: 8 }),
    ...[92, 112, 132].map((y) => svg("rect", { x: 164, y, width: 82, height: 10, rx: 3, class: "field" })),
    svg("rect", { x: 178, y: 156, width: 54, height: 20, rx: 6, class: "submit" }),
    svg("text", { x: 205, y: 170, "text-anchor": "middle" }, "Submit"));
  const guard = svg("g", { class: "c-guard" },
    svg("path", { d: "M330 64 l34 12 v28 c0 26 -16 42 -34 52 c-18 -10 -34 -26 -34 -52 v-28 z" }),
    svg("text", { x: 330, y: 118, "text-anchor": "middle", class: "big" }, "?"),
    svg("rect", { x: 292, y: 168, width: 78, height: 30, rx: 6, class: "sign" }),
    svg("text", { x: 331, y: 188, "text-anchor": "middle", class: "sign-t" }, "Passkey"));
  const finger = svg("g", { class: "c-finger" },
    svg("circle", { cx: 330, cy: 112, r: 26, class: "pad" }),
    ...[8, 14, 20].map((r) => svg("path", { d: `M${330 - r} 116 a${r} ${r} 0 0 1 ${2 * r} 0`, class: "ridge" })));
  const receipt = svg("g", { class: "c-receipt" },
    svg("path", { d: "M420 60 h70 v130 l-7 -6 l-7 6 l-7 -6 l-7 6 l-7 -6 l-7 6 l-7 -6 l-7 6 l-7 -6 l-7 6 z" }),
    ...[80, 96, 112, 128].map((y) => svg("rect", { x: 430, y, width: 50, height: 6, rx: 2, class: "line" })));
  const seal = svg("g", { class: "c-seal" },
    svg("circle", { cx: 470, cy: 160, r: 20 }), svg("text", { x: 470, y: 165, "text-anchor": "middle" }, "✓"));
  root.append(form, agent, guard, finger, receipt, seal);
  const caption = el("p", { class: "c-caption", "aria-live": "polite" }, captions[0]);
  const replay = el("button", { class: "btn ghost small", type: "button" }, "Play again");
  host.append(root, caption, replay);

  const still = () => {
    finger.style.opacity = "1"; seal.style.opacity = "1"; guard.style.opacity = "1";
    caption.textContent = captions.join(" ");
  };
  if (calm() || !gsap()) { still(); replay.hidden = true; return { play() {} }; }
  const g = gsap();
  const tl = g.timeline({ paused: true })
    .set([finger, seal], { opacity: 0 }).set(guard, { opacity: 0, y: 20 }).set(agent, { x: 0 })
    .call(() => { caption.textContent = captions[0]; })
    .to(agent, { x: 70, duration: 1.1, ease: "power1.inOut" })
    .to(form.querySelector(".submit"), { scale: 0.92, transformOrigin: "50% 50%", duration: 0.15, yoyo: true, repeat: 1 })
    .call(() => { caption.textContent = captions[1]; })
    .to(guard, { opacity: 1, y: 0, duration: 0.5, ease: "back.out(2)" })
    .to(agent, { x: 52, duration: 0.3, ease: "power2.out" }, "<")
    .to({}, { duration: 0.6 })
    .call(() => { caption.textContent = captions[2]; })
    .to(finger, { opacity: 1, duration: 0.3 })
    .fromTo(finger.querySelectorAll(".ridge"), { strokeDasharray: 80, strokeDashoffset: 80 }, { strokeDashoffset: 0, duration: 0.8, stagger: 0.15 })
    .call(() => { caption.textContent = captions[3]; })
    .to(guard, { opacity: 0.25, duration: 0.3 })
    .to(form, { x: 220, opacity: 0, duration: 0.7, ease: "power2.in" })
    .call(() => { caption.textContent = captions[4]; })
    .fromTo(seal, { opacity: 0, scale: 2.4, rotate: -30, transformOrigin: "470px 160px" }, { opacity: 1, scale: 1, rotate: -8, duration: 0.35, ease: "power4.in" })
    .to({}, { duration: 1.2 })
    .set(form, { x: 0, opacity: 1 });
  replay.addEventListener("click", () => tl.restart());
  return { play: () => tl.restart() };
}

// ===================================================================== 8. DOMINO REVEAL (verdict)
// The verifier's dimensions, in the order abb verify reported them, fall one after another. A
// FAIL stops the row: the tiles after it stay standing. The same facts are listed in text.
export function dominoes(host, dimensions) {
  host.textContent = "";
  const entries = Object.entries(dimensions || {});
  const row = el("div", { class: "dominoes", "aria-hidden": "true" },
    ...entries.map(([name, status]) => el("div", { class: `domino d-${status}`, title: `${name}: ${status}` }, short(status))));
  const list = el("ul", { class: "dims" },
    ...entries.map(([name, status]) => el("li", {}, el("span", {}, name), el("span", { class: `d-${status}` }, status))));
  host.append(row, list);
  const tiles = [...row.children];
  const failAt = entries.findIndex(([, s]) => s === "FAIL");
  const falling = failAt === -1 ? tiles : tiles.slice(0, failAt);
  if (calm()) { falling.forEach((t) => t.classList.add("fallen")); return; }
  falling.forEach((t, i) =>
    go(t, [{ transform: "rotateX(0deg)" }, { transform: "rotateX(78deg)" }], { delay: i * 70, duration: 460 }));
  if (failAt !== -1) {
    // The failed tile does not fall: it shudders once the row has reached it.
    go(tiles[failAt], [{ transform: "translateX(0)" }, { transform: "translateX(-4px)" }, { transform: "translateX(4px)" },
      { transform: "translateX(-3px)" }, { transform: "translateX(0)" }], { delay: falling.length * 70 + 260, duration: 420, fill: "none" });
  }
}
function short(status) {
  return { PASS: "PASS", FAIL: "FAIL", UNKNOWN: "UNK", NOT_APPLICABLE: "N/A", NOT_INDEPENDENT: "N/IND" }[status] || status;
}

// ===================================================================== 9. GLOW ATOM (session core)
// The agent is the nucleus. Events orbit in shells by kind; a pending approval is the glowing
// valence electron; the number of lit shells shows the trust level (100 = all four).
const SHELLS = [
  ["navigate", "#38BDF8"], ["form_submit", "#F59E0B"], ["secret", "#B9A7FF"], ["download", "#7FD3C4"],
];
export function glowAtom(canvas, getState) {
  const ctx = canvas.getContext("2d");
  let raf = 0;
  let t0 = performance.now();
  const draw = (now) => {
    const state = getState();
    const dpr = window.devicePixelRatio || 1;
    const w = canvas.clientWidth;
    const h = canvas.clientHeight;
    if (canvas.width !== w * dpr) { canvas.width = w * dpr; canvas.height = h * dpr; }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, w, h);
    const cx = w / 2;
    const cy = h / 2;
    const t = (now - t0) / 1000;
    const lit = Math.ceil((state.trust ?? 100) / 25);
    SHELLS.forEach(([kind, colour], s) => {
      // The outermost, most tilted orbit must stay inside the canvas: |sin(tilt)| <= 0.6.
      // A hidden or collapsed panel has a tiny canvas; a negative radius would throw (IndexSizeError).
      const outer = Math.max(0, Math.min(w / 2 - 8, (h / 2 - 8) / 0.62));
      const rx = outer * (0.4 + s * 0.2);
      const ry = rx * 0.34;
      if (rx < 1) return;
      const tilt = (s - 1.5) * 0.42;
      ctx.save();
      ctx.translate(cx, cy);
      ctx.rotate(tilt);
      ctx.strokeStyle = s < lit ? hexA(colour, 0.55) : "rgba(138,155,184,.16)";
      ctx.lineWidth = s < lit ? 1.4 : 1;
      ctx.beginPath(); ctx.ellipse(0, 0, rx, ry, 0, 0, Math.PI * 2); ctx.stroke();
      const count = Math.min(12, state.counts?.[kind] || 0);
      for (let i = 0; i < count; i++) {
        const a = (i / count) * Math.PI * 2 + t * (0.5 + s * 0.12) * (s % 2 ? -1 : 1);
        dot(ctx, Math.cos(a) * rx, Math.sin(a) * ry, 2.6, colour, 8);
      }
      if (s === SHELLS.length - 1 && state.waiting > 0) {
        const a = t * 0.9;
        const pulse = 7 + Math.sin(t * 5) * 2;
        dot(ctx, Math.cos(a) * rx, Math.sin(a) * ry, pulse, "#F59E0B", 26);
      }
      ctx.restore();
    });
    // nucleus
    const g = ctx.createRadialGradient(cx, cy, 2, cx, cy, 26);
    g.addColorStop(0, "rgba(255,226,160,1)"); g.addColorStop(0.45, "rgba(245, 158, 11,.85)"); g.addColorStop(1, "rgba(245, 158, 11,0)");
    ctx.fillStyle = g; ctx.beginPath(); ctx.arc(cx, cy, 26, 0, Math.PI * 2); ctx.fill();
    ctx.fillStyle = "#1A1204"; ctx.font = "700 11px ui-monospace, Consolas, monospace"; ctx.textAlign = "center"; ctx.textBaseline = "middle";
    ctx.fillText((state.agent || "AI").slice(0, 2).toUpperCase(), cx, cy + 0.5);
    if (!calm() && raf) raf = requestAnimationFrame(draw);
  };
  const start = () => { if (calm()) { draw(performance.now()); return; } if (!raf) { raf = 1; raf = requestAnimationFrame(draw); } };
  const stop = () => { cancelAnimationFrame(raf); raf = 0; };
  whileVisible(canvas, start, stop);
  return { redraw: () => { if (calm() || !raf) draw(performance.now()); } };
}
function dot(ctx, x, y, r, colour, blur) {
  ctx.shadowColor = colour; ctx.shadowBlur = blur; ctx.fillStyle = colour;
  ctx.beginPath(); ctx.arc(x, y, r, 0, Math.PI * 2); ctx.fill(); ctx.shadowBlur = 0;
}
function hexA(hex, a) {
  const n = parseInt(hex.slice(1), 16);
  return `rgba(${n >> 16},${(n >> 8) & 255},${n & 255},${a})`;
}

// ===================================================================== small mini-maths (extension)
// "You sign SHA-256 of this text": the approval card's formula, drawn in.
export function signFormula(host, digest) {
  host.textContent = "";
  const line = el("div", { class: "sign-f" },
    el("span", { class: "fn" }, "sign"), "( SHA-256(", el("span", { class: "txt" }, "this text"), ") ) = ",
    el("code", {}, (digest || "").slice(0, 16) + "…"));
  host.append(line);
  if (!calm() && gsap()) gsap().from(line.children, { opacity: 0, y: 6, duration: 0.3, stagger: 0.12 });
}
