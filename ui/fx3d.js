// HashCam's nine animation styles. Each has one job, and each has a still version for people who
// ask for reduced motion: the still version shows the same facts, never less.
//
// Nothing here decides anything. The verdict, statuses and counts drawn come from the verifier
// and the recorder; these functions only draw them.

const NS = "http://www.w3.org/2000/svg";
const gsap = () => window.gsap;
export const calm = () => matchMedia("(prefers-reduced-motion: reduce)").matches;

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

// ===================================================================== 1. ISOMETRIC (how it works)
// agent -> policy gateway -> ledger -> separate signer -> receipt. Packets travel the path; every
// third packet is refused and bounces off the gateway.
export function isometric(host) {
  const S = 22;
  const iso = (x, y, z = 0) => [(x - y) * S * 0.866 + 300, (x + y) * S * 0.5 - z * S + 60];
  const stations = [
    { x: 0, y: 0, h: 1.4, label: "AI agent", tone: "cyan" },
    { x: 4, y: 0, h: 2.2, label: "Policy gateway", tone: "gold" },
    { x: 8, y: 0, h: 1.2, label: "Ledger", tone: "cyan" },
    { x: 8, y: 4, h: 1.8, label: "Separate signer", tone: "gold" },
    { x: 12, y: 4, h: 0.6, label: "Receipt", tone: "paper" },
  ];
  const root = svg("svg", { viewBox: "0 0 620 380", class: "iso", role: "img",
    "aria-label": "How it works: the AI agent's actions pass the policy gateway, are written to the ledger, checkpointed by a separate signer, and sealed into a receipt. Refused actions stop at the gateway." });
  const face = (pts, cls) => svg("polygon", { points: pts.map((p) => p.join(",")).join(" "), class: cls });
  // floor tiles
  for (let x = -1; x <= 13; x++) for (let y = -1; y <= 5; y++) {
    root.append(face([iso(x, y), iso(x + 1, y), iso(x + 1, y + 1), iso(x, y + 1)], "iso-tile"));
  }
  // the path the packets take
  const path = [[0.5, 0.5], [4.5, 0.5], [8.5, 0.5], [8.5, 4.5], [12.5, 4.5]].map(([x, y]) => iso(x, y, 0.05));
  root.append(svg("polyline", { points: path.map((p) => p.join(",")).join(" "), class: "iso-path" }));
  for (const s of stations) {
    const [x, y, h] = [s.x, s.y, s.h];
    const g = svg("g", { class: `iso-box tone-${s.tone}` });
    g.append(face([iso(x, y + 1, 0), iso(x + 1, y + 1, 0), iso(x + 1, y + 1, h), iso(x, y + 1, h)], "f-left"));
    g.append(face([iso(x + 1, y, 0), iso(x + 1, y + 1, 0), iso(x + 1, y + 1, h), iso(x + 1, y, h)], "f-right"));
    g.append(face([iso(x, y, h), iso(x + 1, y, h), iso(x + 1, y + 1, h), iso(x, y + 1, h)], "f-top"));
    const [lx, ly] = iso(x + 0.5, y + 1.6, 0);
    g.append(svg("text", { x: lx, y: ly + 14, class: "iso-label", "text-anchor": "middle" }, s.label));
    root.append(g);
  }
  host.append(root);
  if (calm() || !gsap()) return;

  const legs = [[path[0], path[1]], [path[1], path[2]], [path[2], path[3]], [path[3], path[4]]];
  let n = 0;
  let timer = null;
  const send = () => {
    n += 1;
    const refused = n % 3 === 0;
    const packet = svg("circle", { r: 5, class: refused ? "iso-packet bad" : "iso-packet", cx: path[0][0], cy: path[0][1] });
    root.append(packet);
    const tl = gsap().timeline({ onComplete: () => packet.remove() });
    if (refused) {
      const [a, b] = legs[0];
      const stop = [a[0] + (b[0] - a[0]) * 0.86, a[1] + (b[1] - a[1]) * 0.86];
      tl.to(packet, { attr: { cx: stop[0], cy: stop[1] }, duration: 0.9, ease: "none" })
        .to(packet, { attr: { cx: a[0], cy: a[1] }, duration: 0.6, ease: "bounce.out" })
        .to(packet, { opacity: 0, duration: 0.2 });
    } else {
      for (const [, b] of legs) tl.to(packet, { attr: { cx: b[0], cy: b[1] }, duration: 0.8, ease: "none" });
      tl.to(packet, { attr: { r: 9 }, opacity: 0, duration: 0.3 });
    }
  };
  whileVisible(host, () => { send(); timer = setInterval(send, 1100); }, () => clearInterval(timer));
}

// ===================================================================== 2. PAPER-CUT (receipts)
// Each event prints in as a cut strip of paper.
export function printStrip(list, strip, { prepend = false } = {}) {
  strip.classList.add("strip");
  if (prepend) list.prepend(strip); else list.append(strip);
  if (calm() || !gsap()) return strip;
  gsap().fromTo(strip,
    { clipPath: "inset(0 0 100% 0)", y: -14, rotate: -1.2 },
    { clipPath: "inset(0 0 0% 0)", y: 0, rotate: 0, duration: 0.5, ease: "steps(7)", clearProps: "clipPath,transform" });
  return strip;
}

// ===================================================================== 3. 3D DATA CHART (live)
// One stacked 3D bar per session: allowed / approved / blocked / tripwire.
const SEGMENTS = [
  ["allowed", "Allowed"], ["approved", "Approved"], ["blocked", "Blocked or unsent"], ["tripwire", "Tripwire"],
];
export function bars3d(host, sessions) {
  host.textContent = "";
  host.classList.add("bars3d");
  const scene = el("div", { class: "b3-scene", role: "img",
    "aria-label": sessions.length
      ? "Events per session: " + sessions.map((s) => `${s.agent}: ` + SEGMENTS.map(([k, n]) => `${s.counts[k]} ${n.toLowerCase()}`).join(", ")).join("; ")
      : "No sessions yet." });
  const plane = el("div", { class: "b3-plane" });
  scene.append(plane);
  const max = Math.max(4, ...sessions.map((s) => SEGMENTS.reduce((t, [k]) => t + s.counts[k], 0)));
  const unit = 150 / max;
  sessions.slice(0, 8).forEach((s, i) => {
    let z = 0;
    const x = 30 + i * 62;
    for (const [key] of SEGMENTS) {
      const h = s.counts[key] * unit;
      if (h <= 0) continue;
      plane.append(cuboid(x, 70, 34, 34, z, h, key));
      z += h;
    }
    plane.append(el("div", { class: "b3-label", style: `left:${x}px;top:112px` }, s.agent.slice(0, 10)));
  });
  for (let i = 0; i < 6; i++) plane.append(el("div", { class: "b3-gridline", style: `top:${20 + i * 22}px` }));
  host.append(scene, el("ul", { class: "b3-legend" },
    ...SEGMENTS.map(([k, n]) => el("li", {}, el("i", { class: `seg-${k}` }), n))));
  if (!calm() && gsap()) {
    gsap().from(plane.querySelectorAll(".cube"), { scaleZ: 0.01, duration: 0.7, stagger: 0.05, ease: "back.out(1.4)" });
  }
}
function cuboid(x, y, w, d, z, h, key) {
  // The ground is the plane (x, y); height rises along +z.
  const cube = el("div", { class: `cube seg-${key}`, style: `left:${x}px;top:${y}px;transform:translateZ(${z}px)` });
  cube.append(
    el("div", { class: "face top", style: `width:${w}px;height:${d}px;transform:translateZ(${h}px)` }),
    el("div", { class: "face front", style: `width:${w}px;height:${h}px;transform:translateY(${d}px) rotateX(90deg)` }),
    el("div", { class: "face side", style: `width:${h}px;height:${d}px;transform:translateX(${w}px) rotateY(-90deg)` }),
  );
  return cube;
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
  const edges = svg("svg", { class: "mk-edges", viewBox: `0 0 ${W} 330`, "aria-hidden": "true" });
  tree.append(edges);
  const nodes = []; // nodes[level][i]
  const posOf = (level, i) => {
    const count = 8 >> level;
    return { x: (W / count) * (i + 0.5), y: 300 - level * 92 };
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
          edges.append(svg("line", { x1: x, y1: y + 18, x2: a.x, y2: a.y - 18, "data-to": `${level - 1}-${c}` }));
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
        node.querySelector("code").textContent = current[level][i].slice(0, 8);
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
    if (calm() || !gsap() || changedLeaf == null) { lightSteps(broken ? 4 : 3); return; }
    // Climb the tree level by level, lighting the matching maths step.
    let i = changedLeaf;
    const tl = gsap().timeline();
    for (let level = 0; level < 4; level++) {
      const node = nodes[level][i];
      tl.call(() => lightSteps(Math.min(level, 2)))
        .fromTo(node, { scale: 1 }, { scale: 1.18, duration: 0.18, yoyo: true, repeat: 1 });
      i = Math.floor(i / 2);
    }
    tl.call(() => lightSteps(broken ? 4 : 3));
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
  if (calm() || !gsap()) { falling.forEach((t) => t.classList.add("fallen")); return; }
  const tl = gsap().timeline();
  falling.forEach((t, i) => tl.to(t, { rotateX: 78, duration: 0.22, ease: "power2.in" }, i * 0.09));
  if (failAt !== -1) {
    tl.to(tiles[failAt], { x: -4, duration: 0.06, repeat: 5, yoyo: true }, ">");
  }
}
function short(status) {
  return { PASS: "PASS", FAIL: "FAIL", UNKNOWN: "UNK", NOT_APPLICABLE: "N/A", NOT_INDEPENDENT: "N/IND" }[status] || status;
}

// ===================================================================== 9. GLOW ATOM (session core)
// The agent is the nucleus. Events orbit in shells by kind; a pending approval is the glowing
// valence electron; the number of lit shells shows the trust level (100 = all four).
const SHELLS = [
  ["navigate", "#5CC8FF"], ["form_submit", "#F5B841"], ["secret", "#B9A7FF"], ["download", "#7FD3C4"],
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
      const outer = Math.min(w / 2 - 8, (h / 2 - 8) / 0.62);
      const rx = outer * (0.4 + s * 0.2);
      const ry = rx * 0.34;
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
        dot(ctx, Math.cos(a) * rx, Math.sin(a) * ry, pulse, "#F5B841", 26);
      }
      ctx.restore();
    });
    // nucleus
    const g = ctx.createRadialGradient(cx, cy, 2, cx, cy, 26);
    g.addColorStop(0, "rgba(255,226,160,1)"); g.addColorStop(0.45, "rgba(245,184,65,.85)"); g.addColorStop(1, "rgba(245,184,65,0)");
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
