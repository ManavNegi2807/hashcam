// Small, purposeful animations built on Motion (served from this computer: /vendor/motion.js).
// Every effect is decoration: if Motion is missing, or the person asked their system for reduced
// motion, nothing animates and the page works exactly the same. Nothing here reads or changes
// what the page says.
"use strict";

const fx = (() => {
  const reduced = () => window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const ready = () => typeof window.Motion === "object" && window.Motion && !reduced();
  const ease = [0.22, 1, 0.36, 1];

  // A new message or card eases up into place.
  function enter(node, delay = 0) {
    if (!ready() || !node) return;
    window.Motion.animate(node, { opacity: [0, 1], transform: ["translateY(10px)", "translateY(0px)"] },
      { duration: 0.42, delay, ease });
  }

  // A card that asks for attention springs in a little more firmly.
  function pop(node) {
    if (!ready() || !node) return;
    window.Motion.animate(node, { opacity: [0, 1], transform: ["scale(0.96)", "scale(1)"] },
      { type: "spring", stiffness: 380, damping: 26 });
  }

  // A list or group of cards appears one after another.
  function stagger(nodes, step = 0.045) {
    if (!ready()) return;
    const list = Array.from(nodes || []);
    list.forEach((node, index) => enter(node, Math.min(index, 12) * step));
  }

  // Interactive controls give a small press response.
  function press(selector) {
    if (!ready()) return;
    for (const node of document.querySelectorAll(selector)) {
      if (node.dataset.fxPress) continue;
      node.dataset.fxPress = "1";
      node.addEventListener("pointerdown", () => {
        if (!ready() || node.disabled) return;
        window.Motion.animate(node, { transform: ["scale(1)", "scale(0.97)", "scale(1)"] }, { duration: 0.22 });
      });
    }
  }

  // ---- scrolling (audit page only): Lenis smooths the wheel, GSAP ScrollTrigger reveals sections
  // as they come into view and draws a thin progress bar. Same rule as above: decoration only.
  const scrollReady = () =>
    !reduced() && typeof window.gsap === "object" && window.gsap
    && typeof window.ScrollTrigger === "function" && typeof window.Lenis === "function";
  let smoothOn = false;

  function smooth() {
    if (smoothOn || !scrollReady()) return;
    smoothOn = true;
    const { gsap, ScrollTrigger, Lenis } = window;
    gsap.registerPlugin(ScrollTrigger);
    const lenis = new Lenis({ lerp: 0.1, smoothWheel: true });
    lenis.on("scroll", ScrollTrigger.update);
    gsap.ticker.add((time) => lenis.raf(time * 1000));
    gsap.ticker.lagSmoothing(0);
    const bar = document.getElementById("scrollbar");
    if (bar) {
      gsap.fromTo(bar, { scaleX: 0 }, { scaleX: 1, ease: "none",
        scrollTrigger: { start: 0, end: "max", scrub: 0.2 } });
    }
  }

  // Sections and cards fade up once, the first time they come into view. Tables and code boxes
  // that scroll on their own keep native scrolling.
  function reveal(nodes) {
    if (!smoothOn) return;
    const { gsap, ScrollTrigger } = window;
    for (const box of document.querySelectorAll(".scroll, pre")) box.setAttribute("data-lenis-prevent", "");
    for (const node of Array.from(nodes || [])) {
      if (!node || node.dataset.fxRevealed) continue;
      node.dataset.fxRevealed = "1";
      gsap.from(node, { opacity: 0, y: 28, duration: 0.7, ease: "power3.out", clearProps: "all",
        scrollTrigger: { trigger: node, start: "top 92%", once: true,
          onEnter: () => draw(node.querySelector("h2 .ico"), 0.25) } });
    }
    ScrollTrigger.refresh();
  }

  // ---- flair (both pages): drawn-in logo and icons, split-text titles, cursor spotlight, magnetic
  // buttons. Plain GSAP, no React. Decoration only: icons are added by script and hidden from
  // screen readers, text is never removed, and with reduced motion or no GSAP nothing is changed.
  const flairReady = () => !reduced() && typeof window.gsap === "object" && !!window.gsap;
  const NS = "http://www.w3.org/2000/svg";
  const ICONS = {
    chat: "M5 5h14v10h-8l-4 4v-4H5z",
    shield: "M12 3l7 3v5c0 4.5-3 8-7 10-4-2-7-5.5-7-10V6z M9 12l2.2 2.2L15.5 10",
    info: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z M12 11v5 M12 8v.01",
    layers: "M12 3l9 5-9 5-9-5z M3 13l9 5 9-5",
    table: "M4 5h16v14H4z M4 11h16 M10 5v14",
    search: "M11 4a7 7 0 1 0 0 14 7 7 0 0 0 0-14z M20 20l-4-4",
    people: "M16 19v-1a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v1 M10 11a3 3 0 1 0 0-6 3 3 0 0 0 0 6z M17 8l2 2 3-3",
    graph: "M6 4a2 2 0 1 0 0 4 2 2 0 0 0 0-4z M18 10a2 2 0 1 0 0 4 2 2 0 0 0 0-4z M6 16a2 2 0 1 0 0 4 2 2 0 0 0 0-4z M8 7l8 4 M8 17l8-4",
    steps: "M8 6h12 M8 12h12 M8 18h12 M4 6h.01 M4 12h.01 M4 18h.01",
    book: "M5 4h10a3 3 0 0 1 3 3v13H8a3 3 0 0 1-3-3z M5 17a3 3 0 0 1 3-3h10",
    globe: "M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18z M3 12h18 M12 3c3 3 3 15 0 18 M12 3c-3 3-3 15 0 18",
    flask: "M9 3h6 M10 3v6l-5 9a2 2 0 0 0 2 3h10a2 2 0 0 0 2-3l-5-9V3",
    cursor: "M5 4l14 7-6 2-2 6z",
    card: "M3 6h18v12H3z M3 10h18 M7 15h4",
    alert: "M12 3l10 18H2z M12 10v5 M12 18v.01",
    radar: "M12 12m-2 0a2 2 0 1 0 4 0 2 2 0 1 0-4 0 M12 3a9 9 0 1 0 9 9 M12 7a5 5 0 1 0 5 5",
  };
  const HEADING_ICONS = {
    "answer-h": "chat", "overall-h": "shield", "limits-h": "info", "channels-h": "layers",
    "dims-h": "table", "findings-h": "search", "run-h": "people", "graph-h": "graph", "alerts-h": "alert", "events-h": "steps",
  };
  const MODE_ICONS = { search: "search", research: "book", agent: "globe", guarded: "flask", realsite: "cursor", pay: "card", endpoint: "radar" };

  function icon(name) {
    const svg = document.createElementNS(NS, "svg");
    const attrs = { viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", "stroke-width": 2,
      "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true", class: "ico" };
    for (const [k, v] of Object.entries(attrs)) svg.setAttribute(k, String(v));
    for (const d of ICONS[name].split(" M").map((part, i) => (i ? "M" + part : part))) {
      const path = document.createElementNS(NS, "path");
      path.setAttribute("d", d);
      svg.append(path);
    }
    return svg;
  }

  // Strokes draw themselves in, one path after another.
  function draw(svg, delay = 0) {
    if (!flairReady() || !svg) return;
    const paths = Array.from(svg.querySelectorAll("path, rect, circle"));
    for (const p of paths) p.setAttribute("pathLength", "1");
    window.gsap.fromTo(paths, { strokeDasharray: 1, strokeDashoffset: 1 },
      { strokeDashoffset: 0, duration: 0.9, delay, stagger: 0.12, ease: "power2.out",
        onComplete: () => paths.forEach((p) => { p.style.strokeDasharray = "none"; }) });
  }

  // The logos and the small icons already on the page draw in; hovering one gives it a wiggle.
  function logos() {
    if (!flairReady()) return;
    const { gsap } = window;
    const marks = document.querySelectorAll(".logo, .hero-logo, .facts svg, .newrun svg");
    marks.forEach((svg, i) => {
      draw(svg, 0.1 + i * 0.12);
      svg.addEventListener("pointerenter", () =>
        gsap.fromTo(svg, { rotate: -10, scale: 1 }, { rotate: 0, scale: 1.12, duration: 0.5, ease: "elastic.out(1, 0.45)", yoyo: true, repeat: 1 }));
    });
  }

  // Icons in front of each section heading (audit view) and each task type (chat board).
  function icons() {
    for (const [id, name] of Object.entries(HEADING_ICONS)) {
      const h = document.getElementById(id);
      if (!h || h.querySelector(".ico")) continue;
      const mark = icon(name);
      h.prepend(mark);
      // Shown sections draw their icon as they scroll in (see reveal); with no scroll effects, now.
      if (!smoothOn && h.offsetParent !== null) draw(mark);
    }
    for (const input of document.querySelectorAll('.mode input[name="mode"]')) {
      const label = input.parentElement.querySelector("b");
      if (!label || label.querySelector(".ico") || !MODE_ICONS[input.value]) continue;
      const mark = icon(MODE_ICONS[input.value]);
      label.prepend(mark);
      draw(mark, 0.3);
    }
  }

  // A title's letters rise in one after another. The text stays one readable string for screen
  // readers (the visible letters are hidden from them) and is never changed.
  function split(selector) {
    if (!flairReady()) return;
    for (const node of document.querySelectorAll(selector)) {
      if (node.dataset.fxSplit) continue;
      node.dataset.fxSplit = "1";
      node.setAttribute("aria-label", node.textContent.trim());
      const letters = [];
      const walk = (parent) => {
        for (const child of Array.from(parent.childNodes)) {
          if (child.nodeType === 3) {
            // Words stay whole (they never break in the middle); spaces stay real spaces.
            const frag = document.createDocumentFragment();
            for (const part of child.textContent.split(/( )/)) {
              if (part === " " || part === "") { frag.append(part); continue; }
              const word = document.createElement("span");
              word.className = "fxword";
              for (const ch of part) {
                const span = document.createElement("span");
                span.className = "fxchar";
                span.setAttribute("aria-hidden", "true");
                span.textContent = ch;
                letters.push(span);
                word.append(span);
              }
              frag.append(word);
            }
            parent.replaceChild(frag, child);
          } else if (child.nodeType === 1) walk(child);
        }
      };
      walk(node);
      window.gsap.from(letters, { yPercent: 90, opacity: 0, duration: 0.7, stagger: 0.025, ease: "back.out(1.6)", clearProps: "all" });
    }
  }

  // A soft glow follows the pointer inside cards (the CSS paints it on :hover only).
  function spotlight(selector) {
    for (const node of document.querySelectorAll(selector)) {
      if (node.dataset.fxSpot) continue;
      node.dataset.fxSpot = "1";
      node.classList.add("spot");
      node.addEventListener("pointermove", (event) => {
        const box = node.getBoundingClientRect();
        node.style.setProperty("--mx", event.clientX - box.left + "px");
        node.style.setProperty("--my", event.clientY - box.top + "px");
      });
    }
  }

  // Main buttons lean a little toward the pointer.
  function magnet(selector, strength = 0.25) {
    if (!flairReady()) return;
    const { gsap } = window;
    for (const node of document.querySelectorAll(selector)) {
      if (node.dataset.fxMagnet) continue;
      node.dataset.fxMagnet = "1";
      const x = gsap.quickTo(node, "x", { duration: 0.4, ease: "power3.out" });
      const y = gsap.quickTo(node, "y", { duration: 0.4, ease: "power3.out" });
      node.addEventListener("pointermove", (e) => {
        const b = node.getBoundingClientRect();
        x((e.clientX - (b.left + b.width / 2)) * strength);
        y((e.clientY - (b.top + b.height / 2)) * strength);
      });
      node.addEventListener("pointerleave", () => { x(0); y(0); });
    }
  }

  // One call per page: everything above, on the parts both pages share.
  function flair() {
    logos();
    icons();
    split("[data-split]");
    spotlight(".card, .answerbox, .graphbox, .facts li, .idea, .findings li");
    magnet("#verify, .newrun, .linkbtn:not(.small), #task-run");
  }

  // A small icon for a task type, for lists outside the picker (the sidebar).
  function modeIcon(value) {
    const name = MODE_ICONS[value];
    return name ? icon(name) : null;
  }

  return { enter, pop, stagger, press, ready, smooth, reveal, flair, icons, draw, modeIcon };
})();
