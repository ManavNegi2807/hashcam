// The graph of one run, drawn as plain SVG. The data comes from /api/graph (FalkorDB when it is
// connected, otherwise straight from the receipt). This is a picture of what is inside the receipt:
// it never says whether the receipt is valid. Colours use the same pairs as the status chips, so
// they are readable in light and dark, and every node is also listed in text below the picture.
"use strict";

const graphView = (() => {
  const NS = "http://www.w3.org/2000/svg";
  const BOX = { w: 210, h: 56, gapY: 26, colX: [16, 276, 536] };
  const COLUMN = { Run: 0, Mandate: 0, Action: 1, Policy: 2, Approval: 2, Call: 2 };
  const CLASS = {
    succeeded: "ok", approved: "ok", blocked: "fail", failed: "fail", denied: "fail",
    unknown: "unknown", "needs approval": "unknown", requested: "unknown", dispatched: "unknown",
  };

  const svg = (tag, attrs = {}, ...kids) => {
    const node = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, String(v));
    for (const kid of kids) node.append(kid);
    return node;
  };
  const clip = (text, n) => (String(text).length > n ? String(text).slice(0, n - 1) + "…" : String(text));

  function kindOf(n) {
    if (n.label === "Action") return "gn-" + (CLASS[n.status] || "na");
    if (n.label === "Run") return "gn-run";
    if (n.label === "Approval") return "gn-notind";
    return "gn-na";
  }

  function caption(n) {
    if (n.label === "Action") {
      const money = typeof n.amount_minor_units === "number" ? " " + (n.amount_minor_units / 100).toFixed(2) : "";
      return [clip(n.name + money, 22), clip((n.action_type || "action") + " · " + (n.status || ""), 32)];
    }
    if (n.label === "Run") return ["Run " + clip(n.name, 12), clip((n.adapter || "") + " · " + (n.outcome || "…"), 32)];
    if (n.label === "Approval") return ["Signed approval", clip(n.decision || "", 30)];
    if (n.label === "Call") return ["Provider call", n.cents >= 0 ? n.cents + " cent(s)" : "cost not recorded"];
    return [n.label, clip(n.name, 30)];
  }

  // Columns by kind; rows follow the actions they hang from, pushed apart so nothing overlaps.
  function place(graph) {
    const pos = new Map();
    const actions = graph.nodes.filter((n) => n.label === "Action");
    actions.forEach((n, i) => pos.set(n.id, { x: BOX.colX[1], y: 16 + i * (BOX.h + BOX.gapY) }));
    const ys = (id) => graph.edges
      .filter((e) => e.src === id || e.dst === id)
      .map((e) => pos.get(e.src === id ? e.dst : e.src))
      .filter(Boolean).map((p) => p.y);
    const mid = actions.length ? (pos.get(actions[0].id).y + pos.get(actions[actions.length - 1].id).y) / 2 : 16;
    const taken = [new Set(), new Set(), new Set()];
    for (const n of graph.nodes) {
      if (n.label === "Action") continue;
      const col = COLUMN[n.label] ?? 2;
      const near = ys(n.id);
      let y = near.length ? near.reduce((a, b) => a + b, 0) / near.length : (n.label === "Mandate" ? mid + BOX.h + BOX.gapY : mid);
      while ([...taken[col]].some((t) => Math.abs(t - y) < BOX.h + 10)) y += BOX.h + 10;
      taken[col].add(y);
      pos.set(n.id, { x: BOX.colX[col], y });
    }
    return pos;
  }

  function draw(graph) {
    const pos = place(graph);
    const height = Math.max(120, ...[...pos.values()].map((p) => p.y + BOX.h + 16));
    const width = BOX.colX[2] + BOX.w + 16;
    const root = svg("svg", { viewBox: `0 0 ${width} ${height}`, role: "img", class: "graphsvg",
      "aria-label": `Graph of this run: ${graph.nodes.length} items and ${graph.edges.length} links. The same facts are listed below.` });
    root.append(svg("defs", {}, svg("marker", { id: "arrow", viewBox: "0 0 10 10", refX: 9, refY: 5, markerWidth: 7, markerHeight: 7, orient: "auto-start-reverse" },
      svg("path", { d: "M0,0 L10,5 L0,10 z", class: "garrowhead" }))));
    for (const e of graph.edges) {
      const a = pos.get(e.src), b = pos.get(e.dst);
      if (!a || !b) continue;
      const forward = b.x >= a.x;
      const x1 = forward ? a.x + BOX.w : a.x, x2 = forward ? b.x : b.x + BOX.w;
      const y1 = a.y + BOX.h / 2, y2 = b.y + BOX.h / 2;
      const same = a.x === b.x;
      const down = b.y >= a.y;
      const d = same
        ? `M${a.x + BOX.w / 2},${down ? a.y + BOX.h : a.y} L${b.x + BOX.w / 2},${down ? b.y : b.y + BOX.h}`
        : `M${x1},${y1} C${(x1 + x2) / 2},${y1} ${(x1 + x2) / 2},${y2} ${x2},${y2}`;
      root.append(svg("path", { d, class: "gedge", "marker-end": "url(#arrow)" }));
      const label = same
        ? svg("text", { x: a.x + BOX.w / 2 + 8, y: (a.y + b.y + BOX.h) / 2 + 4, class: "gedgelabel" })
        : svg("text", { x: (x1 + x2) / 2, y: (y1 + y2) / 2 - 5, class: "gedgelabel", "text-anchor": "middle" });
      label.textContent = e.type.toLowerCase().replace(/_/g, " ");
      root.append(label);
    }
    for (const n of graph.nodes) {
      const p = pos.get(n.id);
      if (!p) continue;
      const [one, two] = caption(n);
      const t1 = svg("text", { x: p.x + 12, y: p.y + 23, class: "gtitle" }); t1.textContent = one;
      const t2 = svg("text", { x: p.x + 12, y: p.y + 42, class: "gsub" }); t2.textContent = two;
      root.append(svg("g", { class: "gnode " + kindOf(n) }, svg("rect", { x: p.x, y: p.y, width: BOX.w, height: BOX.h, rx: 10 }), t1, t2));
    }
    return root;
  }

  function list(graph) {
    const items = document.createElement("ul");
    items.className = "graphlist";
    const names = new Map(graph.nodes.map((n) => [n.id, caption(n).join(" — ")]));
    for (const e of graph.edges) {
      const li = document.createElement("li");
      li.textContent = `${names.get(e.src) || e.src} → ${e.type.toLowerCase().replace(/_/g, " ")} → ${names.get(e.dst) || e.dst}`;
      items.append(li);
    }
    if (!graph.edges.length) {
      const li = document.createElement("li");
      li.textContent = "This run has no linked items to show.";
      items.append(li);
    }
    return items;
  }

  // Fetches the graph for a receipt name and fills the section. Never throws: a failure only hides it.
  async function show(name) {
    const section = document.getElementById("graph");
    const body = document.getElementById("graph-body");
    try {
      const response = await fetch("/api/graph?name=" + encodeURIComponent(name), { headers: { Accept: "application/json" } });
      if (!response.ok) throw new Error("no graph");
      const graph = await response.json();
      body.replaceChildren(draw(graph), document.createElement("details"));
      const details = body.querySelector("details");
      const summary = document.createElement("summary");
      summary.textContent = "The same graph as a list";
      details.append(summary, list(graph));
      const stats = graph.actions_by_status
        ? " Counted by the database: " + Object.entries(graph.actions_by_status).map(([k, v]) => `${v} ${k}`).join(", ") + "."
        : "";
      document.getElementById("graph-note").textContent =
        (graph.source === "falkordb" ? "Stored in and read back from FalkorDB on this computer." : graph.note || "") + stats;
      section.hidden = false;
      if (typeof fx === "object") fx.reveal([section]);
    } catch (error) {
      section.hidden = true;
    }
  }

  return { show, draw, place };
})();
