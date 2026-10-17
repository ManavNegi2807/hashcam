// Turns an answer's plain text into readable blocks: headings, bullet lists, paragraphs, **bold**.
// Built only from DOM nodes and textContent, never as markup, so a hostile answer cannot inject
// anything. Display only.
"use strict";

function richInline(parent, text) {
  // **bold**, `code`, [label](https://link) and bare https:// links; everything else is plain text.
  const pattern = /(\*\*[^*]+\*\*|`[^`]+`|\[[^\]]+\]\(https?:\/\/[^\s)]+\)|https?:\/\/[^\s)<>\]]+)/g;
  for (const part of text.split(pattern)) {
    if (!part) continue;
    const md = /^\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)$/.exec(part);
    if (md || /^https?:\/\/\S+$/.test(part)) {
      const link = document.createElement("a");
      link.href = md ? md[2] : part;
      link.textContent = md ? md[1] : part;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      parent.appendChild(link);
      continue;
    }
    if (part.startsWith("**") && part.endsWith("**") && part.length > 4) {
      const strong = document.createElement("strong");
      strong.textContent = part.slice(2, -2);
      parent.appendChild(strong);
    } else if (part.startsWith("`") && part.endsWith("`") && part.length > 2) {
      const code = document.createElement("code");
      code.textContent = part.slice(1, -1);
      parent.appendChild(code);
    } else {
      parent.appendChild(document.createTextNode(part));
    }
  }
}

function renderRich(text) {
  const box = document.createElement("div");
  box.className = "rich";
  let list = null;
  let paragraph = null;
  const flush = () => { list = null; paragraph = null; };
  for (const raw of String(text).replace(/\r/g, "").split("\n")) {
    const line = raw.trim();
    if (!line) { flush(); continue; }
    const heading = /^#{1,4}\s+(.*)$/.exec(line);
    const bullet = /^(?:[-*•]|\d+[.)])\s+(.*)$/.exec(line);
    if (heading) {
      flush();
      const h = document.createElement("h4");
      richInline(h, heading[1]);
      box.appendChild(h);
    } else if (bullet) {
      paragraph = null;
      if (!list) { list = document.createElement("ul"); box.appendChild(list); }
      const li = document.createElement("li");
      richInline(li, bullet[1]);
      list.appendChild(li);
    } else {
      list = null;
      if (!paragraph) { paragraph = document.createElement("p"); box.appendChild(paragraph); }
      else paragraph.appendChild(document.createTextNode(" "));
      richInline(paragraph, line);
    }
  }
  return box;
}
