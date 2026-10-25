/* VibeGuard issue explorer: an interactive view of a report's issues, shown above the issue list.
 *
 * Every place an issue was found is a tile in a slowly turning cloud (drag to spin it). Tiles are coloured
 * by severity; probable false alarms are grey. Clicking a tile brings that issue forward with its tags
 * (severity, standard, CWE, kind, places, AI verdict) around it; clicking a tag searches for it. The search
 * pill filters by title, CWE, OWASP control, kind or file. Three short captions walk a first-time reader
 * through it.
 *
 * Usage: VGExplorer.render(report, { onOpen(issue), onDone() }) returns the element. Works for the free
 * (locked) report too, which has titles, severities and standards but no locations.
 * All report content comes from an untrusted app, so it is only ever inserted as text.
 */
(() => {
  "use strict";
  const SEVERITIES = ["critical", "warning", "smell"];
  const SEV_LABEL = { critical: "Critical", warning: "Warning", smell: "Smell" };
  const KIND_ICON = { secret: "🔑", security: "🛡️", bug: "🐞", smell: "🧹", logic: "💡" };
  const TARGET_TILES = 54;  // enough tiles for a full-looking cloud; each issue gets a share by how often it occurs
  const reducedMotion = () => window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches;
  const t = (s) => (window.VG ? VG.translate(s) : s);

  function el(tag, attrs = {}, ...children) {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (k === "class") node.className = v;
      else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
      else node.setAttribute(k, v);
    }
    for (const c of children.flat()) {
      if (c === null || c === undefined || c === false) continue;
      node.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return node;
  }

  // Every issue once, with what the tiles, tags and search need.
  function collect(report) {
    const out = [];
    for (const sev of SEVERITIES) {
      for (const issue of (report.issues || {})[sev] || []) out.push({ issue, severity: sev, alarm: false });
    }
    for (const issue of report.false_alarms || []) out.push({ issue, severity: issue.severity, alarm: true });
    for (const item of out) {
      const i = item.issue, std = i.standard || {};
      const files = (i.locations || []).map((l) => l.file.replace(/^sources\//, ""));
      item.kindLabel = i.kind_label || { secret: "Leaked secret", security: "Security", bug: "Likely bug", smell: "Code quality" }[i.kind] || "";
      item.tags = [
        { text: SEV_LABEL[item.severity], cls: item.severity },
        std.control ? { text: std.control } : null,
        std.cwe ? { text: std.cwe } : null,
        item.kindLabel ? { text: item.kindLabel } : null,
        { text: i.occurrences === 1 ? "1 place" : `${i.occurrences} places` },
        item.alarm ? { text: "Probably a false alarm", cls: "alarm" } : null,
      ].filter(Boolean);
      item.haystack = [i.title, SEV_LABEL[item.severity], t(SEV_LABEL[item.severity]), std.control, std.cwe, item.kindLabel,
        t(item.kindLabel), i.rule_id, item.alarm ? "false alarm" : "", ...files].join(" ").toLowerCase();
    }
    return out;
  }

  // How many tiles each issue gets: at least one, more for issues found in more places.
  function tileCounts(items) {
    const weights = items.map((it) => Math.log2((it.issue.occurrences || 1) + 1));
    const sum = weights.reduce((a, b) => a + b, 0) || 1;
    const target = Math.max(items.length, TARGET_TILES);
    return weights.map((w) => Math.max(1, Math.min(8, Math.round((w / sum) * target))));
  }

  function render(report, opts = {}) {
    const items = collect(report);
    if (!items.length) return null;
    const counts = tileCounts(items);
    const places = items.reduce((n, it) => n + (it.issue.occurrences || 1), 0);

    // Tiles of one issue are spread over the cloud by dealing them out round-robin.
    const order = [];
    for (let round = 0; order.length < counts.reduce((a, b) => a + b, 0); round++) {
      items.forEach((it, k) => { if (round < counts[k]) order.push(k); });
    }

    const stage = el("div", { class: "vgx-stage", "aria-label": "Issue explorer" });
    const cloud = el("div", { class: "vgx-cloud" });
    const n = order.length;
    const tiles = order.map((k, idx) => {
      const it = items[k];
      // Fibonacci sphere: evenly spread points.
      const y = 1 - (2 * (idx + 0.5)) / n, r = Math.sqrt(1 - y * y), phi = idx * Math.PI * (3 - Math.sqrt(5));
      const first = order.indexOf(k) === idx;
      const node = el("button", {
        type: "button", class: `vgx-tile ${it.alarm ? "alarm" : it.severity}`,
        "aria-label": `${t(SEV_LABEL[it.severity])}: ${it.issue.title}`, title: it.issue.title,
        tabindex: first ? "0" : "-1", onclick: (e) => { e.stopPropagation(); focusIssue(k); },
      }, el("span", { "aria-hidden": "true" }, KIND_ICON[it.issue.kind] || "•"));
      cloud.append(node);
      return { node, k, x: Math.cos(phi) * r, y, z: Math.sin(phi) * r };
    });

    // ---- centre pill: status, then search
    const status = el("span", { class: "vgx-status" }, "Analysing…");
    const input = el("input", { class: "vgx-input", type: "search", placeholder: "Search issues, CWE, file…",
      "aria-label": "Search issues", autocomplete: "off", spellcheck: "false" });
    const matches = el("span", { class: "vgx-matches", "aria-live": "polite" });
    const pill = el("div", { class: "vgx-pill" },
      el("svg", { class: "vgx-glass", viewBox: "0 0 24 24", "aria-hidden": "true" }), status, input, matches);
    pill.querySelector("svg").innerHTML = '<circle cx="11" cy="11" r="6.5"/><path d="m16 16 4 4"/>';
    pill.addEventListener("click", () => { if (step < 2) go(2); input.focus(); });

    // ---- focused issue
    const focus = el("div", { class: "vgx-focus", hidden: "" });

    // ---- captions
    const STEPS = [
      ["Everything we found", "Each tile is one place in your code: red is critical, amber a warning, blue a smell, grey a probable false alarm. Drag to spin it."],
      ["Every issue, tagged", "Tap any tile to see its severity, its security standard and how many places it's in."],
      ["Find anything", "Search by name, CWE, OWASP control, kind or file name."],
    ];
    const capTitle = el("h3", {}), capText = el("p", {});
    const dots = el("div", { class: "vgx-dots" }, STEPS.map(() => el("span", {})));
    const next = el("button", { type: "button", class: "vgx-next", onclick: () => (step < 2 ? go(step + 1) : opts.onDone && opts.onDone()) });
    const caption = el("div", { class: "vgx-caption" }, capTitle, capText, el("div", { class: "vgx-row" }, dots, next));

    const root = el("section", { class: "vgx" }, stage, caption);
    stage.append(cloud, pill, focus);

    // ---- motion: auto-turn, drag to spin
    let angleY = 0.6, angleX = -0.28, spin = reducedMotion() ? 0 : 0.0032, dragging = null, raf = 0, query = "", focused = -1;
    const visible = () => root.isConnected;
    function frame() {
      if (!visible()) { cancelAnimationFrame(raf); return; }
      if (!dragging) angleY += spin;
      const w = stage.clientWidth, h = stage.clientHeight, R = Math.min(w * 0.42, h * 0.38);
      const cy = Math.cos(angleY), sy = Math.sin(angleY), cx = Math.cos(angleX), sx = Math.sin(angleX);
      for (const tile of tiles) {
        const x1 = tile.x * cy + tile.z * sy, z1 = -tile.x * sy + tile.z * cy;
        const y2 = tile.y * cx - z1 * sx, z2 = tile.y * sx + z1 * cx;
        const p = 2.6 / (2.6 - z2);  // perspective
        const hit = !query || items[tile.k].haystack.includes(query);
        const isFocus = focused === tile.k;
        let scale = p * (hit && query ? 1.25 : 1), alpha = 0.3 + 0.7 * ((z2 + 1) / 2);
        if (query && !hit) { scale *= 0.75; alpha *= 0.14; }
        if (focused >= 0 && !isFocus) alpha *= 0.25;
        tile.node.style.transform = `translate(-50%, -50%) translate(${x1 * R * p}px, ${y2 * R * p}px) scale(${scale})`;
        tile.node.style.opacity = alpha.toFixed(3);
        tile.node.style.zIndex = String(Math.round((z2 + 1) * 50) + (hit && query ? 100 : 0));
        tile.node.classList.toggle("hit", Boolean(query && hit));
      }
      raf = requestAnimationFrame(frame);
    }
    stage.addEventListener("pointerdown", (e) => {
      if (e.target.closest(".vgx-pill, .vgx-focus")) return;
      dragging = { x: e.clientX, y: e.clientY, ay: angleY, ax: angleX, moved: false };
    });
    window.addEventListener("pointermove", (e) => {
      if (!dragging) return;
      const dx = e.clientX - dragging.x, dy = e.clientY - dragging.y;
      if (Math.abs(dx) + Math.abs(dy) > 4) dragging.moved = true;
      angleY = dragging.ay + dx * 0.008;
      angleX = Math.max(-1.1, Math.min(1.1, dragging.ax - dy * 0.006));
    });
    window.addEventListener("pointerup", () => { dragging = null; });
    stage.addEventListener("click", (e) => {
      if (!e.target.closest(".vgx-tile, .vgx-pill, .vgx-focus") && focused >= 0) closeFocus();
    });

    // ---- search
    function setQuery(value) {
      query = value.trim().toLowerCase();
      const found = query ? items.filter((it) => it.haystack.includes(query)).length : 0;
      matches.textContent = !query ? "" : found === 0 ? "No matches" : found === 1 ? "1 match" : `${found} matches`;
    }
    input.addEventListener("input", () => { stopDemo(); closeFocus(); setQuery(input.value); });
    input.addEventListener("keydown", (e) => { if (e.key === "Escape") { input.value = ""; setQuery(""); } });

    // ---- focus an issue: it comes forward with its tags around it
    function focusIssue(k) {
      stopDemo();
      focused = k;
      const it = items[k], i = it.issue;
      const spots = ["tl", "tr", "r", "br", "bl", "l"];
      focus.replaceChildren(
        el("div", { class: `vgx-card ${it.alarm ? "alarm" : it.severity}` },
          el("div", { class: "vgx-icon", "aria-hidden": "true" }, KIND_ICON[i.kind] || "•"),
          el("h4", {}, i.title),
          el("div", { class: "vgx-actions" },
            opts.onOpen ? el("button", { type: "button", class: "vgx-open", onclick: () => opts.onOpen(i) }, "Show in report") : null,
            el("button", { type: "button", class: "vgx-close", "aria-label": "Close", onclick: closeFocus }, "×"))),
        ...it.tags.map((tag, n) => el("button", {
          type: "button", class: `vgx-tag ${spots[n % spots.length]} ${tag.cls || ""}`, style: `animation-delay:${n * 70}ms`,
          title: "Search for this", onclick: () => { closeFocus(); go(2, false); input.value = tag.text; setQuery(tag.text); },
        }, tag.text)));
      focus.hidden = false;
      if (step === 0) go(1, false);
    }
    function closeFocus() { focused = -1; focus.hidden = true; }
    stage.addEventListener("keydown", (e) => { if (e.key === "Escape" && focused >= 0) closeFocus(); });

    // ---- the self-typing search demo (uses terms from this report)
    let demoTimer = 0;
    function stopDemo() { clearTimeout(demoTimer); demoTimer = 0; }
    function demo() {
      const terms = [...new Set(items.flatMap((it) => [it.issue.standard && it.issue.standard.control, it.kindLabel]).filter(Boolean))].slice(0, 3);
      if (!terms.length || reducedMotion()) return;
      let ti = 0, ci = 0, deleting = false;
      const tick = () => {
        const term = terms[ti % terms.length];
        if (!deleting) { ci++; if (ci >= term.length) { deleting = true; demoTimer = setTimeout(tick, 1600); input.value = term; setQuery(term); return; } }
        else { ci--; if (ci <= 0) { deleting = false; ti++; } }
        input.value = term.slice(0, ci);
        setQuery(input.value);
        if (ti >= terms.length * 2) { input.value = ""; setQuery(""); return; }
        demoTimer = setTimeout(tick, deleting ? 35 : 85);
      };
      demoTimer = setTimeout(tick, 500);
    }

    // ---- steps
    let step = -1;
    function go(s, auto = true) {
      step = s;
      capTitle.textContent = STEPS[s][0];
      capText.textContent = STEPS[s][1];
      [...dots.children].forEach((d, n) => d.classList.toggle("on", n === s));
      next.textContent = s < 2 ? "Continue" : "See all issues ↓";
      pill.classList.toggle("searching", s === 2);
      if (s === 1 && auto) {
        const top = items.findIndex((it) => !it.alarm);
        focusIssue(top >= 0 ? top : 0);
      }
      if (s === 2) {
        if (auto) { closeFocus(); demo(); }
      } else { stopDemo(); input.value = ""; setQuery(""); }
    }

    go(0);
    setTimeout(() => {
      status.textContent = items.length === 1 ? `1 issue · ${places} places` : `${items.length} issues · ${places} places`;
    }, reducedMotion() ? 0 : 1500);
    raf = requestAnimationFrame(frame);
    return root;
  }

  const style = document.createElement("style");
  style.textContent = `
.vgx{margin:18px 0;border-radius:18px;overflow:hidden;color:#f4f2ff;
  background:radial-gradient(120% 70% at 50% 108%,#ff7a59 0%,#e0559a 26%,#7a4bd8 52%,#241a6b 76%,#0d0f2e 100%);
  box-shadow:0 10px 40px rgba(20,10,60,.25)}
.vgx-stage{position:relative;height:430px;touch-action:none;cursor:grab;user-select:none}
.vgx-stage:active{cursor:grabbing}
.vgx-cloud{position:absolute;left:50%;top:46%;width:0;height:0}
.vgx-tile{position:absolute;left:0;top:0;width:34px;height:34px;border-radius:9px;border:1px solid rgba(255,255,255,.35);
  display:grid;place-items:center;font-size:16px;line-height:1;cursor:pointer;padding:0;will-change:transform,opacity;
  box-shadow:0 4px 14px rgba(0,0,0,.25);transition:box-shadow .2s,border-color .2s}
.vgx-tile.critical{background:linear-gradient(145deg,#ff8a7a,#d63a2f)}
.vgx-tile.warning{background:linear-gradient(145deg,#ffd27a,#e0951f)}
.vgx-tile.smell{background:linear-gradient(145deg,#9cc0ff,#4f73d9)}
.vgx-tile.alarm{background:linear-gradient(145deg,#c9cbd6,#7d8193)}
.vgx-tile.hit{border-color:#fff;box-shadow:0 0 0 2px rgba(255,255,255,.75),0 0 22px rgba(255,255,255,.55)}
.vgx-tile:focus-visible{outline:2px solid #fff;outline-offset:2px}
.vgx-pill{position:absolute;left:50%;top:46%;transform:translate(-50%,-50%);z-index:300;display:flex;align-items:center;gap:8px;
  width:min(320px,78%);padding:10px 16px;border-radius:999px;cursor:text;
  background:rgba(30,26,70,.55);border:1px solid rgba(255,255,255,.22);backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px)}
.vgx-glass{width:16px;height:16px;flex:none;fill:none;stroke:#fff;stroke-width:2;stroke-linecap:round;opacity:.8}
.vgx-status{flex:1;font:500 14px var(--body,system-ui);opacity:.9;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.vgx-input{flex:1;min-width:0;display:none;background:none;border:none;outline:none;color:#fff;font:500 14px var(--body,system-ui)}
.vgx-input::placeholder{color:rgba(255,255,255,.6)}
.vgx-pill.searching .vgx-status{display:none}.vgx-pill.searching .vgx-input{display:block}
.vgx-matches{font:500 11.5px var(--mono,monospace);opacity:.75;white-space:nowrap}
.vgx-focus{position:absolute;inset:0;z-index:400;display:grid;place-items:center;pointer-events:none}
.vgx-focus[hidden]{display:none}
.vgx-card{pointer-events:auto;width:min(270px,70%);padding:18px 18px 14px;border-radius:16px;text-align:center;
  background:rgba(24,20,60,.72);border:1px solid rgba(255,255,255,.25);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);
  box-shadow:0 18px 50px rgba(0,0,0,.4);animation:vgx-pop .35s cubic-bezier(.2,.9,.3,1.2)}
.vgx-card.critical{border-top:4px solid #ff6b5e}.vgx-card.warning{border-top:4px solid #f2b84b}
.vgx-card.smell{border-top:4px solid #7aa7ff}.vgx-card.alarm{border-top:4px solid #a7abbb}
.vgx-icon{font-size:30px;line-height:1;margin-bottom:8px}
.vgx-card h4{margin:0 0 12px;font:700 15.5px/1.35 var(--display,system-ui);color:#fff}
.vgx-actions{display:flex;gap:8px;justify-content:center}
.vgx-actions button,.vgx-next{font:600 13px var(--body,system-ui);border-radius:999px;cursor:pointer}
.vgx-open{padding:7px 14px;border:none;background:#fff;color:#1d1640}
.vgx-close{width:32px;padding:0;border:1px solid rgba(255,255,255,.35);background:none;color:#fff;font-size:18px!important}
.vgx-tag{pointer-events:auto;position:absolute;padding:6px 12px;border-radius:999px;cursor:pointer;color:#fff;
  font:600 12px var(--body,system-ui);background:rgba(30,26,70,.7);border:1px solid rgba(255,255,255,.28);
  backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);animation:vgx-in .4s both,vgx-float 4s ease-in-out infinite;white-space:nowrap}
.vgx-tag.critical{background:rgba(214,58,47,.75)}.vgx-tag.warning{background:rgba(224,149,31,.75)}
.vgx-tag.smell{background:rgba(79,115,217,.75)}.vgx-tag.alarm{background:rgba(125,129,147,.8)}
.vgx-tag.tl{left:8%;top:14%}.vgx-tag.tr{right:8%;top:16%}.vgx-tag.r{right:5%;top:47%}
.vgx-tag.br{right:12%;bottom:12%}.vgx-tag.bl{left:10%;bottom:14%}.vgx-tag.l{left:4%;top:50%}
.vgx-caption{padding:16px 22px 18px;text-align:center}
.vgx-caption h3{margin:0 0 4px;font:700 18px var(--display,system-ui);color:#fff}
.vgx-caption p{margin:0 auto 14px;max-width:520px;font-size:13.5px;line-height:1.5;color:rgba(255,255,255,.85)}
.vgx-row{display:flex;align-items:center;justify-content:center;gap:16px}
.vgx-dots{display:flex;gap:6px}.vgx-dots span{width:7px;height:7px;border-radius:50%;background:rgba(255,255,255,.35);transition:all .25s}
.vgx-dots span.on{width:20px;border-radius:4px;background:#fff}
.vgx-next{padding:10px 26px;border:1px solid rgba(255,255,255,.35);background:rgba(255,255,255,.16);color:#fff;
  backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px)}
.vgx-next:hover{background:rgba(255,255,255,.26)}
@keyframes vgx-pop{from{transform:scale(.6);opacity:0}to{transform:none;opacity:1}}
@keyframes vgx-in{from{opacity:0;transform:scale(.6)}to{opacity:1;transform:none}}
@keyframes vgx-float{0%,100%{translate:0 0}50%{translate:0 -6px}}
.issue.vgx-flash{animation:vgx-flash 1.6s ease}
@keyframes vgx-flash{0%,40%{box-shadow:0 0 0 3px var(--accent,#6fbf33)}100%{box-shadow:none}}
@media (max-width:560px){.vgx-stage{height:360px}.vgx-tile{width:28px;height:28px;font-size:13px;border-radius:7px}
  .vgx-tag{font-size:11px;padding:5px 9px}.vgx-tag.l,.vgx-tag.r{display:none}}
@media (prefers-reduced-motion:reduce){.vgx-card,.vgx-tag{animation:none}}`;
  document.head.append(style);

  window.VGExplorer = { render };
})();
