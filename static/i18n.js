/* VibeGuard languages: English (the source text) and German.
 *
 * The pages are written in English. When German is selected, every text node and the placeholder /
 * aria-label / title attributes are looked up in window.VG_DE (static/i18n-de.js): first as an exact
 * sentence, then against patterns for sentences with numbers or names in them. Text that is not in the
 * dictionary (file paths, code, tokens, AI-written text) is left as it is. A MutationObserver translates
 * whatever the page adds later, so the page code itself stays in English and keeps working unchanged.
 *
 * The choice is kept in localStorage and in a "vg_lang" cookie, which the server reads to have the AI
 * write paid reports and fix summaries in the same language.
 */
(() => {
  "use strict";
  const KEY = "vibeguard.lang";
  const SKIP = "script, style, pre, code, textarea, .token, .where, .diff, [data-no-i18n]";
  const ATTRS = ["placeholder", "aria-label", "title"];

  function chosen() {
    try {
      const saved = localStorage.getItem(KEY);
      if (saved === "en" || saved === "de") return saved;
    } catch { /* storage blocked */ }
    return (navigator.language || "").toLowerCase().startsWith("de") ? "de" : "en";
  }
  let lang = chosen();
  const original = new WeakMap();   // text node -> its English text
  const shown = new WeakMap();      // text node -> what we last wrote into it
  const originalAttr = new WeakMap();

  const squash = (s) => s.replace(/\s+/g, " ").trim();
  let compiled = null;
  function patterns() {
    if (!compiled) compiled = ((window.VG_DE || {}).patterns || []).map(([re, to]) => [new RegExp(`^${re}$`, "s"), to]);
    return compiled;
  }

  // A captured value: a known sentence, or English with the known terms swapped (e.g. "8 Java files").
  function part(value) {
    if (value === undefined) return "";
    const dict = window.VG_DE;
    if (dict.exact[value] !== undefined) return dict.exact[value];
    let out = value;
    for (const [en, de] of dict.terms || []) out = out.split(en).join(de);
    return out;
  }

  function translate(text) {
    const dict = window.VG_DE;
    if (!dict) return text;
    const key = squash(text);
    if (!key || !/[A-Za-z]/.test(key)) return text;
    let out = dict.exact[key];
    if (out === undefined) {
      for (const [re, to] of patterns()) {
        if (re.test(key)) {
          out = key.replace(re, (...m) => to.replace(/\$(\d)/g, (_, n) => part(m[n])));
          break;
        }
      }
    }
    if (out === undefined) return text;
    const lead = text.match(/^\s*/)[0], trail = text.match(/\s*$/)[0];
    return lead + out + trail;
  }

  function skipped(node) {
    const el = node.nodeType === 1 ? node : node.parentElement;
    return !el || !!el.closest(SKIP);
  }

  // force: a language switch - re-translate from the English we kept, unless the page has since put new text there.
  function doText(node, force = false) {
    if (skipped(node)) return;
    const ours = shown.get(node) === node.nodeValue;  // unchanged since we last wrote it
    if (ours && !force) return;
    const source = ours && original.has(node) ? original.get(node) : node.nodeValue;
    original.set(node, source);
    const value = lang === "de" ? translate(source) : source;
    shown.set(node, value);
    if (value !== node.nodeValue) node.nodeValue = value;
  }

  function doAttrs(el) {
    if (el.closest(SKIP)) return;
    let saved = originalAttr.get(el);
    if (!saved) { saved = {}; originalAttr.set(el, saved); }
    for (const a of ATTRS) {
      if (!el.hasAttribute(a)) continue;
      const now = el.getAttribute(a);
      if (saved[a] === undefined || (now !== saved[`${a}:shown`])) saved[a] = now;
      const value = lang === "de" ? translate(saved[a]) : saved[a];
      saved[`${a}:shown`] = value;
      if (value !== now) el.setAttribute(a, value);
    }
  }

  function walk(root, force = false) {
    if (root.nodeType === 3) { doText(root, force); return; }
    if (root.nodeType !== 1) return;
    doAttrs(root);
    const it = document.createTreeWalker(root, NodeFilter.SHOW_TEXT | NodeFilter.SHOW_ELEMENT);
    for (let n = it.nextNode(); n; n = it.nextNode()) n.nodeType === 3 ? doText(n, force) : doAttrs(n);
  }

  // Switching language: put the English back first, then translate again.
  function restoreAll() {
    const it = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT | NodeFilter.SHOW_ELEMENT);
    for (let n = it.nextNode(); n; n = it.nextNode()) {
      if (n.nodeType === 3 && original.has(n) && shown.get(n) === n.nodeValue) {
        n.nodeValue = original.get(n);
        shown.set(n, n.nodeValue);
      } else if (n.nodeType === 1 && originalAttr.has(n)) {
        const saved = originalAttr.get(n);
        for (const a of ATTRS) if (saved[a] !== undefined) { n.setAttribute(a, saved[a]); saved[`${a}:shown`] = saved[a]; }
      }
    }
  }

  function setLang(next) {
    lang = next;
    try { localStorage.setItem(KEY, next); } catch { /* storage blocked */ }
    document.cookie = `vg_lang=${next}; path=/; max-age=31536000; samesite=lax`;
    document.documentElement.lang = next;
    restoreAll();
    walk(document.body, true);
    const t = document.querySelector("title");
    if (t) { if (!t.dataset.en) t.dataset.en = t.textContent; t.textContent = next === "de" ? translate(t.dataset.en) : t.dataset.en; }
    document.querySelectorAll("[data-lang-switch] button").forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.lang === next)));
    window.dispatchEvent(new CustomEvent("vg-lang", { detail: next }));
  }

  function addSwitch() {
    const host = document.querySelector("[data-lang-host]");
    if (!host || host.querySelector("[data-lang-switch]")) return;
    const box = document.createElement("span");
    box.setAttribute("data-lang-switch", "");
    box.setAttribute("data-no-i18n", "");
    box.className = "lang-switch";
    box.setAttribute("role", "group");
    box.setAttribute("aria-label", "Language / Sprache");
    for (const [code, label] of [["en", "EN"], ["de", "DE"]]) {
      const b = document.createElement("button");
      b.type = "button";
      b.dataset.lang = code;
      b.textContent = label;
      b.title = code === "en" ? "English" : "Deutsch";
      b.addEventListener("click", () => setLang(code));
      box.append(b);
    }
    host.prepend(box);
  }

  const style = document.createElement("style");
  style.textContent = `.lang-switch{display:inline-flex;gap:2px;padding:2px;border:1px solid var(--border);border-radius:8px;background:var(--card,transparent);vertical-align:middle;margin-right:10px}
    .lang-switch button{font:600 11.5px var(--mono,monospace);letter-spacing:.04em;border:none;background:none;color:var(--muted);padding:4px 7px;border-radius:6px;cursor:pointer}
    .lang-switch button[aria-pressed="true"]{background:var(--accent);color:var(--accent-text)}`;
  document.head.append(style);

  function start() {
    addSwitch();
    setLang(lang);
    new MutationObserver((changes) => {
      for (const c of changes) {
        if (c.type === "characterData") doText(c.target);
        else if (c.type === "attributes") doAttrs(c.target);
        else c.addedNodes.forEach(walk);
      }
    }).observe(document.body, { childList: true, subtree: true, characterData: true, attributes: true, attributeFilter: ATTRS });
  }
  window.VG = { translate: (s) => (lang === "de" ? translate(s) : s), lang: () => lang, setLang };
  document.readyState === "loading" ? document.addEventListener("DOMContentLoaded", start) : start();
})();
