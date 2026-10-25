/* VibeGuard landing page. Settings come from site-config.js (window.VG_SITE):
 *   appUrl:           "" = the app runs on this same site (/app); a URL = the app runs there;
 *                     null = no app online yet, so the "try it" buttons open the waitlist instead.
 *   supabaseUrl/Key:  where waitlist sign-ups are saved (Supabase table "waitlist", anon key: insert only).
 *   contactEmail:     shown in the footer when set.
 * Without Supabase settings the form posts to the VibeGuard server's /waitlist instead.
 */
(() => {
  "use strict";
  // An old Supabase sign-in redirect may land here: hand it to the scanner page, which finishes it.
  if (location.hash.includes("access_token")) { location.replace("/app" + location.hash); return; }
  const $ = (id) => document.getElementById(id);
  const t = (s) => (window.VG ? VG.translate(s) : s);
  const site = window.VG_SITE || { appUrl: "" };
  const app = site.appUrl === null || site.appUrl === undefined ? null : String(site.appUrl).replace(/\/$/, "");

  if (app === null) {
    // No app online yet: the "try it" buttons lead to the waitlist.
    for (const [id, label] of [["nav-cta", "Get early access"], ["hero-cta", "Get early access →"]]) {
      $(id).href = "#apply";
      $(id).textContent = label;
    }
    $("free-line").textContent = "The free scan opens soon. Join the waitlist to be the first to try it.";
    // (this also removes the link to the example report, which needs the app; the page shows an example instead)
    $("nav-apply").hidden = true;  // both buttons would open the waitlist: keep one
    $("hero-apply").hidden = true;
  } else if (app) {
    $("nav-cta").href = `${app}/app`;
    $("hero-cta").href = `${app}/app`;
    $("example-link").href = `${app}/app#example`;
  }

  // A plan's "Apply for waitlist" button picks that package in the form.
  document.querySelectorAll("[data-package]").forEach((a) =>
    a.addEventListener("click", () => { $("package").value = a.dataset.package; }));

  const form = $("waitlist"), msg = $("apply-msg");
  const say = (kind, text) => { msg.className = `msg ${kind}`; msg.textContent = t(text); };
  async function save(entry) {
    if (site.supabaseUrl && site.supabaseAnonKey) {
      const res = await fetch(`${site.supabaseUrl}/rest/v1/waitlist`, {
        method: "POST",
        headers: { apikey: site.supabaseAnonKey, Authorization: `Bearer ${site.supabaseAnonKey}`,
                   "Content-Type": "application/json", Prefer: "return=minimal" },
        body: JSON.stringify({ ...entry, package: entry.package || null, link: entry.link || null,
                               source: location.hostname.slice(0, 40) }),
      });
      if (!res.ok) throw new Error("We couldn't save that. Please check your email address and try again.");
      return;
    }
    const res = await fetch("/waitlist", { method: "POST", body: new URLSearchParams(entry) });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.detail || "We couldn't save that. Please try again.");
  }
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const data = new FormData(form);
    if (data.get("website")) { form.reset(); say("ok", "Thanks! We'll write back soon."); return; }  // a bot filled the hidden field
    const entry = { name: String(data.get("name") || "").trim(), email: String(data.get("email") || "").trim().toLowerCase(),
                    package: String(data.get("package") || ""), link: String(data.get("link") || "").trim() };
    if (!entry.name || !entry.email) { say("err", "Please enter your name and email."); return; }
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(entry.email)) { say("err", "Please enter a valid email address."); return; }
    $("apply-btn").disabled = true;
    try {
      await save(entry);
      form.reset();
      say("ok", "Thanks! We'll write back soon.");
    } catch (err) {
      say("err", String(err.message || err));
    } finally {
      $("apply-btn").disabled = false;
    }
  });

  if (site.contactEmail) {
    const c = $("contact");
    c.textContent = site.contactEmail;
    c.href = `mailto:${site.contactEmail}`;
    c.hidden = false;
  }
  if (app !== "") return;  // prices and sign-in state come from the app server when it is this same site
  fetch("/health").then((r) => r.json()).then((h) => {
    const money = (c) => `$${(c / 100).toFixed(c % 100 ? 2 : 0)}`;
    for (const p of h.plans || []) {
      const el = document.querySelector(`.plan[data-plan="${p.id}"] .price`);
      if (el) el.textContent = p.price_android_cents ? `${money(p.price_cents)}–${money(p.price_android_cents)}` : money(p.price_cents);
    }
    if (h.payments_mode === "demo") $("demo-note").hidden = false;
    return fetch("/limits").then((r) => r.json());
  }).then((l) => {
    if (l && l.signed_in) { $("nav-cta").textContent = "Open VibeGuard"; $("hero-cta").textContent = "Open VibeGuard →"; }
  }).catch(() => {});
})();
