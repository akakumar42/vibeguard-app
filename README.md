# VibeGuard

> Scan · explain · fix. The user interface is branded VibeGuard; the deep reverse-engineering engine is built on
> [REA](https://www.npmjs.com/package/rea-agents) (`rea-agents`), recorded as `rea` in every report's tool versions.

Scan an Android app (.apk) or a website you own or are authorized to test, and get a plain-English
report of how it works and what's wrong with it — grouped into **Critical / Warning / Smell**.

Reverse engineering is done by [REA](https://github.com/morluto/rea) (Reverse Engineer Anything); the bug
engine, severity policy, AI explanations and report are this project.

```
apk ─► REA: manifest + class inventory + the app's own code, method by method (evidence IDs)
         └─ jadx --no-src for XML resources
url ─► safety + ownership checks ─► HTTP checks ─► REA: headless Chrome capture of the page's JavaScript
    ─► bug engine: Semgrep (rules/android.yml | rules/web.yml) + Gitleaks + manifest / HTTP checks
    ─► severity policy (OWASP MASVS v2 | OWASP ASVS 4.0, CWE) ─► triage ─► LLM explains ─► report
```

Pick the decompiler per scan with the **Fast · jadx / Deep · REA** switch on the page (or the `engine`
form field on `POST /scan`: `jadx`, `rea` or `auto`). Without it the server uses `APK_ENGINE`
(default `auto` = REA when installed). Both find the same issues; jadx takes ~1 minute, REA ~13.
If REA fails, or an app is too large for it, the scan falls back to jadx and the report says so.

Every APK's signature is checked with Google's **apksig** library (the code behind `apksigner verify`),
whichever decompiler is used: invalid/missing signature, v1-only signing (Janus, CVE-2017-13156),
debug certificate, weak signing key. Setup: `java` plus `tools/apksig/apksig-9.3.3.jar`
(from `https://dl.google.com/android/maven2/com/android/tools/build/apksig/9.3.3/`, sha256 pinned in
`scanner/signing.py`).

Only small code snippets (~10k tokens) go to the LLM, never the whole app. Secrets are hidden before anything is sent.

**Run it in Docker on any computer (about 2 GB of memory, no server needed): see [DOCKER.md](DOCKER.md).**

## Languages (English, German)

The **EN | DE** switch in the header (German is picked automatically for German browsers; the choice is
remembered) translates every page: `static/i18n.js` looks each text up in `static/i18n-de.js`, which is generated
from `scanner/i18n_de.py` (`python -m scanner.i18n_de`): about 590 sentences, 98 patterns for sentences with
numbers or names, and all 59 rule texts. With German selected, the paid report's explanations, the fix summaries
and the structure review are written by the AI in German (the `vg_lang` cookie). Code, file paths, tokens and
the downloads (`fixes.patch`, PR description, text report) stay in English. The example report has a German copy,
`static/sample-report.de.json` (same scan, same fingerprint).

## Repeatable results

Which issues are reported, their severity and their order come only from the scanners and the severity
policy in `scanner/policy.py` (each rule mapped to OWASP MASVS v2 and a CWE id). The AI writes the
wording, gives a false-alarm opinion per issue, and lists extra **AI suggestions** that are kept separate
and not counted. An issue the AI judges a false alarm in every place it saw is moved out of the counts into
a "Probably false alarms" list (`report["false_alarms"]`; the scanner's own counts stay in
`report["ai_review"]["scanner_counts"]`). It is never re-rated or hidden.

So the same APK always gives the same `result_fingerprint`, with or without AI, and the same counts
without AI. With AI the counts can be lower by the issues listed as probable false alarms.
Every report records the engine, policy, rules and tool versions, since changing those can change results.

## Setup (macOS)

```bash
brew install jadx semgrep gitleaks node@24      # REA needs Node 22, 24 or 26+ (not 25); JDK 17+ too
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env          # then put your OpenRouter key in .env

# REA, pinned (tools/rea/package.json) + its JADX engine jar, checked against REA's pinned SHA-256
cd tools/rea && PATH="$(brew --prefix node@24)/bin:$PATH" npm ci && mkdir -p jar && cd jar
curl -fLO https://github.com/1013503897/jadx-headless-mcp/releases/download/v0.7.1/jadx-headless-mcp-0.7.1-all.jar
echo '6e5eacf500b64292bfb73c49797c1958f6ee44646e43e868039ae7feb573ff75  jadx-headless-mcp-0.7.1-all.jar' | shasum -a 256 -c -
```

Website scans also need Google Chrome (or set `CHROME_BIN`).

## Run

```bash
uvicorn api:app --reload
```

- **http://127.0.0.1:8000** – landing page (`static/landing.html`: what VibeGuard checks, how it works, pricing, FAQ).
  Its live preview is the real F-Droid example report, and prices and the free allowance are read from the server.
- **http://127.0.0.1:8000/app** – the scanner (sign in, then Android app / Website / Fix my code). Old links to
  `/?report=…` are forwarded to `/app?report=…`.
- **http://127.0.0.1:8000/#example** – opens a saved F-Droid report instantly (no scan, no AI - good backup for live demos)
- **http://127.0.0.1:8000/docs** – raw API

```bash

curl -F file=@app.apk -F i_am_authorized=true http://127.0.0.1:8000/scan
```

`POST /scan` (multipart form):

| field | | |
|---|---|---|
| `file` | required | the .apk |
| `i_am_authorized` | required | must be `true`, otherwise 403 |
| `engine` | default `APK_ENGINE` | `jadx` (~1 min), `rea` (~13 min) or `auto` |
| `use_ai` | default `true` | only with `PAYWALL=off`: `false` = same issues, standard rule wording |
| `include_text` | default `true` | also return `report_text` (readable version) |

With the paywall on (default) this returns the free result: `{"report": {"locked": true, ...}, "report_id": "...", "plans": [...]}`.
With `PAYWALL=off` it returns the full `{"report": {...}, "report_text": "..."}`. `GET /health` checks the tools and LLM key.

### Free scan and payment (demo)

The scan runs once and its findings are stored (`data/`, deleted after `REPORT_TTL_HOURS`, default 24).
The free result shows the counts, the fingerprint and each issue's title. Paying unlocks where each
issue is, the AI explanations, the fixes and the AI suggestions. The AI runs only after payment, on the
stored findings, so the paid report always has **the same issues and the same fingerprint** as the free one
(issues the AI judges false alarms are listed separately and not counted). A paid app or website report can
be downloaded as one HTML file in English or German: `GET /reports/{id}/download/html?lang=en|de`.

| Plan | Price | Status |
|---|---|---|
| Quick-Scan & Report (`report`) | $29 | available |
| Secure & Auto-Fix (`fix`) | $99 | available (needs source-code upload) |
| Deep Architecture Audit (`improve`) | $199 website · $249 Android project (has an AndroidManifest.xml) | available (needs source-code upload) |

```
POST /checkout  report_id, plan=report   -> {"checkout_url": "/pay/ord_..."}
GET  /pay/{order_id}                      -> checkout page
POST /orders/{order_id}/complete          -> demo only: marks the order paid (what a payment webhook does)
POST /orders/{order_id}/cancel
GET  /reports/{report_id}                 -> free result, or the full report once paid
```

**Free-tier limits**
- `FREE_SCANS_PER_DAY` (default 5) per visitor, reset at midnight UTC; over the limit `/scan` and
  `/scan-web` return 429 with `Retry-After`. `GET /limits` shows what is left (the page shows it under the
  scan button).
- Visitors are told apart by IP address, stored only as a keyed hash in `data/usage/` (kept for one day).
  Behind a reverse proxy set `TRUST_PROXY_HEADERS=true` so the real address in `X-Forwarded-For` is used.
- A failed scan (bad file, unreachable site) gives the scan back.
- Uploading the same .apk again (same file hash, engine, engine and policy version) returns the stored
  result instantly and costs no scan, including the paid report if it was unlocked. Only the same visitor
  gets it: someone else uploading that app gets their own scan.
- Upload cap `MAX_UPLOAD_MB` (150), checked in the browser before upload and again on the server.
- `REA_MAX_CONCURRENT` (1): only one deep REA scan at a time, as it needs most of an 8 GB machine.

`PAYMENTS_MODE=demo` (the default and only mode so far) is a hackathon stand-in: the checkout page says
so, collects no card details and moves no money. For real payments, replace `create_checkout()` in
`scanner/billing.py` with a Stripe Checkout Session (`metadata.order_id`) and mark the order paid from the
`checkout.session.completed` webhook instead of `/orders/{id}/complete`.

### Websites

```bash
curl "http://127.0.0.1:8000/web/verify?url=https://myapp.com"      # token for the ownership file
curl -F url=https://myapp.com -F i_am_authorized=true http://127.0.0.1:8000/scan-web
```

Before a website scan the owner proves they control the site, in one of two ways (like Google Search Console):
- **Meta tag (easiest):** `<meta name="vibeguard-site-verification" content="vibeguard-verify=…">` in the homepage's
  `<head>`. In Next.js: `export const metadata = { other: { "vibeguard-site-verification": "vibeguard-verify=…" } }`
  in `app/layout.tsx`. Works even when the rest of the site redirects to a login page.
- **File:** the token in `https://<site>/.well-known/vibeguard-verify.txt` (redirects are not followed, so a login
  page can't stand in for it).

The token is derived from the site name, so no database is needed; `GET /web/verify?url=` returns both forms.
Sites on your own computer (`localhost`) skip this; turn that off on a public server with `WEB_ALLOW_LOCAL=false`.
`WEB_VERIFY_EXEMPT_HOSTS` (server setting, e.g. `job-tracker.in,*.mycompany.dev`) lists sites the operator owns,
which skip verification. Addresses in private networks are always refused. Each report records how the site was
verified (`reverse_engineering.ownership_verified_by`: local | trusted | meta | file).

If REA's browser capture fails on a site (it can run out of memory on some bundles, such as Next.js Turbopack
builds), the scan falls back to a **direct capture**: the scripts the page links to (same site only), inline
scripts, and their source maps are fetched and checked with the same rules. The report says so; scripts the page
loads later while it runs are not seen. Limits: `REA_WEB_HEAP_MB` (2048) and `REA_WEB_TIMEOUT` (90 s) for the web
capture, `REA_NODE_HEAP_MB` (4096) for APK work.

Test target with deliberate problems: `python samples/web-demo/serve.py`, then scan `http://127.0.0.1:8100`.

A scan takes about 1 minute (decompile ~20s, scan ~12s, AI ~40s).

Command line, without the server:

```bash
python -m scanner.pipeline app.apk            # readable report
python -m scanner.pipeline app.apk --json     # JSON
```

Each step can also be run on its own: `python -m scanner.ingest|mapper|scan|triage|ai <apk or decompiled folder>`.

## Cancelling and following scans

Every free scan (app, website, source preview) runs in its own child process that leads its own process
group (`scanner/jobs.py`), so **Cancel scan** (`POST /scans/cancel`) stops the scan and every program it
started (jadx, REA's Node and Java workers, Semgrep, Gitleaks, the headless browser) at once, and the free
scan is given back. The server also remembers each account's running scan (`GET /scans/active`): a reloaded
page shows its progress and opens the report when it finishes, and a second scan request follows the first
instead of failing. A paid fixing run cannot be cancelled from the page.

## Secure & Auto-Fix ($99): fixes proven by a re-scan

The customer uploads their Android project as a .zip on the **Fix my code** tab (`POST /scan-source`).
The free preview scans the source with the same rules as the app scan and shows what would be fixed.
After payment, for each Critical/Warning issue (grouped per rule and file) the AI proposes exact
find-and-replace edits, and an edit is **kept only if**:

1. every "find" text occurs exactly once in the file,
2. re-scanning the edited file shows the problem gone,
3. no other rule got more findings in that file, and
4. the file still parses (no Semgrep syntax error), and
5. no non-private method or constructor was removed or changed, and no first constructor was added
   (`scanner/structure.breaking_changes`), since other files we can't compile here call them.

Otherwise the AI gets one more try with the scanner's feedback, then the issue is marked "needs a manual
fix" with how-to-fix guidance. Leaked keys are never "fixed" in code (they have already shipped and must be
revoked); smells are left for the Code improvement tier. The page polls `GET /reports/{id}` for progress.

Delivered: `GET /reports/{id}/download/patch` (`git apply fixes.patch`, checked with `git apply --check`
against the upload) and `/download/zip` (the fixed project), plus a before/after scan with fingerprints.
The project is **not compiled** here (no Android SDK); the report says so and asks for a review of every
change. Coverage: Java files (`rules/android.yml`), Kotlin files (`rules/android-kotlin.yml`, the same rule ids
so the same severity policy; `==` on strings is not ported because it is correct in Kotlin) and
AndroidManifest.xml. Gradle `.kts` scripts are listed as not checked. The Kotlin rules are tested against
annotated good/bad examples in `tests/rules/android-kotlin.kt`; the interface check and structure
measurements have Kotlin versions too.

Uploads are unpacked safely (no `..`, absolute paths or symlinks; size and file-count limits; build folders
skipped) into `data/jobs/<report id>/` and deleted with the report after `REPORT_TTL_HOURS`. Signing keys
(`.jks`, `.keystore`, `.p12`, `.pem`, `.key`, …), `local.properties`, `keystore.properties`, `.env` files and
service-account JSON are never unpacked or stored; the preview lists what was left out. Customers can also
upload just the app module (`app/`) instead of the whole repository.

**Web projects** (JavaScript/TypeScript, React, Next.js) work too: `.js .jsx .ts .tsx .mjs .cjs` files are
checked with `rules/web.yml` plus the secret scan (Supabase anon keys are public by design and not flagged;
service_role keys are). Build output and caches (`.next`, `dist`, `out`, `node_modules`, …), minified files,
`.d.ts` files and files over 1 MB are skipped. Fixes must not remove or rename anything a file exports.
Web demo: upload `samples/web-demo-src.zip` (7 of 7 fixable issues fixed and proven in ~80 s).

Demo project with planted problems: `cd samples && zip -r taskpal-src.zip android-demo-src`, then upload
`taskpal-src.zip`. Measured: 11 of 11 Critical/Warning issues fixed and proven (Critical 6 → 1, the leaked
key; Warnings 8 → 0) in about 2.5 minutes with z-ai/glm-5.2. AI output varies between runs; the checks
above decide what is kept, so a run can also end with an issue marked "needs a manual fix".

## Deep Architecture Audit ($199, Android $249)

Everything in Secure & Auto-Fix, plus:
- **Smells fixed** with the same proof (silently ignored errors, `printStackTrace`, `System.exit`, caught
  `NullPointerException`, shared storage, `allowBackup`, …).
- **Structure review**: every Java method is measured (`scanner/structure.py`, Semgrep locates methods) against
  SonarSource's default limits: more than 75 lines (java:S138) or more than 7 parameters (java:S107). The AI
  writes a refactoring plan, a sketch and what to test for each; these are **not applied**, because a
  restructure can only be proven safe by compiling and running the app's tests.
- **Pull-request package**: `pr-description.md` (summary table, every change with its CWE, data-migration notes,
  manual to-dos, structure review, before-merging checklist), `commit-message.txt` (lists only verified fixes)
  and the git commands. Downloads: `/reports/{id}/download/pr` and `/download/commit`.

Measured on the demo project: 20 problems found; 17 of 17 fixed and proven (Critical 6 → 1 the leaked key,
Warnings 8 → 0, Smells 6 → 0), 2 structure plans, about 2.5 minutes. The PR commands apply cleanly on a fresh
git copy, and its re-scan matches the "after" fingerprint.

Creating the pull request on GitHub automatically needs a GitHub App connection (not built yet); the customer
runs the shown git commands instead.

## Sign-in (accounts)

Scanning needs a signed-in account (with the paywall on). Free scans are counted per account, keyed by
the normalized email (lower-case, no `+tag`, no Gmail dots), so a new network or VPN doesn't give more.
Reports and orders are visible only to the account that ran the scan.

| `AUTH_MODE` | How people sign in |
|---|---|
| `supabase` (default when `SUPABASE_URL` is set) | **Continue with Google** or an emailed sign-in link, through Supabase Auth |
| `local` (default otherwise) | 6-digit code by email. Without `SMTP_HOST` the code is shown on the page in a "demo inbox" (works offline) |

In supabase mode the page signs in with supabase-js (pinned 2.45.4 with an integrity hash), then sends
the access token once to `POST /auth/supabase`. The server asks Supabase who it belongs to
(`GET /auth/v1/user`), requires a confirmed email and starts its own 30-day session cookie (HttpOnly,
SameSite=Lax). The local code endpoints are switched off in this mode.

**Supabase setup**
1. Create a project at supabase.com. From Project Settings → API copy the **Project URL** and the
   **anon public** key into `.env` as `SUPABASE_URL` and `SUPABASE_ANON_KEY`. Never use the `service_role` key.
2. Authentication → Providers → **Google**: turn it on and paste a Google OAuth client ID and secret
   (Google Cloud Console → APIs & Services → Credentials → OAuth client ID, type "Web application").
   In Google, add the callback URL Supabase shows you (`https://<project-ref>.supabase.co/auth/v1/callback`)
   as an authorized redirect URI.
3. Authentication → URL Configuration: set **Site URL** to `http://127.0.0.1:8000` and add
   `http://127.0.0.1:8000/**` to **Redirect URLs** (plus your real domain later).
4. Restart the server. If Supabase or the Wi-Fi fails during a demo, start it with `AUTH_MODE=local`.

Abuse limits: `ACCOUNTS_PER_IP_PER_DAY` (3 new accounts per network per day), `FREE_SCANS_PER_IP_PER_DAY`
(15 scans per network across accounts), sign-in codes expire after 10 minutes, work once and allow 5
tries, one code per minute and 5 per hour per email, and common throwaway-inbox domains are refused.
Sessions and codes are stored only as keyed hashes in `data/`.

## LLM settings (`.env`)

| variable | default | |
|---|---|---|
| `LLM_PROVIDER` | `openrouter` | or `glm` (Z.ai direct), `kimi` (Moonshot direct) |
| `LLM_MODEL` | `z-ai/glm-5.2` | any OpenRouter model id, e.g. `moonshotai/kimi-k3` |
| `OPENROUTER_API_KEY` | | |
| `LLM_FALLBACK_MODELS` | | comma-separated, tried if the main model fails twice |
| `LLM_TIMEOUT`, `LLM_MAX_TOKENS` | `300`, provider default | |

Server: `MAX_UPLOAD_MB` (150), `MAX_CONCURRENT_SCANS` (2), `CORS_ORIGINS` (`*`).
REA: `APK_ENGINE` (`auto`), `REA_WORKERS` (3 – each is a JVM with a ~2 GB heap), `REA_MAX_CLASSES` (1500),
`REA_NODE_BIN`, `REA_BIN`, `REA_JADX_MCP_JAR`. Web: `WEB_ALLOW_LOCAL` (`true`), `WEB_VERIFY_SECRET`, `CHROME_BIN`.

## Measured (MacBook, 8 GB RAM)

| | jadx engine | REA engine |
|---|---|---|
| F-Droid APK: issues found | 1 critical · 4 warnings · 7 smells | **identical** (same 56 raw findings, rules, counts) |
| Decompile step | ~17 s (whole app) | ~13 min (845 app classes, ~6,200 method requests; libraries not decompiled) |
| Coverage of app code | whole classes | 4,777 methods as Java, 1,385 as smali (mostly constructors / static initializers), 49 failed |
| Evidence | – | REA evidence IDs + engine digests in `scan.reverse_engineering` |

REA restarts its JADX session after a method it can't decompile (~5 s each), and each worker is a
~2 GB JVM, so more RAM (and `REA_WORKERS`) is the main lever for speed. Website scans take ~10 s plus
~20 s for the AI.

Tests: `.venv/bin/python -m unittest discover -s tests -v` (add `RUN_GOLDEN=1` for the full F-Droid check).

## Limits

Automated scan of decompiled code: it can miss problems and raise false alarms. Heavily obfuscated apps
scan more slowly and are harder to attribute. Accounts, saved scans, orders and usage counts are JSON files in
`data/` (no database): fine for one server, but `data/` must live on a disk that survives redeploys.
