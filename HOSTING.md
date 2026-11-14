# VibeGuard: Free Public Hosting Plan

> Status: **planned, not executed**. Date: 2026-11-13.
> Repo: `D:\vibeguard-app` (github.com/akakumar42/vibeguard-app), running locally via `docker compose` on port 8000.

## What the app needs (constraints any host must satisfy)

- **RAM:** ~2 GB for the fast engine (jadx is a JVM), ~6 GB if the deep REA engine should be usable. This rules out most free tiers (Render/Railway/Fly free = 512 MB).
- **One container, two ports:** app on `8000` (hardcoded in `docker/entrypoint.sh` — uvicorn `--port 8000`), demo site on `8100` (can be disabled with `DEMO_SITE=0`).
- **Persistent disk:** `data/` volume (accounts, scan results; results auto-expire after 24 h anyway).
- **Env config:** `OPENAI_API_KEY`, `LLM_PROVIDER=openai`, `LLM_MODEL=gpt-4.1-mini`, `WEB_VERIFY_EXEMPT_HOSTS` — must become platform secrets, never committed to git.
- **Egress:** sends ~10k-token snippets to OpenAI for explanations; nothing else leaves the box.

## Platform options (free tier reality check)

| Platform | Free specs | Verdict |
|---|---|---|
| **Oracle Cloud Always Free** | ARM VM: up to 4 vCPU / 24 GB RAM / 200 GB disk, always-on, public IP | **Only option that runs all features incl. deep REA, with headroom.** Card required at signup (verification only, never charged). You manage the VM. |
| **Hugging Face Spaces (Docker)** | ~2 vCPU / 16 GB RAM, public URL, git-push deploy | Best effort-free option. Sleeps when idle (cold start ~1 min on visit). Must listen on port 7860 → small patch. Public by default. |
| **Cloudflare Tunnel → your PC** | Unlimited (it's your machine) | Zero changes, instant free URL, but the PC must stay on. Fine for demos, not real hosting. |
| Google Cloud Run | ~180k vCPU-s/mo free, scale-to-zero | Doable but fiddly: PORT patch, single port, in-memory FS, 2.3 GB image = slow cold starts, ~100–300 scans/mo ceiling. |
| Render / Railway / Fly / Koyeb free | 512 MB RAM or trial credit | Ruled out — jadx won't fit. |

**Recommendation: Oracle Always Free VM** for permanent + all features; **HF Spaces** for a public URL in ~15 minutes with sleep-on-idle accepted.

## Pre-flight changes (needed for either path)

1. **Commit and push `scanner/ai.py`** (the `openai` provider entry) — HF deploys from git; Oracle clones from git.
2. **Parameterize the port** in `docker/entrypoint.sh`:
   ```sh
   exec uvicorn api:app --host 0.0.0.0 --port "${PORT:-8000}"
   ```
   Required for HF Spaces (port 7860); harmless elsewhere. Skip for Oracle (8000 behind a reverse proxy is fine).
3. **Secrets out of `.env`:** HF → Settings → Variables and secrets; Oracle → keep `.env` on the VM with `chmod 600`.
4. **`TRUST_PROXY_HEADERS=true`** behind any proxy/tunnel — otherwise per-IP rate limits see the proxy IP and everyone shares one quota.
5. **Harden for public exposure** (README says this explicitly): `WEB_ALLOW_LOCAL=false` so strangers can't scan the container's own localhost. Keep the built-in limits: `FREE_SCANS_PER_DAY=5`, `ACCOUNTS_PER_IP_PER_DAY=3`, `FREE_SCANS_PER_IP_PER_DAY=15`.
6. **Cost cap (OpenAI spend):** in demo payment mode anyone can "pay" and trigger AI explanations. Worst case per IP: 15 scans/day × ~$0.003 with gpt-4.1-mini ≈ **cents per day**. Acceptable; revisit if traffic grows.
7. Keep `DEMO_SITE=1` — the "Scan the built-in demo site" button is server-side (the scan originates from the container), so it works on every platform even though browsers can't reach port 8100 directly.

## Path A — Oracle Always Free (recommended, permanent)

1. Sign up at <https://www.oracle.com/cloud/free/> (card for verification). Pick a home region with ARM capacity.
2. Create an Ampere A1 VM: Ubuntu 24.04 ARM, 1–2 OCPU / 12 GB RAM (4 OCPU / 24 GB max free).
3. `sudo apt install docker.io docker-compose-v2`; open ports 80/443 in the VCN security list and iptables.
4. `git clone` the repo, place `.env` (`chmod 600`), then `docker compose up -d --build` (~10 min ARM build).
5. TLS + domain: Caddy container with a free DuckDNS subdomain (`vibeguard.duckdns.org`) — Caddy auto-issues Let's Encrypt. Zero cost, no domain purchase.
6. Point DNS at the VM IP; verify `https://<name>.duckdns.org/health`; run one APK scan and one website scan end-to-end.

**Result:** always-on, all features, ~$0/month.
**Maintenance:** occasional `apt upgrade` + `git pull && docker compose up -d --build`.

## Path B — Hugging Face Spaces (fastest, sleeps when idle)

1. Push the repo to GitHub (including the `ai.py` change).
2. HF account → New Space → Docker SDK → link the repo. Free CPU hardware.
3. Space secrets: `OPENAI_API_KEY`, `LLM_PROVIDER=openai`, `LLM_MODEL=gpt-4.1-mini`, `LLM_FALLBACK_MODELS=gpt-4o-mini`, `TRUST_PROXY_HEADERS=true`, `WEB_ALLOW_LOCAL=false`, `WEB_VERIFY_EXEMPT_HOSTS=demo.owasp-juice.shop`.
4. Apply the PORT patch from pre-flight (Spaces require 7860).
5. Space builds on push; URL is `https://<you>-vibeguard.hf.space`.

**Caveats:** cold start after sleep (~1 min); the 8100 demo-site preview won't open in a visitor's browser (the scan itself still works); storage is semi-ephemeral — accounts/results in `data/` survive restarts but treat it as demo-grade.

## Launch-day verification (both paths)

- [ ] `GET /health` → all tools `true`, `llm.provider=openai`, `api_key_set=true`
- [ ] Sign in with a throwaway email → demo-code flow works
- [ ] Scan `https://demo.owasp-juice.shop` (exempt host) → full report with AI explanations
- [ ] Upload an APK → jadx-engine report renders
- [ ] `result_fingerprint` identical between free and paid views of the same scan
