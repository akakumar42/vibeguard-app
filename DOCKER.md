# VibeGuard in Docker (local edition)

Runs entirely on your own computer: nothing is uploaded anywhere except, if you add an AI key, short code
snippets sent to the AI for the plain-English explanations and fixes.

**Needs:** Docker Desktop (Mac, Windows or Linux) and about **2 GB of free memory** (measured peak while
scanning F-Droid). The image is about 1 GB.

## Start it

```bash
docker compose up            # first time: builds the image (5–10 min), then starts it
```

or without compose:

```bash
docker build -t vibeguard:local .
docker run --rm -p 127.0.0.1:8000:8000 -p 127.0.0.1:8100:8100 -v vibeguard-data:/data vibeguard:local
```

Open **http://127.0.0.1:8000**. Sign in with any email: the 6-digit code is shown on the page (no email is
sent). Payments are a demo: pressing Pay unlocks the report without taking money.

**AI explanations and fixes (optional):** get a key at https://openrouter.ai and start with
`OPENROUTER_API_KEY=sk-or-... docker compose up` (or `-e OPENROUTER_API_KEY=...` with `docker run`). Without
a key every scan still works and finds the same issues, with the rules' standard wording; Bug fixing and
Code improvement need the key. **Never put a key into the image or share it with the image.**

## Try it

- **Android app:** download https://f-droid.org/F-Droid.apk and upload it. The reference copy
  (`samples/fdroid.apk`, not in the share zip) gives 1 critical, 4 warnings, 7 smells, fingerprint
  `8528083a414fad21`; a newer F-Droid release can give slightly different numbers.
- **Website:** click "Scan the built-in demo site" (http://127.0.0.1:8100, 17 planted problems).
  To scan a site running on your own computer outside Docker, use `http://host.docker.internal:3000`.
- **Fix my code:** upload `samples/web-demo-src.zip` (web) or `samples/taskpal-src.zip` (Android).

## What is different from the full setup

| | Docker local edition | Full setup |
|---|---|---|
| APK engine | Fast (jadx) only | Fast or Deep (REA, needs ~6 GB) |
| Website capture | Direct fetch of the scripts the page links to | REA + headless Chrome, falling back to the direct fetch |
| Sign-in | On-screen code | Google / email via Supabase |
| Results | **Same rules, tool versions and fingerprints** | |

Tool versions are pinned in the Dockerfile (jadx 1.5.6, Semgrep 1.182.0, Gitleaks 8.30.1, apksig 9.3.3,
Java 21), with checksums, so every copy gives the same results.

## Share it

- **Easiest:** share this folder (or a git repo of it). Others run `docker compose up`, which builds an
  image for their own computer (Intel, Apple Silicon or Windows).
- **As a file** (same chip type only; this one is built for Apple Silicon / arm64):
  `docker save vibeguard:local | gzip > vibeguard-arm64.tar.gz`, then on the other computer
  `docker load < vibeguard-arm64.tar.gz` and the `docker run` command above.
- **Through a registry** (Docker Hub or GitHub Container Registry), for both chip types at once:
  `docker buildx build --platform linux/amd64,linux/arm64 -t <you>/vibeguard:latest --push .`

Data (accounts, scans) lives in the `vibeguard-data` volume; `docker volume rm vibeguard-data` deletes it.
