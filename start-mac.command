#!/bin/sh
# VibeGuard: double-click to start (Mac). The first start takes 5-10 minutes; later starts take seconds.
cd "$(dirname "$0")" || exit 1
URL="http://127.0.0.1:8000"

pause() { printf '\nPress Enter to close this window.'; read -r _; }

if ! command -v docker >/dev/null 2>&1; then
  echo "Docker Desktop is not installed."
  echo "Install it from https://www.docker.com/products/docker-desktop/ , open it once, then double-click this file again."
  pause; exit 1
fi
if ! docker info >/dev/null 2>&1; then
  echo "Starting Docker Desktop..."
  open -a Docker 2>/dev/null
  for _ in $(seq 1 60); do docker info >/dev/null 2>&1 && break; sleep 3; done
  if ! docker info >/dev/null 2>&1; then
    echo "Docker Desktop did not start. Open it yourself, wait until it says \"Engine running\", then try again."
    pause; exit 1
  fi
fi

echo "Starting VibeGuard (the first time this downloads and builds everything, about 5-10 minutes)..."
if ! docker compose up -d --build; then
  echo "VibeGuard could not start. Send a screenshot of this window to the person who shared it."
  pause; exit 1
fi

printf "Waiting for VibeGuard to be ready"
for _ in $(seq 1 60); do
  curl -sf "$URL/health" >/dev/null 2>&1 && break
  printf "."; sleep 2
done
echo
open "$URL"
echo "VibeGuard is running at $URL"
echo "Sign in with any email: the 6-digit code is shown on the page. Test files are in the samples folder."
echo "To stop it, double-click stop-mac.command."
pause
