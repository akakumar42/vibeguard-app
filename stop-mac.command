#!/bin/sh
# VibeGuard: double-click to stop (Mac). Your account and scans are kept for next time.
cd "$(dirname "$0")" || exit 1
docker compose stop && echo "VibeGuard is stopped."
printf '\nPress Enter to close this window.'; read -r _
