#!/bin/sh
# Builds ../vibeguard-share.zip for teammates: the code, start scripts and the small samples.
# The F-Droid test files are left out (about 33 MB); START-HERE.md links to their downloads.
# Never included: your own .env, data/ (your accounts, sessions, reports, orders), .venv and the deep engine.
# If team.env exists it is put in the zip as the team's .env (Google sign-in, AI key, unlimited accounts).
set -e
cd "$(dirname "$0")/.."
OUT="$PWD/vibeguard-share.zip"
rm -f "$OUT"
zip -qr "$OUT" vibeguard \
  -x 'vibeguard/.env' 'vibeguard/team.env' 'vibeguard/.verify-secret' 'vibeguard/data/*' 'vibeguard/.venv/*' \
     '*/__pycache__/*' '*.pyc' '*.DS_Store' 'vibeguard/tools/rea/*' \
     'vibeguard/samples/fdroid*.apk' 'vibeguard/samples/fdroidclient-*.zip'
if [ -f vibeguard/team.env ]; then
  tmp=$(mktemp -d)
  mkdir "$tmp/vibeguard" && cp vibeguard/team.env "$tmp/vibeguard/.env"
  (cd "$tmp" && zip -q "$OUT" vibeguard/.env)
  rm -rf "$tmp"
  echo "Included team.env as the team's .env"
else
  echo "No team.env: teammates get email sign-in and scans without AI wording"
fi
ls -lh "$OUT"
