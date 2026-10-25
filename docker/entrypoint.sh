#!/bin/sh
# Starts the demo website (port 8100, for trying the Website tab) and VibeGuard (port 8000).
set -e
if [ "${DEMO_SITE:-1}" != "0" ]; then
  python samples/web-demo/serve.py 8100 >/dev/null 2>&1 &
fi
echo "VibeGuard is starting on http://127.0.0.1:8000  (demo website: http://127.0.0.1:8100)"
if [ -z "${OPENROUTER_API_KEY}${LLM_API_KEY}${ZAI_API_KEY}${MOONSHOT_API_KEY}" ]; then
  echo "No AI key set: scans work, with the rules' standard wording; Bug fixing needs a key (-e OPENROUTER_API_KEY=...)."
fi
exec uvicorn api:app --host 0.0.0.0 --port 8000
