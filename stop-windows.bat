@echo off
rem VibeGuard: double-click to stop (Windows). Your account and scans are kept for next time.
cd /d "%~dp0"
docker compose stop && echo VibeGuard is stopped.
pause
