@echo off
rem VibeGuard: double-click to start (Windows). The first start takes 5-10 minutes; later starts take seconds.
cd /d "%~dp0"
set URL=http://127.0.0.1:8000

where docker >nul 2>nul
if errorlevel 1 (
  echo Docker Desktop is not installed.
  echo Install it from https://www.docker.com/products/docker-desktop/ , open it once, then double-click this file again.
  pause & exit /b 1
)
docker info >nul 2>nul
if errorlevel 1 (
  echo Starting Docker Desktop...
  start "" "%ProgramFiles%\Docker\Docker\Docker Desktop.exe"
  for /l %%i in (1,1,60) do (
    docker info >nul 2>nul && goto docker_ready
    timeout /t 3 /nobreak >nul
  )
  echo Docker Desktop did not start. Open it yourself, wait until it says "Engine running", then try again.
  pause & exit /b 1
)
:docker_ready

echo Starting VibeGuard (the first time this downloads and builds everything, about 5-10 minutes)...
docker compose up -d --build
if errorlevel 1 (
  echo VibeGuard could not start. Send a screenshot of this window to the person who shared it.
  pause & exit /b 1
)

echo Waiting for VibeGuard to be ready...
for /l %%i in (1,1,60) do (
  curl -sf %URL%/health >nul 2>nul && goto ready
  timeout /t 2 /nobreak >nul
)
:ready
start "" %URL%
echo VibeGuard is running at %URL%
echo Sign in with any email: the 6-digit code is shown on the page. Test files are in the samples folder.
echo To stop it, double-click stop-windows.bat.
pause
