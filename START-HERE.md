# VibeGuard: try it on your laptop

You need about 4 GB of free memory and 3 GB of disk. Nothing leaves your laptop unless you add an AI key.

## 1. Install Docker Desktop (once)
Download it from https://www.docker.com/products/docker-desktop/ and open it once.
On Windows, say yes when it asks to set up WSL 2, and restart if it asks.

## 2. Start VibeGuard
- **Mac:** double-click `start-mac.command`.
  If the Mac says it "cannot be opened", right-click the file, choose **Open**, then **Open** again.
- **Windows:** double-click `start-windows.bat`.
  If a blue "Windows protected your PC" box appears, click **More info**, then **Run anyway**.

The first start takes 5-10 minutes. When it's done, your browser opens http://127.0.0.1:8000 by itself.

## 3. Sign in
Press **Continue with Google**, or use the email sign-in link.

## 4. Try it
| Tab | What to do |
|---|---|
| Android app | Download the F-Droid app from https://f-droid.org/F-Droid.apk (12 MB), upload it, tick the box, press **Scan app** (about 1 minute). Any APK you own works too |
| Website | Click **Scan the built-in demo site** |
| Fix my code | Upload `samples/web-demo-src.zip` (website) or `samples/taskpal-src.zip` (Android). For a big real project, download F-Droid's source: https://gitlab.com/fdroid/fdroidclient/-/archive/2.0.2/fdroidclient-2.0.2.zip |

Payments are a demo: no card, no real money.

## 5. Stop it
Double-click `stop-mac.command` or `stop-windows.bat`. Your account and scans are kept for next time.

## Settings
The settings are already in the hidden `.env` file in this folder (sign-in, AI explanations and fixing).
It contains a private key: don't share this folder or post it anywhere.

## Something wrong?
- **"port is already allocated":** something else uses port 8000. Close it and start again.
- **Scan fails or Docker restarts:** Docker Desktop → Settings → Resources → give it at least 4 GB of memory.
- **Anything else:** send a screenshot of the black start window to the person who shared VibeGuard.
