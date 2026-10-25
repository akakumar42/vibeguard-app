"""Severity policy: the single, reviewed source of truth for how serious each finding is.

Severity is decided here, by rule, never by the AI - so the same app always gets the same counts.
Each rule is mapped to a control in OWASP MASVS v2 (mobile apps) or OWASP ASVS 4.0 (websites) and to
a CWE id (the industry catalogue of weakness types), and carries a fixed plain-English title, risk
and fix that are used when the AI is off and as the reference the AI must stay consistent with.

Changing anything here changes reports: bump POLICY_VERSION so old and new reports can be told apart.
"""

from __future__ import annotations

from dataclasses import dataclass

POLICY_VERSION = "1.3.1"

FRAMEWORKS = {"MASVS": "OWASP MASVS v2", "ASVS": "OWASP ASVS 4.0"}

# Control groups, in words a non-expert can follow.
CONTROLS = {
    "MASVS-STORAGE": "Storing data safely on the phone",
    "MASVS-CRYPTO": "Encryption and keys",
    "MASVS-AUTH": "Logins and sessions",
    "MASVS-NETWORK": "Safe network connections",
    "MASVS-PLATFORM": "Safe use of Android features",
    "MASVS-CODE": "Code quality and safe input handling",
    "MASVS-RESILIENCE": "Resistance to tampering",
    "MASVS-PRIVACY": "User privacy",
    "ASVS-V3": "Sessions and cookies",
    "ASVS-V5": "Handling untrusted input",
    "ASVS-V6": "Secrets and encryption",
    "ASVS-V7": "Errors and logging",
    "ASVS-V8": "Protecting data in the browser",
    "ASVS-V9": "Encrypted connections",
    "ASVS-V14": "Server configuration",
}


@dataclass(frozen=True)
class Rule:
    severity: str  # critical | warning | smell
    control: str  # e.g. MASVS-NETWORK or ASVS-V9
    cwe: str
    title: str
    risk: str
    fix: str


RULES: dict[str, Rule] = {
    # ---------------------------------------------------------------- network
    "trust-all-certificates": Rule(
        "critical", "MASVS-NETWORK", "CWE-295", "The app accepts fake security certificates",
        "The app trusts any server certificate, so someone on the same Wi-Fi can pretend to be your "
        "server and read or change everything the app sends, including passwords.",
        "Remove the custom `TrustManager` that accepts every certificate and use the system default; "
        "for a self-signed server, use a network security config with that certificate pinned."),
    "hostname-verifier-allow-all": Rule(
        "critical", "MASVS-NETWORK", "CWE-297", "The app doesn't check which server it is talking to",
        "The app accepts a secure connection to any website name, so an attacker with any valid "
        "certificate can intercept its traffic.",
        "Delete the custom `HostnameVerifier` that always returns true and use the default one."),
    "webview-ignores-ssl-errors": Rule(
        "critical", "MASVS-NETWORK", "CWE-295", "Built-in web pages ignore security warnings",
        "When a page shown inside the app has a broken or fake certificate, the app loads it anyway, "
        "so the page and anything typed into it can be intercepted.",
        "In `onReceivedSslError`, call `handler.cancel()` instead of `handler.proceed()`."),
    "weak-tls-version": Rule(
        "warning", "MASVS-NETWORK", "CWE-327", "The app allows outdated encryption for connections",
        "Old connection security versions have known weaknesses that can let attackers read traffic.",
        "Only allow TLS 1.2 and 1.3; remove references to SSLv3, TLS 1.0 and TLS 1.1."),
    "cleartext-traffic": Rule(
        "warning", "MASVS-NETWORK", "CWE-319", "The app is allowed to send data unencrypted",
        "The app may use plain http:// connections, which anyone on the same network can read or change.",
        "Set `android:usesCleartextTraffic=\"false\"` and switch every server address to https://."),
    "nsc-cleartext": Rule(
        "warning", "MASVS-NETWORK", "CWE-319", "Unencrypted connections are allowed for some servers",
        "The app's network settings allow plain http:// traffic, which others on the network can read.",
        "In the network security config, set `cleartextTrafficPermitted=\"false\"` and use https://."),
    "nsc-user-certs": Rule(
        "warning", "MASVS-NETWORK", "CWE-295", "The app trusts certificates the user installs",
        "Anyone who can install a certificate on the phone can read the app's secure traffic.",
        "Remove `<certificates src=\"user\"/>` from the release network security config "
        "(keep it only inside `<debug-overrides>`)."),
    # ---------------------------------------------------------------- web views
    "webview-javascript-enabled": Rule(
        "smell", "MASVS-PLATFORM", "CWE-79", "Built-in web pages can run scripts",
        "This is often needed, but if the app shows pages it does not fully control, a malicious "
        "page could run code inside the app.",
        "Only enable JavaScript for pages you control and load them over https://."),
    "webview-javascript-interface": Rule(
        "warning", "MASVS-PLATFORM", "CWE-749", "Web pages can call into the app's own code",
        "Any page loaded in this web view can call the app's functions, so a malicious page could "
        "reach app data or features.",
        "Only add the JavaScript interface for trusted https:// pages and expose as few methods as possible."),
    "webview-file-access": Rule(
        "warning", "MASVS-PLATFORM", "CWE-200", "Built-in web pages can read files on the phone",
        "A page in the web view may be able to read the app's private files and send them elsewhere.",
        "Call `setAllowFileAccess(false)` and avoid the file-URL access settings."),
    # ---------------------------------------------------------------- crypto
    "weak-hash": Rule(
        "warning", "MASVS-CRYPTO", "CWE-328", "The app uses an outdated fingerprinting method",
        "MD5 and SHA-1 can be faked, so they must not protect passwords or verify downloads.",
        "Use SHA-256 for checks, and a password hashing method such as Argon2 or PBKDF2 for passwords."),
    "weak-cipher": Rule(
        "warning", "MASVS-CRYPTO", "CWE-327", "The app uses weak encryption",
        "Old or badly configured encryption (such as DES or ECB mode) can be broken to reveal the data.",
        "Use AES in GCM mode with a random IV for every message."),
    "hardcoded-crypto-key-or-iv": Rule(
        "critical", "MASVS-CRYPTO", "CWE-321", "An encryption key is written into the app",
        "Anyone who downloads the app can pull out this key and decrypt the data it protects.",
        "Generate keys at runtime and keep them in the Android Keystore; never put keys in code."),
    "secret": Rule(
        "critical", "MASVS-CRYPTO", "CWE-798", "A password or API key is written into the app",
        "Anyone who downloads the app can extract this secret and use it - for example to run up "
        "bills on your account or reach your users' data.",
        "Revoke and replace this key now, then move it to your server; the app should get "
        "short-lived tokens from your backend instead of holding the key."),
    # ---------------------------------------------------------------- storage
    "world-readable-file": Rule(
        "critical", "MASVS-STORAGE", "CWE-276", "Other apps can read the app's files",
        "Files are saved so that any app on the phone can read or overwrite them.",
        "Use `MODE_PRIVATE` when creating files and shared preferences."),
    "external-storage": Rule(
        "smell", "MASVS-STORAGE", "CWE-922", "The app uses shared phone storage",
        "Files in shared storage can be read by other apps, so they must not hold personal data.",
        "Keep personal data in the app's private storage (`getFilesDir()`)."),
    "sensitive-data-logged": Rule(
        "warning", "MASVS-STORAGE", "CWE-532", "Private information may be written to the logs",
        "Logs can be read through debugging tools and crash reports, which could expose passwords or tokens.",
        "Remove these log lines or strip logging from release builds."),
    "allow-backup": Rule(
        "smell", "MASVS-STORAGE", "CWE-530", "App data can be copied off the phone",
        "A backup tool can copy the app's data, including saved logins, to another device.",
        "Set `android:allowBackup=\"false\"`, or exclude private files with backup rules."),
    # ---------------------------------------------------------------- code / input handling
    "sql-string-concatenation": Rule(
        "warning", "MASVS-CODE", "CWE-89", "A database query is built from raw text",
        "If any part of that text comes from a user or a server, it could change the query and read "
        "or delete data it shouldn't.",
        "Use query parameters (`?` placeholders with selection arguments) instead of joining strings."),
    "zip-path-traversal": Rule(
        "critical", "MASVS-CODE", "CWE-22", "Unpacking a zip file can overwrite the app's own files",
        "A specially made zip file can contain names like ../../ that write files outside the target "
        "folder, which can replace app code or data.",
        "Before writing each entry, check that its resolved path stays inside the destination folder."),
    "runtime-exec": Rule(
        "warning", "MASVS-CODE", "CWE-78", "The app runs commands on the phone",
        "If any part of the command comes from outside the app, an attacker could run their own commands.",
        "Avoid running shell commands; if it is necessary, never build the command from outside input."),
    "dynamic-code-loading": Rule(
        "warning", "MASVS-CODE", "CWE-94", "The app loads extra code while it runs",
        "Code loaded at runtime is not checked by the Play Store, and if its source can be changed an "
        "attacker can run their own code inside the app.",
        "Ship all code inside the app, or verify the signature of any code you load."),
    "string-compared-with-equals-sign": Rule(
        "warning", "MASVS-CODE", "CWE-597", "Text is compared the wrong way",
        "Comparing text with == checks whether it is the same object, not the same words, so checks "
        "can fail at random.",
        "Use `.equals()` (or `TextUtils.equals()`) to compare strings."),
    "handler-without-looper": Rule(
        "smell", "MASVS-CODE", "CWE-1188", "Background work is scheduled in an outdated way",
        "This old pattern can run work on the wrong thread and cause rare crashes or freezes.",
        "Pass a looper explicitly, for example `new Handler(Looper.getMainLooper())`."),
    "catch-null-pointer": Rule(
        "smell", "MASVS-CODE", "CWE-395", "A crash is hidden instead of fixed",
        "The code catches a missing-value crash instead of checking for the missing value, which hides "
        "real bugs.",
        "Check for null before using the value and remove the `catch (NullPointerException)`."),
    "empty-catch-block": Rule(
        "smell", "MASVS-CODE", "CWE-390", "Errors are silently ignored",
        "When something goes wrong here, the app carries on as if nothing happened, which makes bugs "
        "hard to find.",
        "Log the error, or handle it so the user sees what went wrong."),
    "print-stack-trace": Rule(
        "smell", "MASVS-CODE", "CWE-209", "Error details are printed to the logs",
        "Raw error details in logs can reveal how the app works and are lost in release builds.",
        "Replace `printStackTrace()` with proper logging or a crash reporter."),
    "system-exit": Rule(
        "smell", "MASVS-CODE", "CWE-382", "The app shuts itself down abruptly",
        "Killing the app process skips normal clean-up and can lose user data.",
        "Close the screen with `finish()` instead of `System.exit()`."),
    # ---------------------------------------------------------------- signing (checked by apksig)
    "apk-signature-invalid": Rule(
        "critical", "MASVS-RESILIENCE", "CWE-347", "The app's signature is missing or broken",
        "Android cannot confirm who built this file or that nobody changed it afterwards, and phones "
        "will refuse to install it.",
        "Rebuild the release with Android Studio's \"Generate Signed App Bundle / APK\" and your release key."),
    "apk-signature-v1-only": Rule(
        "warning", "MASVS-RESILIENCE", "CWE-347", "The app uses only the old signing method",
        "The old v1 signature does not cover the whole file, so on older phones an attacker can slip "
        "code into the app without breaking the signature (the Janus flaw, CVE-2017-13156).",
        "Enable v2 and v3 signing (the default in current Android build tools) and rebuild."),
    "apk-debug-certificate": Rule(
        "warning", "MASVS-RESILIENCE", "CWE-321", "The app is signed with a developer test key",
        "The debug key is created automatically, has the well-known password \"android\", and Google Play "
        "rejects apps signed with it. Updates signed with your real key will not install over this build.",
        "Create a release key and sign the release build with it."),
    "apk-weak-signing-key": Rule(
        "warning", "MASVS-RESILIENCE", "CWE-326", "The app's signing key is too weak",
        "A short or outdated key is easier to forge, which would let someone publish fake updates.",
        "Use an RSA key of at least 2048 bits (or EC 256). Google Play's key rotation can move an existing app to a new key."),
    # ---------------------------------------------------------------- platform / build
    "debuggable": Rule(
        "critical", "MASVS-RESILIENCE", "CWE-489", "The app was released in debug mode",
        "Anyone with a USB cable can inspect the app's memory and private data on the phone.",
        "Remove `android:debuggable=\"true\"` and build the release version of the app."),
    "old-target-sdk": Rule(
        "warning", "MASVS-PLATFORM", "CWE-1104", "The app is built for an old version of Android",
        "Targeting an old Android version opts the app out of newer privacy and security protections.",
        "Raise `targetSdkVersion` to the version the Play Store currently requires."),
    "exported-service": Rule(
        "warning", "MASVS-PLATFORM", "CWE-926", "Other apps can start one of the app's background services",
        "Any app on the phone can trigger this service without permission.",
        "Set `android:exported=\"false\"`, or protect it with a permission."),
    "exported-receiver": Rule(
        "warning", "MASVS-PLATFORM", "CWE-926", "Other apps can send messages to this app",
        "Any app on the phone can send this app events, which it will act on without checking who sent them.",
        "Set `android:exported=\"false\"`, or protect it with a permission."),
    "exported-provider": Rule(
        "warning", "MASVS-PLATFORM", "CWE-926", "Other apps can read the app's shared data",
        "Any app on the phone can query this data store without permission.",
        "Set `android:exported=\"false\"`, or protect it with read and write permissions."),
}

WEB_RULES: dict[str, Rule] = {
    # ---------------------------------------------------------------- website code (Semgrep, rules/web.yml)
    "web-innerhtml-assignment": Rule(
        "warning", "ASVS-V5", "CWE-79", "Text from outside is inserted into the page as HTML",
        "If any part of that text comes from a visitor or another site, an attacker can make it run "
        "their own script on your page and steal logins (cross-site scripting).",
        "Use `textContent` for plain text, or sanitize the HTML first with a library such as DOMPurify."),
    "web-document-write": Rule(
        "warning", "ASVS-V5", "CWE-79", "The page writes HTML with document.write",
        "Writing HTML built from variables can let an attacker inject their own script.",
        "Replace `document.write` with DOM methods such as `textContent` or `appendChild`."),
    "web-dangerously-set-inner-html": Rule(
        "warning", "ASVS-V5", "CWE-79", "React inserts raw HTML into the page",
        "`dangerouslySetInnerHTML` with data from users or an API can run an attacker's script.",
        "Render the data as normal JSX text, or sanitize it with DOMPurify before inserting it."),
    "web-eval": Rule(
        "warning", "ASVS-V5", "CWE-95", "The website runs text as code",
        "If the text can be influenced by a visitor (for example through the URL), an attacker can run "
        "any code in your users' browsers.",
        "Remove `eval` / `new Function`; parse data with `JSON.parse` or use a safe expression library."),
    "web-token-in-localstorage": Rule(
        "warning", "ASVS-V8", "CWE-922", "Login tokens are stored where any script can read them",
        "Anything in localStorage can be read by any script on the page, so one injected script is "
        "enough to steal every user's session.",
        "Keep session tokens in `HttpOnly`, `Secure` cookies set by your server."),
    "web-postmessage-no-origin-check": Rule(
        "warning", "ASVS-V5", "CWE-346", "The page trusts messages from any website",
        "Any site that opens or embeds your page can send it messages, and the page acts on them "
        "without checking who sent them.",
        "At the start of the message handler, return unless `event.origin` is one of your own domains."),
    "web-postmessage-wildcard": Rule(
        "smell", "ASVS-V8", "CWE-345", "The page broadcasts data to any website",
        "Sending messages to '*' means a malicious page that embeds yours can read them.",
        "Pass your parent site's exact origin instead of '*' as the second argument of `postMessage`."),
    "web-insecure-http-request": Rule(
        "warning", "ASVS-V9", "CWE-319", "The website calls a server without encryption",
        "Requests to http:// addresses can be read and changed by anyone on the same network, "
        "including passwords and tokens.",
        "Switch the address to https:// and make sure the server supports it."),
    "web-sensitive-console-log": Rule(
        "smell", "ASVS-V7", "CWE-532", "A token or password is printed to the browser console",
        "Browser extensions, screen sharing and support screenshots can reveal what is printed there.",
        "Remove the `console.log` line, or log only that the action succeeded."),
    # ---------------------------------------------------------------- secrets in website code (Gitleaks)
    "web-secret": Rule(
        "critical", "ASVS-V6", "CWE-798", "A secret key is visible in the website's code",
        "Everything a website sends to the browser can be read by anyone, so this key is public. "
        "Attackers can use it to run up bills or reach your data.",
        "Revoke and replace the key now, then move the call that needs it into a server-side function "
        "(for example an API route or edge function). Only keys meant to be public belong in the browser."),
    "supabase-service-role-key": Rule(
        "critical", "ASVS-V6", "CWE-798", "The Supabase admin key is in the website's code",
        "The service_role key bypasses all row level security, so anyone can read, change or delete "
        "every row in your database.",
        "Rotate the service_role key in the Supabase dashboard now, use the anon key in the browser, "
        "and protect tables with row level security policies."),
    # ---------------------------------------------------------------- server configuration (HTTP checks)
    "web-no-https": Rule(
        "critical", "ASVS-V9", "CWE-319", "The website does not use HTTPS",
        "Everything visitors send, including passwords, travels unencrypted and can be read or changed "
        "on public Wi-Fi.",
        "Turn on HTTPS with a free certificate (most hosts do this automatically) and redirect http:// to https://."),
    "web-no-https-redirect": Rule(
        "warning", "ASVS-V9", "CWE-319", "The http:// address does not redirect to HTTPS",
        "Visitors who type the address without https:// stay on an unencrypted connection.",
        "Redirect every http:// request to the https:// address (status 301 or 308)."),
    "web-missing-hsts": Rule(
        "warning", "ASVS-V9", "CWE-319", "Browsers are not told to always use HTTPS",
        "Without the HSTS header, an attacker on the network can downgrade a visitor to plain http://.",
        "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` on HTTPS responses."),
    "web-missing-csp": Rule(
        "warning", "ASVS-V14", "CWE-693", "No Content Security Policy",
        "A Content Security Policy limits which scripts can run, so it stops most injected scripts "
        "from working. This site has none.",
        "Add a `Content-Security-Policy` header, starting with `default-src 'self'` and allowing only "
        "the domains you use."),
    "web-missing-frame-protection": Rule(
        "warning", "ASVS-V14", "CWE-1021", "Other sites can embed this page invisibly",
        "An attacker can load your site inside an invisible frame and trick visitors into clicking "
        "buttons (clickjacking).",
        "Send `Content-Security-Policy: frame-ancestors 'self'` (or `X-Frame-Options: DENY`)."),
    "web-missing-nosniff": Rule(
        "smell", "ASVS-V14", "CWE-693", "Browsers may guess file types",
        "Without the nosniff header, a browser can treat an uploaded file as a script.",
        "Send `X-Content-Type-Options: nosniff` on every response."),
    "web-cookie-insecure": Rule(
        "warning", "ASVS-V3", "CWE-614", "A cookie is missing its safety flags",
        "Cookies without Secure, HttpOnly and SameSite can be stolen by scripts, sent unencrypted or "
        "abused by other sites.",
        "Set cookies with `Secure; HttpOnly; SameSite=Lax` (or `Strict`)."),
    "web-server-version-disclosure": Rule(
        "smell", "ASVS-V14", "CWE-200", "The server reveals what software it runs",
        "Version details help attackers look up known weaknesses for exactly that software.",
        "Remove `X-Powered-By` and hide version numbers in the `Server` header."),
    "web-exposed-env-file": Rule(
        "critical", "ASVS-V14", "CWE-538", "The website's .env file can be downloaded",
        "This file usually holds database passwords and API keys, and anyone can download it.",
        "Delete it from the public folder, block dot-files on the server, and rotate every key it contained."),
    "web-exposed-git": Rule(
        "critical", "ASVS-V14", "CWE-527", "The website's .git folder can be downloaded",
        "Anyone can download the full source code history, often including old passwords and keys.",
        "Block access to `/.git/` on the server (or deploy without it) and rotate any secret ever committed."),
    "web-source-map-exposed": Rule(
        "warning", "ASVS-V14", "CWE-540", "The website's original source code is public",
        "Source map files rebuild your original, readable code, making it easy to find weaknesses "
        "and hidden endpoints.",
        "Stop uploading `.map` files to production, or restrict them to your error-tracking service."),
}
RULES.update(WEB_RULES)

# Used only for rules added later without a policy entry, so nothing is ever left unrated.
_FALLBACK = {"ERROR": "critical", "WARNING": "warning", "INFO": "smell"}


def rule_for(finding: dict) -> Rule:
    """Policy entry for a scanner finding (secrets from any Gitleaks rule share one entry)."""
    if finding["category"] == "secret":
        if finding["rule_id"] in WEB_RULES:
            return RULES[finding["rule_id"]]
        return RULES["web-secret"] if finding.get("extra", {}).get("target") == "web" else RULES["secret"]
    if finding["rule_id"] in RULES:
        return RULES[finding["rule_id"]]
    severity = "smell" if finding["category"] == "smell" else _FALLBACK.get(finding["tool_severity"], "warning")
    cwe = str(finding.get("extra", {}).get("cwe", "")).split(":")[0]
    control = "ASVS-V14" if finding.get("extra", {}).get("target") == "web" else "MASVS-CODE"
    return Rule(severity, control, cwe, finding["rule_id"].replace("-", " ").capitalize(),
                finding["message"], "")


def standard(rule: Rule) -> dict:
    """How the report cites a rule: framework, control, its plain name, and the CWE id."""
    family = rule.control.split("-", 1)[0]
    return {"framework": FRAMEWORKS.get(family, family), "control": rule.control,
            "control_area": CONTROLS.get(rule.control, ""), "cwe": rule.cwe}
