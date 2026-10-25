"""Regression tests for the parts that decide what a paid report contains.

Run:  .venv/bin/python -m unittest discover -s tests -v

Fast tests run always. The golden APK test needs samples/fdroid.apk and the scanners installed,
and runs only with RUN_GOLDEN=1 (it takes a few minutes with the REA engine).
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import unittest
import unittest.mock
import zipfile
from pathlib import Path

from scanner import accounts, billing, fixer, limits, policy, signing, source
from scanner.report import result_fingerprint
from scanner.scan import _jwt_claims, _run_semgrep
from scanner.web import WebScanError, check_target, normalize_url, verification_token

ROOT = Path(__file__).resolve().parent.parent
WEB_DEMO = ROOT / "samples" / "web-demo"

# The F-Droid result every engine change must keep (or explain): see README "Repeatable results".
GOLDEN_FDROID_COUNTS = {"critical": 1, "warning": 4, "smell": 7}
GOLDEN_FDROID_RULES = {
    "zip-path-traversal", "nsc-cleartext", "old-target-sdk", "runtime-exec", "weak-hash", "external-storage",
    "allow-backup", "catch-null-pointer", "handler-without-looper", "empty-catch-block", "print-stack-trace",
    "system-exit",
}


def _rule_ids(path: Path) -> list[str]:
    return re.findall(r"(?m)^  - id: ([\w-]+)", path.read_text())


class PolicyTests(unittest.TestCase):
    def test_every_rule_has_a_fixed_severity(self):
        ids = _rule_ids(ROOT / "rules" / "android.yml") + _rule_ids(ROOT / "rules" / "web.yml")
        missing = [i for i in ids if i not in policy.RULES]
        self.assertEqual(missing, [], "add these rules to scanner/policy.py")

    def test_policy_values_are_valid(self):
        for rule_id, rule in policy.RULES.items():
            with self.subTest(rule_id):
                self.assertIn(rule.severity, ("critical", "warning", "smell"))
                self.assertIn(rule.control, policy.CONTROLS)
                self.assertRegex(rule.cwe, r"^CWE-\d+$")
                self.assertTrue(rule.title and rule.risk and rule.fix)

    def test_secrets_are_always_critical(self):
        for target in ("android", "web"):
            finding = {"category": "secret", "rule_id": "generic-api-key", "tool_severity": "ERROR",
                       "extra": {"target": target}}
            self.assertEqual(policy.rule_for(finding).severity, "critical")


class FingerprintTests(unittest.TestCase):
    ISSUE = {"rule_id": "weak-hash", "severity": "warning", "occurrences": 1,
             "locations": [{"file": "a.java", "line": 3}], "more_locations": [], "more_locations_count": 0}

    def test_fingerprint_ignores_ai_wording(self):
        a = dict(self.ISSUE, explanation="one wording", ai_review={"verdict": "confirmed"})
        b = dict(self.ISSUE, explanation="another wording", ai_review={"verdict": "likely_false_alarm"})
        self.assertEqual(result_fingerprint([a]), result_fingerprint([b]))

    def test_fingerprint_changes_with_findings(self):
        moved = dict(self.ISSUE, locations=[{"file": "a.java", "line": 4}])
        self.assertNotEqual(result_fingerprint([self.ISSUE]), result_fingerprint([moved]))


class WebSafetyTests(unittest.TestCase):
    def test_private_networks_are_refused(self):
        for url in ("http://10.0.0.1/", "http://192.168.1.1/", "http://169.254.169.254/latest/meta-data"):
            with self.subTest(url), self.assertRaises(WebScanError):
                check_target(normalize_url(url))

    def test_only_http_urls(self):
        for url in ("file:///etc/passwd", "ftp://example.com", "javascript:alert(1)"):
            with self.subTest(url), self.assertRaises(WebScanError):
                normalize_url(url)

    def test_https_certificates_are_checked(self):
        # python.org builds for macOS have no root certificates; scanner/tls.py must supply them,
        # without switching verification off.
        from scanner import tls
        import ssl
        self.assertEqual(tls.CONTEXT.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(tls.CONTEXT.check_hostname)

    def test_token_is_stable_per_site(self):
        self.assertEqual(verification_token("https://myapp.com/a"), verification_token("myapp.com"))
        self.assertNotEqual(verification_token("myapp.com"), verification_token("other.com"))

    def test_meta_tag_verification(self):
        from scanner import web
        token = verification_token("https://myapp.com")
        ok = [f'<meta name="vibeguard-site-verification" content="{token}">',
              f"<meta content='{token}' name='vibeguard-site-verification'/>",
              f'<META NAME="vibeguard-site-verification" CONTENT="{token}" />']
        for html in ok:
            with self.subTest(html):
                self.assertTrue(web._has_meta_token(f"<html><head>{html}</head></html>", token))
        self.assertFalse(web._has_meta_token('<meta name="vibeguard-site-verification" content="vibeguard-verify=wrong">', token))
        self.assertFalse(web._has_meta_token(f'<meta name="description" content="{token}">', token))

    def test_ownership_methods(self):
        from scanner import web
        info = web.verification_instructions("https://myapp.com")
        page = f'<html><head><meta name="vibeguard-site-verification" content="{info["token"]}"></head></html>'.encode()

        def site(home=(200, b"<html></html>"), home_final="https://myapp.com/", file=(404, b"")):
            follow = lambda url: (home_final, home[0], [], home[1], [])  # noqa: E731
            fetch = lambda url: (file[0], [], file[1])  # noqa: E731
            return unittest.mock.patch.multiple(web, _follow=follow, _fetch=fetch)

        with site(home=(200, page)):
            self.assertEqual(web.check_ownership("https://myapp.com"), "meta")
        with site(file=(200, info["token"].encode())):
            self.assertEqual(web.check_ownership("https://myapp.com"), "file")
        with site(home=(200, page), home_final="https://other-site.com/"), self.assertRaises(web.NotVerifiedError):
            web.check_ownership("https://myapp.com")  # the tag must be on the site itself, not where it redirects
        with site(file=(307, b"Redirecting...")), self.assertRaises(web.NotVerifiedError):
            web.check_ownership("https://myapp.com")  # a login redirect doesn't count as the file

    def test_trusted_sites_setting(self):
        from scanner import web
        with unittest.mock.patch.dict(os.environ, {"WEB_VERIFY_EXEMPT_HOSTS": "job-tracker.in, *.mycompany.dev"}):
            self.assertEqual(web.check_ownership("https://job-tracker.in/dashboard"), "trusted")
            self.assertEqual(web.check_ownership("https://staging.mycompany.dev"), "trusted")
            self.assertFalse(web.is_trusted("https://job-tracker.in.evil.com"))
            self.assertFalse(web.is_trusted("https://mycompany.dev.evil.com"))
        without = {k: v for k, v in os.environ.items() if k != "WEB_VERIFY_EXEMPT_HOSTS"}
        with unittest.mock.patch.dict(os.environ, without, clear=True):
            self.assertFalse(web.is_trusted("https://job-tracker.in"), "nothing is trusted unless the server sets it")

    def test_direct_capture_fallback(self):
        from scanner import web
        html = (b'<html><head><script src="/_next/static/chunks/app.js"></script>'
                b'<link rel="modulepreload" href="/_next/static/chunks/page.js">'
                b'<script src="https://cdn.other.com/lib.js"></script></head>'
                b'<body><script>window.__CONFIG = {"stripe": "pk_test_1"};</script></body></html>')
        served = {"https://myapp.com/_next/static/chunks/app.js": b"el.innerHTML = userText;\n//# sourceMappingURL=app.js.map",
                  "https://myapp.com/_next/static/chunks/app.js.map": b'{"version":3,"mappings":"AAAA"}',
                  "https://myapp.com/_next/static/chunks/page.js": b"console.log(1)"}
        fetched = []

        def fetch(url):
            fetched.append(url)
            return (200, [], served[url]) if url in served else (404, [], b"")
        with tempfile.TemporaryDirectory() as tmp, unittest.mock.patch.object(web, "_fetch", fetch), \
                unittest.mock.patch.object(web, "check_target", lambda url: None):
            cap = web.capture_direct("https://myapp.com/", html, Path(tmp))
            files = sorted(p.relative_to(cap["scripts_dir"]).as_posix() for p in cap["scripts_dir"].rglob("*.js"))
        self.assertNotIn("https://cdn.other.com/lib.js", fetched, "other sites' scripts are not fetched")
        self.assertEqual(files, ["myapp.com/_next/static/chunks/app.js", "myapp.com/_next/static/chunks/page.js",
                                 "myapp.com/inline/inline-1.js"])
        self.assertEqual([f.rule_id for f in cap["findings"]], ["web-source-map-exposed"])
        self.assertEqual((cap["scripts_linked"], cap["scripts_fetched"]), (2, 2))

    def test_directory_listing(self):
        from scanner import web
        html = [("Content-Type", "text/html")]
        served = {
            # nginx autoindex: reported
            "https://myapp.com/vendor/": (200, html, b'<html><head><title>Index of /vendor/</title></head><body><h1>Index of '
                                                     b'/vendor/</h1><a href="../">../</a><a href="jquery/">jquery/</a></body></html>'),
            # an ordinary page that only mentions the words: not reported
            "https://myapp.com/assets/": (200, html, b'<html><head><title>Docs</title></head><body>Index of /assets/ is '
                                                     b'explained <a href="/help">here</a></body></html>'),
            # a listing behind a redirect is not followed (only the first answer counts)
            "https://myapp.com/static/": (301, [("Location", "/static/index.html")], b""),
        }
        with tempfile.TemporaryDirectory() as tmp, \
                unittest.mock.patch.object(web, "_fetch", lambda url: served.get(url, (404, [], b""))):
            found = web._directory_listings("https://myapp.com", Path(tmp))
            evidence = (Path(tmp) / "directory-listing.txt").read_text()
        self.assertEqual([f.rule_id for f in found], ["web-directory-listing"])
        self.assertIn("/vendor/", found[0].message)
        self.assertNotIn("/assets/", found[0].message)
        self.assertIn("jquery/", evidence)
        self.assertEqual(policy.rule_for({"rule_id": "web-directory-listing", "category": "security",
                                          "extra": {"target": "web"}}).severity, "warning")

    def test_supabase_key_roles(self):
        key = re.search(r'SUPABASE_SERVICE_KEY = "([^"]+)"', (WEB_DEMO / "app.js").read_text()).group(1)
        self.assertEqual(_jwt_claims(key)["jwt_role"], "service_role")


class WebRuleTests(unittest.TestCase):
    def test_demo_site_findings(self):
        findings = _run_semgrep([WEB_DEMO], WEB_DEMO, ROOT / "rules" / "web.yml")
        got = sorted((f.rule_id, f.line) for f in findings if f.file.endswith("app.js"))
        self.assertEqual(got, [
            ("web-eval", 15), ("web-innerhtml-assignment", 9), ("web-innerhtml-assignment", 37),
            ("web-insecure-http-request", 20), ("web-postmessage-no-origin-check", 36),
            ("web-postmessage-wildcard", 41), ("web-sensitive-console-log", 26), ("web-token-in-localstorage", 25),
        ])


class SignatureTests(unittest.TestCase):
    GOOD = {"verified": True, "v1": True, "v2": True, "v3": True, "signers": [
        {"subject": "CN=Real Dev", "key_algorithm": "RSA", "key_bits": 4096}]}

    def rules(self, sig: dict) -> list[str]:
        return sorted(f.rule_id for f in signing.signature_findings(sig))

    def test_signing_rules_have_a_policy(self):
        for rule_id in ("apk-signature-invalid", "apk-signature-v1-only", "apk-debug-certificate", "apk-weak-signing-key"):
            self.assertIn(rule_id, policy.RULES)

    def test_classification(self):
        self.assertEqual(self.rules(self.GOOD), [])
        self.assertEqual(self.rules({"verified": False, "errors": ["no signature"]}), ["apk-signature-invalid"])
        self.assertEqual(self.rules(dict(self.GOOD, v2=False, v3=False)), ["apk-signature-v1-only"])
        debug = dict(self.GOOD, signers=[{"subject": "C=US,O=Android,CN=Android Debug", "key_algorithm": "RSA", "key_bits": 1024}])
        self.assertEqual(self.rules(debug), ["apk-debug-certificate", "apk-weak-signing-key"])

    @unittest.skipUnless(signing.apksig_available() and (ROOT / "samples" / "fdroid.apk").is_file(), "needs Java + apksig")
    def test_real_apks(self):
        sig = signing.read_signature(ROOT / "samples" / "fdroid.apk")
        self.assertTrue(sig["verified"])
        self.assertEqual(sig["signers"][0]["sha256"], "43238d512c1e5eb2d6569f4a3afbf5523418b82e0a3ed1552770abb9a9c9ccab")
        self.assertEqual(self.rules(sig), [])
        with tempfile.TemporaryDirectory() as tmp:
            broken = Path(tmp) / "unsigned.apk"
            with zipfile.ZipFile(broken, "w") as z:
                z.writestr("AndroidManifest.xml", "not signed")
            self.assertEqual(self.rules(signing.read_signature(broken)), ["apk-signature-invalid"])


class TempDataDir(unittest.TestCase):
    """Stored scans, orders and usage counts go to a throwaway folder."""
    REPORT = json.loads((ROOT / "static" / "sample-report.json").read_text())["report"]

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.old_dir, billing.DATA_DIR = billing.DATA_DIR, Path(self.tmp.name)

    def tearDown(self):
        billing.DATA_DIR = self.old_dir
        self.tmp.cleanup()


class BillingTests(TempDataDir):
    def test_free_report_hides_details(self):
        locked = billing.lock_report(self.REPORT)
        self.assertEqual(locked["counts"], self.REPORT["counts"])
        self.assertEqual(locked["result_fingerprint"], self.REPORT["result_fingerprint"])
        text = json.dumps(locked)
        for hidden in ('"locations"', '"explanation"', '"fix"', '"ai_suggestions"', ".java"):
            self.assertNotIn(hidden, text)

    def test_pay_then_unlock(self):
        report_id = billing.save_scan({"state": 1}, billing.lock_report(self.REPORT))
        with self.assertRaises(billing.BillingError):
            billing.full_report(report_id, lambda state: self.REPORT)  # not paid yet
        with self.assertRaises(billing.BillingError):
            billing.create_checkout(report_id, "fix")  # coming soon
        order = billing.create_checkout(report_id, "report")
        self.assertEqual(billing.get_order(order["order_id"])["price_cents"], 2900)
        billing.complete_demo_order(order["order_id"])
        built = []
        full = billing.full_report(report_id, lambda state: built.append(state) or self.REPORT)
        billing.full_report(report_id, lambda state: built.append(state) or self.REPORT)
        self.assertEqual(full["result_fingerprint"], self.REPORT["result_fingerprint"])
        self.assertEqual(built, [{"state": 1}], "the paid report is built once, from the stored scan")

    def test_report_in_another_language_is_built_once(self):
        report_id = billing.save_scan({"state": 1}, billing.lock_report(self.REPORT))
        billing.complete_demo_order(billing.create_checkout(report_id, "report")["order_id"])  # paid in English
        billing.full_report(report_id, lambda state: self.REPORT)
        built = []
        german = dict(self.REPORT, disclaimer="auf Deutsch")
        for _ in range(2):
            self.assertEqual(billing.report_in_language(report_id, "de", lambda s: built.append(s) or german), german)
        self.assertEqual(built, [{"state": 1}])
        self.assertEqual(billing.report_in_language(report_id, "en", lambda s: 1 / 0), self.REPORT)

    def test_cancelled_order_cannot_be_paid(self):
        report_id = billing.save_scan({}, billing.lock_report(self.REPORT))
        order = billing.create_checkout(report_id, "report")["order_id"]
        billing.cancel_order(order)
        with self.assertRaises(billing.BillingError):
            billing.complete_demo_order(order)

    def test_ids_cannot_escape_the_data_folder(self):
        for bad in ("../../etc/passwd", "a/b", "", "x" * 65):
            with self.subTest(bad), self.assertRaises(billing.BillingError):
                billing.load_scan(bad)


class FreeLimitTests(TempDataDir):
    def test_daily_limit_is_per_account(self):
        ip = limits.visitor_key("203.0.113.7")
        with unittest.mock.patch.dict(os.environ, {"FREE_SCANS_PER_DAY": "2"}):
            limits.reserve("acct_a", ip)
            limits.reserve("acct_a", ip)
            with self.assertRaises(limits.LimitError):
                limits.reserve("acct_a", ip)
            limits.refund("acct_a", ip)  # a failed scan gives the scan back
            self.assertEqual(limits.status("acct_a")["left_today"], 1)
            # a new network does not reset the account's count
            with self.assertRaises(limits.LimitError):
                limits.reserve("acct_a", limits.visitor_key("198.51.100.9"))
                limits.reserve("acct_a", limits.visitor_key("198.51.100.9"))

    def test_unlimited_account(self):
        account, _ = None, None
        email = accounts.normalize_email("tester@company.io")
        accounts._write("accounts", accounts._key("email", email), {"id": "acct_unlim", "email": email, "created": 0})
        ip = limits.visitor_key("203.0.113.7")
        with unittest.mock.patch.dict(os.environ, {"UNLIMITED_ACCOUNTS": "Tester@company.io", "FREE_SCANS_PER_DAY": "1",
                                                   "FREE_SCANS_PER_IP_PER_DAY": "1"}):
            for _ in range(5):
                limits.reserve("acct_unlim", ip)  # never refused, not even by the network cap
            self.assertTrue(limits.status("acct_unlim")["unlimited"])
            limits.reserve("acct_other", ip)  # the network cap still counts other accounts' scans normally
            with self.assertRaises(limits.LimitError):
                limits.reserve("acct_other", ip)
        self.assertFalse(limits.is_unlimited("acct_unlim"), "only while the server setting lists it")

    def test_network_cap_across_accounts(self):
        ip = limits.visitor_key("203.0.113.7")
        with unittest.mock.patch.dict(os.environ, {"FREE_SCANS_PER_DAY": "5", "FREE_SCANS_PER_IP_PER_DAY": "3"}):
            for n in range(3):
                limits.reserve(f"acct_{n}", ip)
            with self.assertRaises(limits.LimitError):
                limits.reserve("acct_new", ip)

    def test_visitor_key_hides_the_ip(self):
        key = limits.visitor_key("203.0.113.7")
        self.assertNotIn("203", key)
        self.assertEqual(key, limits.visitor_key("203.0.113.7"))

    def test_saved_scan_is_reused_only_by_its_owner(self):
        alice, bob = limits.visitor_key("198.51.100.1"), limits.visitor_key("198.51.100.2")
        report_id = billing.save_scan({}, billing.lock_report(self.REPORT), alice, "apk:abc:jadx")
        self.assertEqual(billing.find_recent_scan(alice, "apk:abc:jadx"), report_id)
        self.assertIsNone(billing.find_recent_scan(bob, "apk:abc:jadx"))
        self.assertIsNone(billing.find_recent_scan(alice, "apk:abc:rea"))


class AccountTests(TempDataDir):
    IP = "ip-hash"

    def sign_in(self, email: str) -> tuple[dict, str]:
        code = accounts.start_sign_in(email)["demo_code"]
        return accounts.verify_code(email, code, self.IP)

    def setUp(self):
        super().setUp()
        self.env = unittest.mock.patch.dict(os.environ, {"AUTH_MODE": "local", "EMAIL_MODE": "demo"})
        self.env.start()

    def tearDown(self):
        self.env.stop()
        super().tearDown()

    def test_one_account_per_inbox(self):
        self.assertEqual(accounts.normalize_email(" Jane.Doe+apk@GMail.com "), "janedoe@gmail.com")
        self.assertEqual(accounts.normalize_email("jane+x@company.io"), "jane@company.io")
        for bad in ("not-an-email", "a@b", "x@mailinator.com", "+tag@company.io"):
            with self.subTest(bad), self.assertRaises(accounts.AuthError):
                accounts.normalize_email(bad)

    def test_sign_in_and_session(self):
        account, token = self.sign_in("jane@company.io")
        self.assertEqual(accounts.account_for_session(token)["id"], account["id"])
        with unittest.mock.patch("time.time", return_value=__import__("time").time() + 61):
            again, _ = self.sign_in("Jane+other@company.io")
        self.assertEqual(again["id"], account["id"], "same inbox, same account")
        accounts.end_session(token)
        self.assertIsNone(accounts.account_for_session(token))
        self.assertIsNone(accounts.account_for_session("made-up-token"))

    def test_codes_are_single_use_and_guess_limited(self):
        code = accounts.start_sign_in("sam@company.io")["demo_code"]
        wrong = "000000" if code != "000000" else "111111"
        for _ in range(accounts.CODE_MAX_ATTEMPTS):
            with self.assertRaises(accounts.AuthError):
                accounts.verify_code("sam@company.io", wrong, self.IP)
        with self.assertRaises(accounts.AuthError):  # even the right code is refused now
            accounts.verify_code("sam@company.io", code, self.IP)

        with unittest.mock.patch("time.time", return_value=__import__("time").time() + 61):
            code = accounts.start_sign_in("sam@company.io")["demo_code"]
            accounts.verify_code("sam@company.io", code, self.IP)
            with self.assertRaises(accounts.AuthError):
                accounts.verify_code("sam@company.io", code, self.IP)

    def test_resend_is_rate_limited(self):
        accounts.start_sign_in("kim@company.io")
        with self.assertRaises(accounts.AuthError):
            accounts.start_sign_in("kim@company.io")

    def test_new_accounts_per_network(self):
        with unittest.mock.patch.dict(os.environ, {"ACCOUNTS_PER_IP_PER_DAY": "2"}):
            self.sign_in("one@company.io")
            self.sign_in("two@company.io")
            with self.assertRaises(accounts.AuthError):
                self.sign_in("three@company.io")

    def test_nothing_secret_is_stored_in_clear(self):
        _, token = self.sign_in("lee@company.io")
        stored = " ".join(p.read_text() + p.name for p in Path(self.tmp.name).rglob("*.json"))
        self.assertNotIn(token, stored)


class SupabaseSignInTests(TempDataDir):
    ENV = {"AUTH_MODE": "supabase", "SUPABASE_URL": "https://example.supabase.co", "SUPABASE_ANON_KEY": "anon"}

    def setUp(self):
        super().setUp()
        self.env = unittest.mock.patch.dict(os.environ, self.ENV)
        self.env.start()

    def tearDown(self):
        self.env.stop()
        super().tearDown()

    def supabase_says(self, user: dict | None = None, status: int = 200):
        """Stand-in for Supabase's GET /auth/v1/user."""
        import io
        import urllib.error

        def fake_urlopen(request, timeout, context=None):
            self.assertIsNotNone(context, "Supabase calls must use scanner/tls.py")
            self.assertEqual(request.full_url, "https://example.supabase.co/auth/v1/user")
            self.assertEqual(request.get_header("Authorization"), "Bearer token-from-browser")
            if status != 200:
                raise urllib.error.HTTPError(request.full_url, status, "no", {}, io.BytesIO(b"{}"))
            return io.BytesIO(json.dumps(user).encode())
        return unittest.mock.patch("urllib.request.urlopen", fake_urlopen)

    GOOGLE_USER = {"id": "uuid-1", "email": "Jane.Doe@gmail.com", "email_confirmed_at": "2026-10-24T08:00:00Z",
                   "app_metadata": {"provider": "google"}}

    def test_google_sign_in_creates_one_account_per_inbox(self):
        with self.supabase_says(self.GOOGLE_USER):
            account, token = accounts.sign_in_with_supabase("token-from-browser", "ip")
            again, _ = accounts.sign_in_with_supabase("token-from-browser", "ip")
        self.assertEqual(account["email"], "janedoe@gmail.com")
        self.assertEqual(again["id"], account["id"])
        self.assertEqual(accounts.account_for_session(token)["last_method"], "google")

    def test_refused_tokens_and_unconfirmed_emails(self):
        with self.supabase_says(status=401), self.assertRaises(accounts.AuthError) as e:
            accounts.sign_in_with_supabase("token-from-browser", "ip")
        self.assertEqual(e.exception.status, 401)
        with self.supabase_says(dict(self.GOOGLE_USER, email_confirmed_at=None)), self.assertRaises(accounts.AuthError):
            accounts.sign_in_with_supabase("token-from-browser", "ip")

    def test_local_codes_are_off_in_supabase_mode(self):
        with self.assertRaises(accounts.AuthError):
            accounts.start_sign_in("jane@company.io")

    def test_config_exposes_only_public_values(self):
        with unittest.mock.patch.object(accounts, "_enabled_providers", return_value={"google": False, "email": True}):
            cfg = accounts.public_config()
        self.assertEqual(cfg["providers"], ["email"], "a provider switched off in Supabase is not offered")
        self.assertEqual(set(cfg), {"mode", "supabase_url", "supabase_anon_key", "providers"})


DEMO_SRC = ROOT / "samples" / "android-demo-src"


class SourceUploadTests(unittest.TestCase):
    def unpack(self, entries: dict, symlink: str | None = None):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        z = Path(tmp.name) / "up.zip"
        with zipfile.ZipFile(z, "w") as archive:
            for name, data in entries.items():
                archive.writestr(name, data)
            if symlink:
                info = zipfile.ZipInfo(symlink)
                info.external_attr = (0o120777 << 16)
                archive.writestr(info, "/etc/passwd")
        return source.unpack_source_zip(z, Path(tmp.name) / "out")[0]

    def test_zip_slip_and_absolute_paths_are_refused(self):
        for bad in ("../evil.java", "app/../../evil.java", "/etc/evil.java", "C:/evil.java"):
            with self.subTest(bad), self.assertRaises(source.SourceError):
                self.unpack({bad: "x"})

    def test_symlinks_and_build_folders_are_skipped(self):
        root = self.unpack({"proj/app/src/A.java": "class A {}", "proj/app/build/Gen.java": "class G {}"},
                           symlink="proj/app/src/link.java")
        self.assertEqual(root.name, "proj", "a single top folder becomes the project root")
        self.assertEqual(sorted(p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()), ["app/src/A.java"])

    def test_secret_files_are_never_unpacked(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        z = Path(tmp.name) / "up.zip"
        with zipfile.ZipFile(z, "w") as archive:
            for name in ("p/app/src/A.kt", "p/app/release.jks", "p/local.properties", "p/.env", "p/keys/upload.keystore",
                         "p/app/google.pem"):
                archive.writestr(name, "secret" if not name.endswith(".kt") else "class A")
        root, left_out = source.unpack_source_zip(z, Path(tmp.name) / "out")
        self.assertEqual(sorted(p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()), ["app/src/A.kt"])
        self.assertEqual(left_out, [".env", "app/google.pem", "app/release.jks", "keys/upload.keystore", "local.properties"])

    def test_demo_project_findings(self):
        scan = source.scan_source(DEMO_SRC.resolve(), gitleaks=False)
        rules = sorted({f["policy_rule"] for f in scan.findings})
        self.assertEqual(rules, sorted(["debuggable", "trust-all-certificates", "zip-path-traversal", "world-readable-file",
                                        "cleartext-traffic", "exported-service", "sensitive-data-logged", "runtime-exec",
                                        "weak-hash", "string-compared-with-equals-sign", "sql-string-concatenation",
                                        "allow-backup", "empty-catch-block", "external-storage", "print-stack-trace",
                                        "catch-null-pointer", "system-exit"]))
        self.assertEqual(scan.kotlin_files, ["app/src/main/java/com/example/taskpal/Reminders.kt",
                                             "app/src/main/java/com/example/taskpal/SyncManager.kt"])
        kotlin = sorted((f["policy_rule"], f["line"]) for f in scan.findings if f["file"].endswith("SyncManager.kt"))
        self.assertEqual(kotlin, [("empty-catch-block", 23), ("sensitive-data-logged", 12), ("sql-string-concatenation", 15),
                                  ("system-exit", 31), ("weak-hash", 18)])
        self.assertFalse([f for f in scan.findings if f["file"].endswith("Reminders.kt")], "clean Kotlin stays clean")


class WebSourceTests(unittest.TestCase):
    def test_web_project_is_scanned(self):
        scan = source.scan_source(WEB_DEMO.resolve(), gitleaks=True)
        self.assertEqual(scan.web_files, ["app.js"])
        code = sorted({f["policy_rule"] for f in scan.findings if f["file"] == "app.js" and f["policy_rule"] != "secret"})
        self.assertEqual(code, ["web-eval", "web-innerhtml-assignment", "web-insecure-http-request",
                                "web-postmessage-no-origin-check", "web-postmessage-wildcard",
                                "web-sensitive-console-log", "web-token-in-localstorage"])
        secrets = sorted(f["title"] for f in scan.findings if f["file"] == "app.js" and f["policy_rule"] == "secret")
        self.assertIn("The Supabase admin key is in the website's code", secrets)

    def test_build_output_and_bundles_are_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for rel in ("src/app.ts", "src/page.tsx", ".next/server/chunk.js", "node_modules/x/index.js",
                        "dist/bundle.js", "public/vendor.min.js", "src/types.d.ts"):
                (root / rel).parent.mkdir(parents=True, exist_ok=True)
                (root / rel).write_text("export const x = 1;\n")
            self.assertEqual([p.relative_to(root).as_posix() for p in source.web_files(root)], ["src/app.ts", "src/page.tsx"])

    def test_nothing_supported_is_a_clear_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "notes.txt").write_text("hello")
            with self.assertRaises(source.SourceError) as e:
                source.scan_source(Path(tmp), gitleaks=False)
        self.assertIn("web projects (.js, .jsx, .ts, .tsx)", str(e.exception))

    def test_export_check(self):
        from scanner.structure import js_breaking_changes
        src = "export function login() {}\nexport default function Page() { return null }\nfunction helper() {}\n"
        self.assertEqual(js_breaking_changes(src, src.replace("function helper() {}", "function helper() { return 1 }")), [])
        self.assertTrue(js_breaking_changes(src, src.replace("export function login", "function login")))
        self.assertTrue(js_breaking_changes(src, src.replace("export default function Page", "function Page")))


class KotlinRuleTests(unittest.TestCase):
    def test_every_kotlin_rule_against_annotated_examples(self):
        import sys
        sys.path.insert(0, str(ROOT / "tests"))
        from rule_annotations import check
        missed, wrong = check(ROOT / "rules" / "android-kotlin.yml", ROOT / "tests" / "rules" / "android-kotlin.kt")
        self.assertEqual((missed, wrong), ([], []))

    def test_kotlin_rules_use_policy_ids(self):
        ids = _rule_ids(ROOT / "rules" / "android-kotlin.yml")
        self.assertTrue(ids)
        self.assertEqual([i for i in ids if i not in policy.RULES], [])
        self.assertLessEqual(set(ids), set(_rule_ids(ROOT / "rules" / "android.yml")), "same ids as the Java rules")

    def test_kotlin_interface_check(self):
        from scanner.structure import kotlin_breaking_changes
        src = ('class Sync(private val db: Db) {\n    fun signIn(user: String, token: String) { }\n'
               '    private fun helper() {}\n    val t = object : X509TrustManager {\n'
               '        override fun checkServerTrusted(c: Array<X509Certificate>?, a: String?) {}\n    }\n}\n'
               'class Empty {\n    fun go() {}\n}\n')
        self.assertEqual(kotlin_breaking_changes(src, src.replace("user: String", "who: String")), [])
        self.assertEqual(kotlin_breaking_changes(src, src.replace("    private fun helper() {}\n", "")), [])
        self.assertEqual(kotlin_breaking_changes(src, re.sub(r"    val t = object[\s\S]*?\n    }\n", "", src)), [])
        self.assertTrue(kotlin_breaking_changes(src, src.replace("token: String)", "token: CharSequence)")))
        self.assertTrue(kotlin_breaking_changes(src, src.replace("(private val db: Db)", "(private val db: Db, ctx: Ctx)")))
        self.assertTrue(kotlin_breaking_changes(src, src.replace("class Empty {", "class Empty(val x: Int) {")))

    def test_kotlin_functions_are_measured(self):
        from scanner.structure import measure_kotlin
        body = "\n".join(f"        val v{i} = {i}" for i in range(80))
        src = (f"class K {{\n    fun big(a: Int, b: Int, c: Int, d: Int, e: Int, f: Int, g: Int, h: Int): Int {{\n{body}\n"
               "        return a\n    }\n    fun small() = 1\n}\n")
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "K.kt").write_text(src)
            found = [(i["rule_id"], i["method"], i["lines"], i["parameters"]) for i in measure_kotlin(Path(tmp), ["K.kt"])]
        self.assertEqual(found, [("long-method", "big", 83, 8), ("too-many-parameters", "big", 83, 8)])


class FixerTests(unittest.TestCase):
    def test_edits_must_match_exactly_once(self):
        text = "a = 1;\nb = 1;\n"
        self.assertEqual(fixer._apply_edits(text, [{"find": "a = 1;", "replace": "a = 2;"}]), ("a = 2;\nb = 1;\n", None))
        self.assertIn("does not occur", fixer._apply_edits(text, [{"find": "c = 1;", "replace": ""}])[1])
        self.assertIn("occurs 2 times", fixer._apply_edits(text, [{"find": " = 1;", "replace": ""}])[1])

    def test_judge(self):
        from collections import Counter
        before = Counter({"weak-hash": 1, "empty-catch-block": 1})
        self.assertIsNone(fixer._judge("weak-hash", 1, before, Counter({"empty-catch-block": 1}), False, False))
        self.assertIn("still finds", fixer._judge("weak-hash", 1, before, before, False, False))
        self.assertIn("new problem", fixer._judge("weak-hash", 1, before, Counter({"empty-catch-block": 2}), False, False))
        self.assertIn("syntax", fixer._judge("weak-hash", 1, before, Counter(), False, True))
        self.assertEqual(fixer._judge("sql", 2, Counter({"sql": 2}), Counter({"sql": 1}), False, False), "partly")

    def test_secrets_and_smells_are_not_auto_fixed(self):
        groups, manual, later = fixer.plan([
            {"policy_rule": "secret", "severity": "critical", "file": "A.java", "line": 1},
            {"policy_rule": "empty-catch-block", "severity": "smell", "file": "A.java", "line": 2},
            {"policy_rule": "weak-hash", "severity": "warning", "file": "A.java", "line": 3},
            {"policy_rule": "weak-hash", "severity": "warning", "file": "A.java", "line": 9}])
        self.assertEqual([(g["rule_id"], len(g["findings"])) for g in groups], [("weak-hash", 2)])
        self.assertEqual((len(manual), len(later)), (1, 1))

    def test_a_correct_zip_fix_passes_the_rule(self):
        original = (DEMO_SRC / "app/src/main/java/com/example/taskpal/BackupImporter.java").read_text()
        fixed = original.replace("File out = new File(targetDir, entry.getName());\n",
                                 "File out = new File(targetDir, entry.getName());\n"
                                 "                if (!out.getCanonicalPath().startsWith(targetDir.getCanonicalPath() + File.separator)) {\n"
                                 "                    throw new IOException(\"Bad entry\");\n                }\n")
        anchor = "File out = new File(targetDir, entry.getName());\n"
        stored = original.replace(anchor, anchor + "                File c = out.getCanonicalFile();\n"
                                  "                if (!c.toPath().startsWith(targetDir.getCanonicalFile().toPath())) {\n"
                                  "                    throw new IOException(\"Bad entry\");\n                }\n")
        unrelated = original.replace(anchor, anchor + "                if (entry.getName().startsWith(\"x\")) { }\n")
        with tempfile.TemporaryDirectory() as tmp:
            for name, text in (("Original.java", original), ("Fixed.java", fixed), ("FixedStored.java", stored),
                               ("Unrelated.java", unrelated)):
                (Path(tmp) / name).write_text(text)
            found, errors = source.semgrep_files(sorted(Path(tmp).glob("*.java")), Path(tmp))
        self.assertEqual(sorted({f.file for f in found if f.rule_id == "zip-path-traversal"}), ["Original.java", "Unrelated.java"])
        self.assertEqual(errors, [])


class ImproveTierTests(unittest.TestCase):
    def test_improve_also_fixes_smells_but_never_secrets(self):
        findings = [{"policy_rule": "secret", "severity": "critical", "file": "A.java", "line": 1},
                    {"policy_rule": "empty-catch-block", "severity": "smell", "file": "A.java", "line": 2},
                    {"policy_rule": "weak-hash", "severity": "warning", "file": "A.java", "line": 3}]
        groups, manual, later = fixer.plan(findings, fixer.TIERS["improve"]["severities"])
        self.assertEqual([g["rule_id"] for g in groups], ["weak-hash", "empty-catch-block"])
        self.assertEqual((len(manual), len(later)), (1, 0))

    def test_structure_is_measured_deterministically(self):
        from scanner import structure
        root = DEMO_SRC.resolve()
        java = [p.relative_to(root).as_posix() for p in source.project_files(root, ".java")]
        found = [(i["rule_id"], i["method"], i["lines"], i["parameters"]) for i in structure.measure(root, java)]
        self.assertEqual(found, [("too-many-parameters", "export", 14, 8), ("long-method", "toRow", 104, 1)])
        self.assertEqual(found, [(i["rule_id"], i["method"], i["lines"], i["parameters"]) for i in structure.measure(root, java)])

    def test_parameter_counting(self):
        from scanner.structure import _describe
        self.assertEqual(_describe("public <K, V> Map<K, V> zip(List<K> a, Map<String, List<V>> b, @Nullable String c) {"),
                         {"name": "zip", "parameters": 3})
        self.assertEqual(_describe("@Override public void run() {")["parameters"], 0)

    def test_interface_check(self):
        from scanner.structure import breaking_changes
        before = ("public class A {\n  public A() {}\n  public int size(String key, int n) { return 1; }\n"
                  "  private void helper() { Runnable r = new Runnable() { public void run() {} }; }\n}\n")
        self.assertEqual(breaking_changes(before, before.replace("String key", "String k")), [], "parameter names don't matter")
        self.assertEqual(breaking_changes(before, before.replace("  private void helper() { Runnable r = new Runnable() "
                                                                 "{ public void run() {} }; }\n", "")), [],
                         "private methods and anonymous classes may change")
        self.assertTrue(breaking_changes(before, before.replace("int n", "long n")))
        self.assertTrue(breaking_changes(before, before.replace("public int size", "private int size")))
        no_ctor = "public class B {\n  void go() {}\n}\n"
        self.assertTrue(breaking_changes(no_ctor, no_ctor.replace("  void go", "  public B(int x) {}\n  void go")),
                        "a first constructor removes the default one")
        self.assertEqual(breaking_changes(no_ctor, no_ctor.replace("void go() {}", "void go() { if (true) { } }")), [])

    def test_pull_request_package(self):
        result = {"tier_name": "Code improvement", "policy_version": "1.3.0",
                  "summary": {"fixed": 1}, "before": {"counts": {"critical": 1, "warning": 0, "smell": 1}, "fingerprint": "a"},
                  "after": {"counts": {"critical": 0, "warning": 0, "smell": 1}, "fingerprint": "b"},
                  "verification": {"patch_sha256": "f" * 64}, "manual_actions": [],
                  "fixes": [{"status": "fixed", "title": "Weak hash", "file": "A.java", "summary": "Use SHA-256. Note: rehash PINs.",
                             "standard": {"cwe": "CWE-328"}, "reason": ""},
                            {"status": "needs_manual_fix", "title": "Exec", "file": "B.java", "summary": "", "standard": None,
                             "reason": "unsafe"}],
                  "structure": {"issues": []}}
        with tempfile.TemporaryDirectory() as tmp:
            pr = fixer._pull_request(result, Path(tmp))
            body = (Path(tmp) / "pr-description.md").read_text()
            commit = (Path(tmp) / "commit-message.txt").read_text()
        self.assertIn("- [x] **Weak hash** (CWE-328)", body)
        self.assertIn("- [ ] **Exec**", body)
        self.assertIn("## Data migration", body)
        self.assertNotIn("Exec", commit, "unfixed issues are not claimed in the commit message")
        self.assertIn("git apply fixes.patch", pr["commands"])


class PaidSourceReuseTests(TempDataDir):
    def test_reopening_a_paid_fixing_result_does_not_crash(self):
        import api
        report_id = billing.save_scan({}, {"target": "source", "locked": True}, "acct_a", kind="source")
        record = billing.load_scan(report_id)
        record.update(paid=True, full_report={"kind": "fix", "tier": "improve", "fixes": []})
        billing._write("reports", report_id, record)
        response = api._stored(report_id, None, reused=True)
        self.assertTrue(response["paid"])
        self.assertEqual(response["report"]["kind"], "fix")
        self.assertNotIn("report_text", response)


class CleanupTests(TempDataDir):
    def test_expired_scans_uploads_and_sessions_are_deleted(self):
        report_id = billing.new_id()
        (billing.job_dir(report_id) / "source").mkdir(parents=True)
        billing.save_scan({}, {}, "acct_a", kind="source", report_id=report_id)
        fresh = billing.save_scan({}, {}, "acct_a")
        accounts._write("sessions", "old", {"account_key": "k", "expires": 1})
        accounts._write("sessions", "live", {"account_key": "k", "expires": __import__("time").time() + 3600})
        with unittest.mock.patch.object(billing, "REPORT_TTL_SECONDS", 0):
            __import__("time").sleep(0.05)
            self.assertEqual(billing.purge_expired(), 2)
        self.assertFalse(billing.job_dir(report_id).exists(), "the uploaded project is deleted too")
        self.assertEqual(accounts.purge_expired(), 1)
        self.assertEqual(sorted(p.stem for p in (billing.DATA_DIR / "sessions").glob("*.json")), ["live"])
        self.assertFalse((billing.DATA_DIR / "reports" / f"{fresh}.json").exists())

    def test_cleanup_runs_on_a_schedule(self):
        import api
        self.assertTrue(any(getattr(h, "__name__", "") == "start_cleanup" for h in api.app.router.on_startup))


class FixTierBillingTests(TempDataDir):
    def test_plans_match_what_was_scanned(self):
        app = billing.save_scan({}, billing.lock_report(self.REPORT), "acct_a", kind="scan")
        src = billing.save_scan({}, {"counts": {}, "result_fingerprint": "x", "scan": {"apk_name": "p"}}, "acct_a", kind="source")
        with self.assertRaises(billing.BillingError):
            billing.create_checkout(app, "fix")  # fixing needs the source code
        with self.assertRaises(billing.BillingError):
            billing.create_checkout(src, "report")
        self.assertEqual(billing.get_order(billing.create_checkout(src, "fix")["order_id"])["price_cents"], 9900)
        self.assertEqual(billing.get_order(billing.create_checkout(src, "improve")["order_id"])["price_cents"], 19900)
        with self.assertRaises(billing.BillingError):
            billing.create_checkout(app, "improve")

    def test_audit_costs_more_for_android_projects(self):
        android = billing.save_scan({}, {"counts": {}, "result_fingerprint": "x", "scan": {"apk_name": "p"},
                                         "coverage": {"manifests": ["app/src/main/AndroidManifest.xml"]}},
                                    "acct_a", kind="source")
        self.assertEqual(billing.get_order(billing.create_checkout(android, "improve")["order_id"])["price_cents"], 24900)
        self.assertEqual(billing.get_order(billing.create_checkout(android, "fix")["order_id"])["price_cents"], 9900)
        prices = {p["id"]: p["price_cents"] for p in billing.public_plans(billing.load_scan(android))}
        self.assertEqual(prices, {"report": 2900, "fix": 9900, "improve": 24900})

    def test_paid_plan_decides_the_tier(self):
        src = billing.save_scan({"source_root": "x"}, {"counts": {}, "result_fingerprint": "x", "scan": {"apk_name": "p"}},
                                "acct_a", kind="source")
        billing.complete_demo_order(billing.create_checkout(src, "improve")["order_id"])
        self.assertEqual(billing.load_scan(src)["state"]["tier"], "improve")

    def test_source_is_deleted_with_the_report(self):
        report_id = billing.new_id()
        job = billing.job_dir(report_id)
        (job / "source").mkdir(parents=True)
        billing.save_scan({}, {}, "acct_a", kind="source", report_id=report_id)
        with unittest.mock.patch.object(billing, "REPORT_TTL_SECONDS", -1):
            with self.assertRaises(billing.BillingError):
                billing.load_scan(report_id)
        self.assertFalse(job.exists())


class DeepEngineGapTests(unittest.TestCase):
    def test_coverage_notes(self):
        from scanner.rea_ingest import _coverage_notes, _coverage_summary
        base = {"methods_total": 6211, "methods_failed": 49, "methods_not_decompiled": 0,
                "classes_completed_with_jadx": ["a.B", "a.C"], "classes_not_fully_decompiled": []}
        self.assertEqual(_coverage_notes(base, None), [], "nothing to warn about when every method was checked")
        self.assertEqual(_coverage_summary(base), "All 6,211 methods checked (49 completed with the fast engine)")
        partly = dict(base, methods_not_decompiled=3, classes_not_fully_decompiled=["org.x.Alpha", "org.x.Beta"])
        self.assertEqual(_coverage_notes(partly, None), ["3 of 6,211 methods (0.0%) could not be decompiled and were not "
                                                         "checked, in 2 classes: Alpha, Beta."])
        self.assertEqual(_coverage_summary(partly), "6,208 of 6,211 methods checked (46 completed with the fast engine)")
        clean = dict(base, methods_failed=0, classes_completed_with_jadx=[])
        self.assertEqual((_coverage_notes(clean, None), _coverage_summary(clean)), ([], "All 6,211 methods checked"))

    def test_fill_only_when_jadx_is_more_complete(self):
        from scanner import rea_ingest
        ok, failed = {"status": "java", "text": "void a() {}"}, {"status": "failed", "text": ""}
        decompiled = {"org.x.Good": {"methods": [ok, failed, failed]}, "org.x.Worse": {"methods": [failed]},
                      "org.x.Act.AnonymousClass1": {"methods": [failed]},          # inner-class alias: lives in Act.java
                      "org.x.ComposableSingletons$HomeKt": {"methods": [failed]},  # Kotlin: its own file with a $
                      "org.x.Fine": {"methods": [ok]}}
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            src = tmp / "sources" / "org" / "x"
            src.mkdir(parents=True)
            for rel in ("Good.java", "Good.smali", "Worse.java", "Act.java", "Act/AnonymousClass1.java",
                        "ComposableSingletons.java", "Fine.java"):
                (src / rel).parent.mkdir(parents=True, exist_ok=True)
                (src / rel).write_text(f"// REA {rel}")

            def fake_jadx(cmd, **kw):
                out = Path(cmd[cmd.index("--output-dir") + 1]) / "sources" / "org" / "x"
                out.mkdir(parents=True)
                (out / "Good.java").write_text("class Good { void a() {} void b() {} }")
                (out / "Worse.java").write_text("/* Method dump skipped */ /* Method dump skipped */ class Worse {}")
                (out / "Act.java").write_text("class Act { static final class AnonymousClass1 {} }")
                (out / "ComposableSingletons$HomeKt.java").write_text("class ComposableSingletons$HomeKt {}")
            with unittest.mock.patch("subprocess.run", fake_jadx):
                gap = rea_ingest._fill_gaps("jadx", tmp / "app.apk", decompiled, tmp / "sources", tmp / "fill")
            self.assertEqual(gap, {"filled": {"org.x.Good": 0, "org.x.Act.AnonymousClass1": 0, "org.x.ComposableSingletons": 0}})
            files = sorted(p.relative_to(src).as_posix() for p in src.rglob("*") if p.is_file())
            self.assertEqual(files, ["Act.java", "ComposableSingletons$HomeKt.java", "Fine.java", "Good.java", "Worse.java"],
                             "REA's incomplete files are removed, so no class is scanned twice")
            self.assertIn("AnonymousClass1", (src / "Act.java").read_text())
            self.assertEqual((src / "Worse.java").read_text(), "// REA Worse.java", "a jadx file with more gaps is not used")
            self.assertEqual((src / "Fine.java").read_text(), "// REA Fine.java", "complete REA classes are left alone")


class CancelScanTests(unittest.TestCase):
    def test_cancel_stops_the_scan_and_its_helper_programs(self):
        import threading
        from scanner import jobs
        with tempfile.TemporaryDirectory() as tmp:
            pidfile = str(Path(tmp) / "helper.pid")
            with unittest.mock.patch.dict(os.environ, {"JOBS_TEST_PIDFILE": pidfile}):
                threading.Timer(2.0, lambda: jobs.cancel("cancel-test")).start()
                started = __import__("time").monotonic()
                with self.assertRaises(jobs.ScanCancelled):
                    jobs.run("cancel-test", jobs.sleep_then, 60, True)
                self.assertLess(__import__("time").monotonic() - started, 10)
                helper = int(Path(pidfile).read_text())
            __import__("time").sleep(0.5)
            with self.assertRaises(ProcessLookupError, msg="the helper program (like jadx) is stopped too"):
                os.kill(helper, 0)
        self.assertFalse(jobs.is_running("cancel-test"))
        self.assertFalse(jobs.cancel("cancel-test"), "nothing left to cancel")

    def test_results_and_errors_come_back(self):
        from scanner import jobs
        self.assertEqual(jobs.run("ok-test", jobs.sleep_then, 0.1), "finished")
        with self.assertRaises(ValueError):
            jobs.run("err-test", int, "not a number")

    def test_cancelled_scan_gives_the_free_scan_back(self):
        import threading
        from fastapi.testclient import TestClient
        import api
        from scanner import jobs
        account = {"id": "acct_cancel", "email": "c@company.io"}
        with tempfile.TemporaryDirectory() as tmp:
            old_dir, billing.DATA_DIR = billing.DATA_DIR, Path(tmp)
            try:
                with unittest.mock.patch.object(api, "_account", lambda request: account), \
                        unittest.mock.patch.object(api.billing, "paywall_enabled", lambda: True), \
                        unittest.mock.patch.object(api, "scan_website", jobs.sleep_then):  # stands in for a long scan
                    client = TestClient(api.app)
                    threading.Timer(2.5, lambda: client.post("/scans/cancel")).start()
                    r = client.post("/scan-web", data={"url": "60", "i_am_authorized": "true"})
                    self.assertEqual(r.status_code, 409)
                    self.assertTrue(r.json()["detail"]["cancelled"])
                    self.assertEqual(limits.status("acct_cancel")["used_today"], 0, "the free scan was given back")
                    active = client.get("/scans/active").json()["active"]
                    self.assertEqual((active["running"], active["error"]), (False, "You cancelled this scan."))
            finally:
                billing.DATA_DIR = old_dir
                api._active.pop("acct_cancel", None)


class ActiveScanTests(unittest.TestCase):
    def test_second_scan_follows_the_running_one(self):
        from fastapi.testclient import TestClient
        import api
        client = TestClient(api.app)
        account = {"id": "acct_follow", "email": "f@company.io"}
        with unittest.mock.patch.object(api, "_account", lambda request: account), \
                unittest.mock.patch.object(api.billing, "paywall_enabled", lambda: True):
            api._scan_started("acct_follow", "apk", "fdroid.apk", "rea")
            try:
                r = client.post("/scan-web", data={"url": "http://127.0.0.1:8100", "i_am_authorized": "true"})
                self.assertEqual(r.status_code, 409)
                self.assertIn("Your deep scan of fdroid.apk is still running", r.json()["detail"]["message"])
                self.assertTrue(client.get("/scans/active").json()["active"]["running"])
                api._scan_finished("acct_follow", report_id="rep123")
                done = client.get("/scans/active").json()["active"]
                self.assertEqual((done["running"], done["report_id"]), (False, "rep123"))
            finally:
                api._active.pop("acct_follow", None)

    def test_signed_out_has_no_active_scan(self):
        from fastapi.testclient import TestClient
        import api
        with unittest.mock.patch.object(api, "_account", lambda request: None):
            self.assertEqual(TestClient(api.app).get("/scans/active").json(), {"active": None})


class GermanTests(unittest.TestCase):
    def test_every_rule_has_german_text(self):
        from scanner import i18n_de
        self.assertEqual([r for r in policy.RULES if r not in i18n_de.RULES], [])
        for rule_id, texts in i18n_de.RULES.items():
            with self.subTest(rule_id):
                self.assertEqual(len(texts), 3)
                self.assertTrue(all(t.strip() for t in texts))

    def test_patterns_compile_and_match_their_examples(self):
        from scanner import i18n_de
        for pattern, _ in i18n_de.PATTERNS:
            re.compile(f"^{pattern}$", re.S)
        def de(text):
            for pattern, to in i18n_de.PATTERNS:
                m = re.fullmatch(pattern, text, re.S)
                if m:
                    return re.sub(r"\$(\d)", lambda g: m.group(int(g.group(1))) or "", to)
        self.assertEqual(de("Free scans left today: 4 of 5. Scanning the same app again is free."),
                         "Heute noch 4 von 5 kostenlosen Scans. Dieselbe App erneut zu scannen ist kostenlos.")
        self.assertEqual(de("We found 12 problems in your app"), "Wir haben 12 Probleme in deiner App gefunden")
        self.assertEqual(de("Fix it for $50"), "Für $50 beheben")

    def test_browser_dictionary_is_up_to_date(self):
        from scanner import i18n_de
        with tempfile.TemporaryDirectory() as tmp:
            fresh = i18n_de.write_js(Path(tmp) / "i18n-de.js").read_text()
        self.assertEqual((ROOT / "static" / "i18n-de.js").read_text(), fresh, "run: python -m scanner.i18n_de")


class PageRouteTests(unittest.TestCase):
    def test_landing_scanner_and_old_links(self):
        from fastapi.testclient import TestClient
        import api
        client = TestClient(api.app)
        self.assertIn("Apply for waitlist", client.get("/").text)
        self.assertIn('"appUrl": ""', client.get("/site-config.js").text)
        self.assertIn('id="drop"', client.get("/app").text)
        old = client.get("/?report=abc123", follow_redirects=False)
        self.assertEqual((old.status_code, old.headers["location"]), (307, "/app?report=abc123"))

    def test_waitlist(self):
        from fastapi.testclient import TestClient
        import api
        client = TestClient(api.app)
        with tempfile.TemporaryDirectory() as tmp, unittest.mock.patch.object(billing, "DATA_DIR", Path(tmp)):
            ok = client.post("/waitlist", data={"name": "Sam", "email": "Sam@Company.io", "package": "improve"})
            self.assertEqual(ok.status_code, 200)
            self.assertEqual(client.post("/waitlist", data={"name": "Sam", "email": "nope"}).status_code, 400)
            client.post("/waitlist", data={"name": "bot", "email": "a@b.co", "website": "spam"})  # ignored
            rows = (Path(tmp) / "waitlist.jsonl").read_text().splitlines()
            self.assertEqual(len(rows), 1)
            self.assertEqual(json.loads(rows[0])["email"], "sam@company.io")


class FalseAlarmReportTests(unittest.TestCase):
    """The example reports: probable false alarms are listed on their own and not counted."""

    def test_false_alarms_are_not_counted(self):
        from scanner.report import render_text
        for name in ("sample-report.json", "sample-report.de.json"):
            report = json.loads((ROOT / "static" / name).read_text(encoding="utf-8"))["report"]
            with self.subTest(name):
                self.assertTrue(report["false_alarms"])
                self.assertEqual(report["counts"], {k: len(v) for k, v in report["issues"].items()})
                self.assertTrue(all(i["ai_review"]["verdict"] == "likely_false_alarm" for i in report["false_alarms"]))
                self.assertEqual(sum(report["ai_review"]["scanner_counts"].values()),
                                 sum(report["counts"].values()) + len(report["false_alarms"]))
                self.assertIn("PROBABLY FALSE ALARMS", render_text(report))

    def test_html_report_in_english_and_german(self):
        from scanner.report_html import render_html
        report = json.loads((ROOT / "static" / "sample-report.json").read_text(encoding="utf-8"))["report"]
        en, de = render_html(report, "en"), render_html(report, "de")
        self.assertIn('<html lang="en">', en)
        self.assertIn("Probably false alarms", en)
        self.assertIn('<html lang="de">', de)
        for german in ("Sicherheitsbericht", "Wahrscheinlich Fehlalarme", "Über diesen Scan", "Kritisch"):
            self.assertIn(german, de)
        self.assertNotIn("<script", en + de)


@unittest.skipUnless(os.environ.get("RUN_GOLDEN") and (ROOT / "samples" / "fdroid.apk").is_file(),
                     "set RUN_GOLDEN=1 (needs samples/fdroid.apk)")
class GoldenApkTest(unittest.TestCase):
    def test_fdroid_counts_and_rules(self):
        from scanner.pipeline import run_pipeline

        report = run_pipeline(ROOT / "samples" / "fdroid.apk", use_ai=False)
        self.assertEqual(report["counts"], GOLDEN_FDROID_COUNTS, json.dumps(report["counts"]))
        rules = {i["rule_id"] for group in report["issues"].values() for i in group}
        self.assertEqual(rules, GOLDEN_FDROID_RULES)
        again = run_pipeline(ROOT / "samples" / "fdroid.apk", use_ai=False)
        self.assertEqual(report["result_fingerprint"], again["result_fingerprint"])


if __name__ == "__main__":
    unittest.main()
