"""Step 2: map the decompiled app - its own code, third-party SDKs, and network endpoints."""

from __future__ import annotations

import re
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

from scanner.ingest import UnpackedApk

# Package prefix -> (friendly name, what it's for). Longer prefixes win over shorter ones.
KNOWN_LIBRARIES: dict[str, tuple[str, str]] = {
    # Core Android / language runtime
    "androidx": ("AndroidX", "core"),
    "android.support": ("Android Support Library", "core"),
    "kotlin": ("Kotlin standard library", "core"),
    "kotlinx.coroutines": ("Kotlin Coroutines", "core"),
    "kotlinx.serialization": ("Kotlin Serialization", "data parsing"),
    "com.google.android.material": ("Material Components", "ui"),
    # Google / Firebase
    "com.google.firebase": ("Firebase", "backend"),
    "com.google.firebase.analytics": ("Firebase Analytics", "analytics"),
    "com.google.firebase.crashlytics": ("Firebase Crashlytics", "crash reporting"),
    "com.google.firebase.messaging": ("Firebase Cloud Messaging", "push notifications"),
    "com.google.firebase.auth": ("Firebase Authentication", "login"),
    "com.google.firebase.firestore": ("Cloud Firestore", "database"),
    "com.google.firebase.database": ("Firebase Realtime Database", "database"),
    "com.google.firebase.storage": ("Firebase Storage", "file storage"),
    "com.google.firebase.remoteconfig": ("Firebase Remote Config", "backend"),
    "com.google.android.gms": ("Google Play Services", "platform"),
    "com.google.android.gms.ads": ("Google AdMob", "ads"),
    "com.google.android.gms.maps": ("Google Maps", "maps"),
    "com.google.android.gms.location": ("Google Location Services", "location"),
    "com.google.android.gms.auth": ("Google Sign-In", "login"),
    "com.google.android.play.core": ("Google Play Core", "platform"),
    "com.android.billingclient": ("Google Play Billing", "payments"),
    "com.google.gson": ("Gson", "data parsing"),
    "com.google.protobuf": ("Protocol Buffers", "data parsing"),
    "com.google.zxing": ("ZXing", "barcode scanning"),
    "com.journeyapps.barcodescanner": ("ZXing Android Embedded", "barcode scanning"),
    "com.google.mlkit": ("ML Kit", "machine learning"),
    "com.google.android.exoplayer2": ("ExoPlayer", "media"),
    "com.google.common": ("Guava", "utilities"),
    # Cross-platform frameworks
    "com.facebook.react": ("React Native", "framework"),
    "io.flutter": ("Flutter", "framework"),
    "com.unity3d.player": ("Unity", "framework"),
    "org.apache.cordova": ("Cordova", "framework"),
    "com.getcapacitor": ("Capacitor", "framework"),
    # Networking
    "okhttp3": ("OkHttp", "networking"),
    "com.squareup.okhttp": ("OkHttp 2", "networking"),
    "okio": ("Okio", "networking"),
    "retrofit2": ("Retrofit", "networking"),
    "com.android.volley": ("Volley", "networking"),
    "io.ktor": ("Ktor", "networking"),
    "io.grpc": ("gRPC", "networking"),
    "org.apache.http": ("Apache HttpClient", "networking"),
    # Data / images / UI / utilities
    "com.squareup.moshi": ("Moshi", "data parsing"),
    "com.fasterxml.jackson": ("Jackson", "data parsing"),
    "com.squareup.picasso": ("Picasso", "images"),
    "com.bumptech.glide": ("Glide", "images"),
    "coil": ("Coil", "images"),
    "com.airbnb.lottie": ("Lottie", "ui"),
    "io.reactivex": ("RxJava", "async"),
    "dagger": ("Dagger / Hilt", "framework"),
    "org.greenrobot.eventbus": ("EventBus", "utilities"),
    "org.apache.commons": ("Apache Commons", "utilities"),
    "org.jsoup": ("jsoup", "html parsing"),
    "org.bouncycastle": ("Bouncy Castle", "cryptography"),
    "io.realm": ("Realm", "database"),
    "net.sqlcipher": ("SQLCipher", "database"),
    "org.slf4j": ("SLF4J", "logging"),
    "ch.qos.logback": ("Logback", "logging"),
    "timber.log": ("Timber", "logging"),
    "com.squareup.leakcanary": ("LeakCanary", "debugging"),
    "org.webrtc": ("WebRTC", "media"),
    "javax.jmdns": ("JmDNS", "local network discovery"),
    "info.guardianproject.netcipher": ("NetCipher", "networking"),
    # Analytics / crash reporting / marketing
    "io.sentry": ("Sentry", "crash reporting"),
    "com.bugsnag": ("Bugsnag", "crash reporting"),
    "com.crashlytics": ("Crashlytics (legacy)", "crash reporting"),
    "org.acra": ("ACRA", "crash reporting"),
    "com.microsoft.appcenter": ("App Center", "analytics"),
    "com.mixpanel": ("Mixpanel", "analytics"),
    "com.amplitude": ("Amplitude", "analytics"),
    "com.segment": ("Segment", "analytics"),
    "com.yandex.metrica": ("AppMetrica", "analytics"),
    "com.appsflyer": ("AppsFlyer", "ad attribution"),
    "com.adjust.sdk": ("Adjust", "ad attribution"),
    "com.braze": ("Braze", "marketing"),
    "com.onesignal": ("OneSignal", "push notifications"),
    # Social
    "com.facebook": ("Facebook SDK", "social"),
    "com.facebook.ads": ("Meta Audience Network", "ads"),
    "com.facebook.appevents": ("Facebook App Events", "analytics"),
    "com.facebook.login": ("Facebook Login", "login"),
    "com.twitter.sdk": ("Twitter SDK", "social"),
    "com.tencent": ("Tencent SDK", "social"),
    # Ads
    "com.applovin": ("AppLovin", "ads"),
    "com.ironsource": ("ironSource", "ads"),
    "com.unity3d.ads": ("Unity Ads", "ads"),
    "com.chartboost": ("Chartboost", "ads"),
    "com.vungle": ("Vungle", "ads"),
    "com.mopub": ("MoPub", "ads"),
    "com.startapp": ("Start.io", "ads"),
    "com.inmobi": ("InMobi", "ads"),
    "com.bytedance.sdk": ("Pangle (TikTok ads)", "ads"),
    # Payments / cloud
    "com.stripe": ("Stripe", "payments"),
    "com.paypal": ("PayPal", "payments"),
    "com.razorpay": ("Razorpay", "payments"),
    "com.revenuecat": ("RevenueCat", "payments"),
    "com.amazonaws": ("AWS SDK", "cloud"),
    "com.huawei.hms": ("Huawei Mobile Services", "platform"),
}

URL_RE = re.compile(r"""\b(?:https?|wss?|ftp)://[A-Za-z0-9\-._~%\[\]]+[^\s"'<>\\`{}|^]*""")
URL_TRAILING_JUNK = ".,;:)]'"

# Hosts that show up in code as XML namespaces, licence headers, etc. - never real endpoints.
NOISE_HOSTS = {
    "schemas.android.com", "www.w3.org", "w3.org", "xmlpull.org", "www.xmlpull.org",
    "www.apache.org", "apache.org", "ns.adobe.com", "json-schema.org", "purl.org",
    "xml.org", "www.xml.org", "java.sun.com", "xml.apache.org", "schemas.microsoft.com",
    "example.com", "www.example.com", "example.org", "www.example.org", "jsoup.org",
}

TEXT_RESOURCE_SUFFIXES = {".xml", ".json", ".properties", ".txt", ".js", ".html", ".cfg", ".conf"}
MAX_RESOURCE_BYTES = 1_000_000
MAX_LOCATIONS_PER_URL = 5


def build_map(unpacked: UnpackedApk) -> dict:
    sources = unpacked.sources_dir
    # The REA engine only decompiles app code, so it supplies the whole-APK inventory itself.
    packages = unpacked.package_counts or _java_file_counts_by_package(sources)

    libraries = _detect_libraries(packages)
    library_prefixes = [lib["package"] for lib in libraries]
    app_prefixes = _app_prefixes(unpacked.package_name, packages)

    def is_app_code(pkg: str) -> bool:
        if app_prefixes:
            return any(_under(pkg, p) for p in app_prefixes)
        # No package match (e.g. heavily obfuscated app): treat everything that
        # isn't a known library as the app's own code.
        return not any(_under(pkg, p) for p in KNOWN_LIBRARIES)

    app_files = sum(n for pkg, n in packages.items() if is_app_code(pkg))
    unrecognized = Counter()
    for pkg, n in packages.items():
        if not is_app_code(pkg) and not any(_under(pkg, p) for p in KNOWN_LIBRARIES):
            unrecognized[".".join(pkg.split(".")[:2]) or "(default package)"] += n

    return {
        "package_name": unpacked.package_name,
        "permissions": unpacked.permissions,
        "app_code": {
            "packages": app_prefixes or ["(no match - using all non-library code)"],
            "source_dirs": [str(sources / p.replace(".", "/")) for p in app_prefixes] or [str(sources)],
            "java_files": app_files,
        },
        "libraries": libraries,
        "library_versions": _library_versions(unpacked.resources_dir),
        "unrecognized_code": [
            {"package": pkg, "java_files": n} for pkg, n in unrecognized.most_common(15)
        ],
        "endpoints": _find_endpoints(unpacked, is_app_code),
        "stats": {
            "total_java_files": sum(packages.values()),
            "library_prefixes_found": len(library_prefixes),
        },
    }


def _java_file_counts_by_package(sources: Path) -> Counter:
    counts: Counter = Counter()
    for f in sources.rglob("*.java"):
        counts[".".join(f.parent.relative_to(sources).parts)] += 1
    return counts


def _under(pkg: str, prefix: str) -> bool:
    return pkg == prefix or pkg.startswith(prefix + ".")


def _library_for(pkg: str) -> str | None:
    """Most specific known library prefix covering this package, so com.google.firebase.auth
    counts as Firebase Authentication rather than generic Firebase."""
    matches = [p for p in KNOWN_LIBRARIES if _under(pkg, p)]
    return max(matches, key=len) if matches else None


def _detect_libraries(packages: Counter) -> list[dict]:
    files_per_lib: Counter = Counter()
    for pkg, n in packages.items():
        if lib := _library_for(pkg):
            files_per_lib[lib] += n
    found = [
        {"name": KNOWN_LIBRARIES[p][0], "category": KNOWN_LIBRARIES[p][1], "package": p, "java_files": n}
        for p, n in files_per_lib.items()
    ]
    return sorted(found, key=lambda lib: (lib["category"] == "core", -lib["java_files"]))


def _app_prefixes(package_name: str | None, packages: Counter) -> list[str]:
    if not package_name:
        return []
    exists = lambda prefix: any(_under(pkg, prefix) for pkg in packages)

    # Prefer the two-segment "company" prefix (org.fdroid covers org.fdroid.fdroid,
    # org.fdroid.index, ...) unless it would swallow third-party libraries (e.g. com.google).
    parts = package_name.split(".")
    company = ".".join(parts[:2])
    if len(parts) > 2 and exists(company) and not any(_under(lib, company) for lib in KNOWN_LIBRARIES):
        return [company]
    if exists(package_name):
        return [package_name]
    return []


def _library_versions(resources: Path) -> list[dict]:
    """Gradle bundles META-INF/<group>_<artifact>.version files - free, exact version info."""
    meta = resources / "META-INF"
    versions = []
    for f in sorted(meta.glob("*.version")) if meta.is_dir() else []:
        try:
            version = f.read_text(errors="ignore").strip()
        except OSError:
            continue
        group, _, artifact = f.stem.partition("_")
        versions.append({"library": f"{group}:{artifact}" if artifact else group, "version": version})
    return versions


def _find_endpoints(unpacked: UnpackedApk, is_app_code) -> list[dict]:
    found: dict[str, dict] = {}

    def scan(path: Path, rel: str, in_app: bool) -> None:
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            return
        if "://" not in text:
            return
        for m in URL_RE.finditer(text):
            url = m.group(0).rstrip(URL_TRAILING_JUNK)
            try:
                parts = urlsplit(url)
                host = (parts.hostname or "").lower()
            except ValueError:
                continue
            if not host or host in NOISE_HOSTS or ("." not in host and host != "localhost"):
                continue
            entry = found.setdefault(url, {
                "url": url,
                "host": host,
                # .onion (Tor) traffic is encrypted end-to-end even over plain http.
                "insecure": parts.scheme in ("http", "ws", "ftp")
                and host not in ("localhost", "127.0.0.1")
                and not host.endswith(".onion"),
                "in_app_code": False,
                "locations": [],
            })
            entry["in_app_code"] |= in_app
            if len(entry["locations"]) < MAX_LOCATIONS_PER_URL:
                entry["locations"].append({"file": rel, "line": text.count("\n", 0, m.start()) + 1})

    sources = unpacked.sources_dir
    for f in sources.rglob("*.java"):
        pkg = ".".join(f.parent.relative_to(sources).parts)
        scan(f, str(f.relative_to(sources.parent)), is_app_code(pkg))

    # Base URLs and API keys often live in strings.xml or bundled assets rather than code.
    res = unpacked.resources_dir
    for sub in ("res/values", "assets"):
        base = res / sub
        if not base.is_dir():
            continue
        for f in base.rglob("*"):
            if f.suffix in TEXT_RESOURCE_SUFFIXES and f.is_file() and f.stat().st_size <= MAX_RESOURCE_BYTES:
                scan(f, str(f.relative_to(res.parent)), True)

    return sorted(found.values(), key=lambda e: (not e["in_app_code"], not e["insecure"], e["host"], e["url"]))


if __name__ == "__main__":
    import argparse
    import json

    from scanner.ingest import load_unpacked, unpack_apk

    parser = argparse.ArgumentParser(description="Map an APK: permissions, endpoints, libraries.")
    parser.add_argument("target", help="path to an .apk, or a folder from an earlier run (skips jadx)")
    args = parser.parse_args()

    target = Path(args.target)
    unpacked = load_unpacked(target) if target.is_dir() else unpack_apk(target)
    app_map = build_map(unpacked)

    app_endpoints = [e for e in app_map["endpoints"] if e["in_app_code"]]
    print(json.dumps({**app_map, "endpoints": app_endpoints}, indent=2))
    print(
        f"\n# decompiled folder: {unpacked.work_dir}"
        f"\n# {len(app_endpoints)} endpoints in app code shown"
        f" ({len(app_map['endpoints']) - len(app_endpoints)} more found inside libraries)"
    )
