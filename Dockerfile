# VibeGuard, local edition: everything runs on the user's own computer.
# Fast engine (jadx) only - the deep engine (REA) needs ~6 GB of RAM. Website scans use the direct fetch.
#
#   docker build -t vibeguard .
#   docker run --rm -p 127.0.0.1:8000:8000 -p 127.0.0.1:8100:8100 -v vibeguard-data:/data \
#              -e OPENROUTER_API_KEY=sk-or-... vibeguard
#
# Tool versions and checksums are pinned so every copy gives the same results as the reference setup.

# ---- 1. compile the APK signature checker (needs a JDK; the final image only needs a JRE)
FROM eclipse-temurin:21-jdk AS apksig
WORKDIR /build
COPY tools/apksig/ ./
RUN javac -cp apksig-9.3.3.jar -d classes ApkSigCheck.java

# ---- 2. the app
FROM python:3.14-slim
ARG TARGETARCH
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    JAVA_HOME=/opt/java/openjdk \
    PATH=/opt/java/openjdk/bin:/opt/jadx/bin:$PATH

COPY --from=eclipse-temurin:21-jre /opt/java/openjdk /opt/java/openjdk
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl unzip git \
 && rm -rf /var/lib/apt/lists/*

# jadx 1.5.6 (decompiler)
RUN curl -fsSL -o /tmp/jadx.zip https://github.com/skylot/jadx/releases/download/v1.5.6/jadx-1.5.6.zip \
 && echo "545ea2be9c242511bc145755cf4bda2485ade42966e096f8b4d3da2a230e8974  /tmp/jadx.zip" | sha256sum -c - \
 && unzip -q /tmp/jadx.zip -d /opt/jadx && rm /tmp/jadx.zip && chmod +x /opt/jadx/bin/jadx

# gitleaks 8.30.1 (secret scanner)
RUN case "$TARGETARCH" in \
      amd64) A=x64;   S=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb ;; \
      arm64) A=arm64; S=e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080 ;; \
      *) echo "unsupported architecture: $TARGETARCH" && exit 1 ;; \
    esac \
 && curl -fsSL -o /tmp/gitleaks.tgz "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_${A}.tar.gz" \
 && echo "$S  /tmp/gitleaks.tgz" | sha256sum -c - \
 && tar -xzf /tmp/gitleaks.tgz -C /usr/local/bin gitleaks && rm /tmp/gitleaks.tgz

# semgrep 1.182.0 (code scanner), in its own environment so its dependencies can't clash with the app's
# Only the semgrep command is linked onto PATH: the venv's own python/pip must not shadow the app's.
RUN python -m venv /opt/semgrep && /opt/semgrep/bin/pip install --no-cache-dir semgrep==1.182.0 \
 && ln -s /opt/semgrep/bin/semgrep /usr/local/bin/semgrep

WORKDIR /app
COPY requirements.lock .
RUN pip install --no-cache-dir -r requirements.lock

COPY api.py ./
COPY scanner/ scanner/
COPY rules/ rules/
COPY static/ static/
COPY tools/apksig/ tools/apksig/
COPY --from=apksig /build/classes tools/apksig/classes
COPY samples/web-demo-src.zip samples/taskpal-src.zip samples/
COPY samples/web-demo/ samples/web-demo/
COPY THIRD_PARTY_NOTICES.md ./
COPY docker/entrypoint.sh /entrypoint.sh

RUN useradd --create-home --uid 10001 vibeguard && mkdir -p /data && chown -R vibeguard /data /app \
 && chmod +x /entrypoint.sh
USER vibeguard

# Local-edition defaults: on-screen sign-in codes, demo payments, fast engine, everything kept in /data.
ENV DATA_DIR=/data VERIFY_SECRET_FILE=/data/.verify-secret \
    APK_ENGINE=jadx EMAIL_MODE=demo PAYMENTS_MODE=demo \
    WEB_ALLOW_LOCAL=true JAVA_OPTS="-Xmx1536m" DEMO_SITE=1
VOLUME /data
EXPOSE 8000 8100
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD curl -fsS http://127.0.0.1:8000/health >/dev/null || exit 1
ENTRYPOINT ["/entrypoint.sh"]
