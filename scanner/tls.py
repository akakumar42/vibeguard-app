"""One TLS setup for every outgoing HTTPS request (Supabase, website scans).

Python from python.org on macOS ships without root certificates, so the default context fails every
HTTPS request ("unable to get local issuer certificate"). truststore uses the operating system's own
certificate store instead (Keychain on macOS), which is also what the OpenAI client uses.
"""

from __future__ import annotations

import ssl

try:
    import truststore

    CONTEXT = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
except ImportError:  # pragma: no cover - fall back to Python's own store (fine on Linux servers)
    CONTEXT = ssl.create_default_context()
