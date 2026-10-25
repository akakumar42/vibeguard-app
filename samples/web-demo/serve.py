"""Serve the TaskPal demo site on http://127.0.0.1:8100 - a test target for the web scanner.

Like many quickly-built sites it sends no security headers, sets a weak cookie, and exposes its
.env file and .git folder. Those two are stored as exposed/env and exposed/git-HEAD so they don't
interfere with this project's own .gitignore and git repo.

usage: python samples/web-demo/serve.py [port]
"""

import sys
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ALIASES = {"/.env": "/exposed/env", "/.git/HEAD": "/exposed/git-HEAD"}


class Handler(SimpleHTTPRequestHandler):
    server_version = "Apache/2.4.29"  # deliberately reveals an old server version
    sys_version = ""

    def translate_path(self, path):
        return super().translate_path(ALIASES.get(path.split("?", 1)[0], path))

    def end_headers(self):
        if self.path.split("?", 1)[0] in ("/", "/index.html"):
            self.send_header("Set-Cookie", "session=demo-session-123; Path=/")
            self.send_header("X-Powered-By", "Express")
        super().end_headers()

    def log_message(self, *args):
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8100
    print(f"TaskPal demo on http://127.0.0.1:{port}")
    ThreadingHTTPServer(("127.0.0.1", port), partial(Handler, directory=str(ROOT))).serve_forever()
