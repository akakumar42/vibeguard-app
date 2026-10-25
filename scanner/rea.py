"""Adapter for REA (Reverse Engineer Anything, https://github.com/morluto/rea).

REA runs as an MCP server over stdio. Keeping one server process open per scan means the APK is
loaded into its JADX engine once and every later class or method request reuses it - the one-shot
CLI reloads the APK for every call (~6s each).

Setup (see README): Node 24, `npm install` in tools/rea, and the pinned jadx-headless-mcp jar.
Settings: REA_BIN, REA_NODE_BIN (folder with a supported `node`), REA_JADX_MCP_JAR.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import threading
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent
REA_DIR = PROJECT / "tools" / "rea"
DEFAULT_BIN = REA_DIR / "node_modules" / ".bin" / "rea"
DEFAULT_JAR = REA_DIR / "jar" / "jadx-headless-mcp-0.7.1-all.jar"
CALL_TIMEOUT = 600


class ReaError(Exception):
    def __init__(self, message: str, reason: str = ""):
        super().__init__(message)
        self.reason = reason  # "out_of_memory" when the Node process ran out of heap


def _node_dir() -> str | None:
    """REA supports Node 22/24/26+, not 25. Prefer an explicit setting, then Homebrew's node@24."""
    if os.environ.get("REA_NODE_BIN"):
        return os.environ["REA_NODE_BIN"]
    for candidate in ("/opt/homebrew/opt/node@24/bin", "/usr/local/opt/node@24/bin"):
        if Path(candidate, "node").is_file():
            return candidate
    return None


def rea_available() -> bool:
    return Path(os.environ.get("REA_BIN", DEFAULT_BIN)).is_file() and Path(
        os.environ.get("REA_JADX_MCP_JAR", DEFAULT_JAR)).is_file()


def rea_version() -> str:
    pkg = REA_DIR / "node_modules" / "rea-agents" / "package.json"
    try:
        return json.loads(pkg.read_text())["version"]
    except (OSError, ValueError, KeyError):
        return "unknown"


class ReaSession:
    """One REA MCP server process. Use as a context manager; calls are serialized."""

    def __init__(self, heap_mb: int | None = None, call_timeout: float | None = None) -> None:
        self._timeout = call_timeout or CALL_TIMEOUT
        self._timed_out = False
        rea_bin = os.environ.get("REA_BIN", str(DEFAULT_BIN))
        jar = os.environ.get("REA_JADX_MCP_JAR", str(DEFAULT_JAR))
        if not Path(rea_bin).is_file():
            raise ReaError(f"REA is not installed ({rea_bin}); run `npm install` in tools/rea")
        if not Path(jar).is_file():
            raise ReaError(f"JADX engine jar for REA is missing ({jar})")
        env = {**os.environ, "REA_JADX_MCP_JAR": jar}
        # Node's default heap (~2 GB) runs out on big web bundles (a Next.js app plus its source maps).
        heap = heap_mb or int(os.environ.get("REA_NODE_HEAP_MB", 4096))
        env["NODE_OPTIONS"] = f"{env.get('NODE_OPTIONS', '')} --max-old-space-size={heap}".strip()
        node_dir = _node_dir()
        if node_dir:
            env["PATH"] = f"{node_dir}{os.pathsep}{env.get('PATH', '')}"
        elif not shutil.which("node"):
            raise ReaError("Node.js is required for REA")

        self._proc = subprocess.Popen(
            [rea_bin, "--mcp"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=env, text=True, encoding="utf-8", bufsize=1)
        self._stderr: list[str] = []
        self._stderr_head: list[str] = []  # a crash report's first lines say why; its tail is just the stack
        threading.Thread(target=self._drain_stderr, daemon=True).start()
        self._next_id = 0
        self._lock = threading.Lock()
        self._request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                     "clientInfo": {"name": "vibeguard", "version": "0.4"}})
        self._send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def __enter__(self) -> "ReaSession":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        if self._proc.poll() is None:
            try:
                self._proc.stdin.close()
                self._proc.wait(timeout=20)
            except (OSError, subprocess.TimeoutExpired):
                self._proc.kill()

    def _drain_stderr(self) -> None:
        for line in self._proc.stderr:
            line = line.rstrip()
            if len(self._stderr_head) < 20:
                self._stderr_head.append(line)
            self._stderr = (self._stderr + [line])[-50:]

    def crash_reason(self) -> str:
        """A plain reason for a crashed REA process (for example running out of memory)."""
        text = "\n".join(self._stderr_head + self._stderr)
        if "heap out of memory" in text or "Reached heap limit" in text or "Allocation failed" in text:
            return "out_of_memory"
        return ""

    def _exited(self, method: str) -> "ReaError":
        if self._timed_out:
            return ReaError(f"REA took longer than {self._timeout:.0f}s for {method}", reason="timeout")
        if self.crash_reason() == "out_of_memory":
            return ReaError(f"REA ran out of memory during {method}", reason="out_of_memory")
        fatal = next((l for l in self._stderr_head + self._stderr if "FATAL" in l or "Error:" in l), "")
        return ReaError(f"REA server exited during {method}: {fatal or ' | '.join(self._stderr[-3:])}")

    def _send(self, msg: dict) -> None:
        try:
            self._proc.stdin.write(json.dumps(msg) + "\n")
            self._proc.stdin.flush()
        except OSError as e:
            raise self._exited("a request") from e

    def _request(self, method: str, params: dict) -> dict:
        with self._lock:
            self._next_id += 1
            rid = self._next_id
            self._send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
            timer = threading.Timer(self._timeout, self._kill_for_timeout)
            timer.start()
            try:
                while True:
                    line = self._proc.stdout.readline()
                    if not line:
                        raise self._exited(method)
                    try:
                        msg = json.loads(line)
                    except ValueError:
                        continue  # not protocol output
                    if msg.get("id") != rid:
                        continue  # notifications / logs
                    if "error" in msg:
                        raise ReaError(f"{method}: {msg['error'].get('message', msg['error'])}")
                    return msg["result"]
            finally:
                timer.cancel()

    def _kill_for_timeout(self) -> None:
        self._timed_out = True
        self._proc.kill()

    def list_tools(self) -> list[dict]:
        return self._request("tools/list", {})["tools"]

    def call(self, tool: str, arguments: dict) -> dict:
        """Call a REA tool and return its Evidence (structured content, or the JSON text reply)."""
        result = self._request("tools/call", {"name": tool, "arguments": arguments})
        if result.get("structuredContent") is not None:
            data = result["structuredContent"]
        else:
            text = "".join(c.get("text", "") for c in result.get("content", []) if c.get("type") == "text")
            try:
                data = json.loads(text)
            except ValueError:
                data = {"text": text}
        if result.get("isError"):
            raise ReaError(f"{tool}: {json.dumps(data)[:500]}")
        return data
