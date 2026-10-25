"""Deterministic structure measurements for the Code improvement tier.

Semgrep locates every Java method and constructor; the size of each is then measured here, so the same
code always gives the same list. Thresholds are SonarSource's defaults for Java:
  java:S138  methods should not have too many lines   (more than 75)
  java:S107  methods should not have too many parameters (more than 7)
Restructuring is only suggested, never applied: without compiling and running the app's tests there is
no way to prove a refactor keeps the app working.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from scanner.scan import ScanError, _run

MAX_METHOD_LINES = 75
MAX_PARAMETERS = 7
METHOD_RULES = Path(__file__).resolve().parent.parent / "rules" / "structure.yml"
STANDARDS = {
    "long-method": {"source": "SonarSource java:S138", "limit": f"more than {MAX_METHOD_LINES} lines",
                    "title": "A method is too long to follow easily",
                    "why": "Long methods are hard to read and test, so bugs hide in them and changes break things."},
    "too-many-parameters": {"source": "SonarSource java:S107", "limit": f"more than {MAX_PARAMETERS} parameters",
                            "title": "A method takes too many parameters",
                            "why": "Calls are easy to get wrong (arguments in the wrong order) and the method is doing too much."},
}


def measure(root: Path, java_files: list[str]) -> list[dict]:
    """Methods over the limits, sorted by file and line."""
    if not java_files:
        return []
    cmd = ["semgrep", "scan", "--json", "--quiet", "--metrics=off", "--disable-version-check", "--no-git-ignore",
           "--timeout=20", "--config", str(METHOD_RULES)] + [str(root / f) for f in java_files]
    result = _run(cmd)
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        raise ScanError(f"semgrep exit {result.returncode}: {(result.stderr or result.stdout)[-500:]}") from None

    texts: dict[str, str] = {}
    seen: set[tuple[str, int]] = set()
    issues = []
    for r in sorted(data.get("results", []), key=lambda r: (r["path"], r["start"]["offset"])):
        rel = Path(r["path"]).resolve().relative_to(root.resolve()).as_posix()
        if (rel, r["start"]["offset"]) in seen:
            continue
        seen.add((rel, r["start"]["offset"]))
        text = texts.setdefault(rel, (root / rel).read_text(errors="replace"))
        method = _describe(text[r["start"]["offset"]:r["end"]["offset"]])
        if method is None:
            continue
        lines = r["end"]["line"] - r["start"]["line"] + 1
        base = {"file": rel, "line": r["start"]["line"], "end_line": r["end"]["line"], "method": method["name"],
                "lines": lines, "parameters": method["parameters"]}
        if lines > MAX_METHOD_LINES:
            issues.append({**base, "rule_id": "long-method", **STANDARDS["long-method"]})
        if method["parameters"] > MAX_PARAMETERS:
            issues.append({**base, "rule_id": "too-many-parameters", **STANDARDS["too-many-parameters"]})
    return issues


def _describe(code: str) -> dict | None:
    """Name and parameter count from the declaration text (up to the body's opening brace)."""
    depth, header_end = 0, None
    for i, ch in enumerate(code):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "{" and depth == 0:
            header_end = i
            break
    if header_end is None:
        return None
    header = re.sub(r"@\w+(\([^)]*\))?", " ", code[:header_end])  # drop annotations
    match = re.search(r"([A-Za-z_$][\w$]*)\s*\(", header)
    if not match:
        return None
    start = match.end()
    depth, params, angle = 1, [], 0
    current = ""
    for ch in header[start:]:
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                break
        if ch == "<":
            angle += 1
        elif ch == ">":
            angle -= 1
        if ch == "," and depth == 1 and angle == 0:
            params.append(current)
            current = ""
        else:
            current += ch
    if current.strip():
        params.append(current)
    return {"name": match.group(1), "parameters": len([p for p in params if p.strip()])}


# ---------------------------------------------------------------- interface check for fixes

_MODIFIERS = r"(?:public|protected|private|static|final|synchronized|abstract|native|strictfp|default|transient|volatile)"


def api_signatures(text: str) -> dict[str, dict]:
    """Non-private methods and constructors of every named class, as {class: {"members": set, "constructors": n}}.

    A light brace scanner (strings and comments skipped). Methods of anonymous classes, lambdas and private
    members are left out: changing those cannot break code in other files."""
    code = _strip_strings_and_comments(text)
    classes: dict[str, dict] = {}
    stack: list[tuple[str, str | None]] = []  # (kind, class name)
    last = 0
    for i, ch in enumerate(code):
        if ch == "{":
            before = code[last:i]
            kind, name = _block_kind(before)
            if kind == "method" and stack and stack[-1][0] == "class":
                owner = stack[-1][1]
                entry = classes.setdefault(owner, {"members": set(), "constructors": 0})
                header = re.sub(r"@\w+(\([^)]*\))?", " ", before).strip()
                described = _describe(header + " {")
                if described and described["name"] == owner:
                    entry["constructors"] += 1
                if not re.search(r"\bprivate\b", header):
                    entry["members"].add(_signature_key(header))
            if kind == "class":
                classes.setdefault(name, {"members": set(), "constructors": 0})
            stack.append((kind, name))
            last = i + 1
        elif ch == "}":
            if stack:
                stack.pop()
            last = i + 1
        elif ch == ";":
            last = i + 1
    return classes


def breaking_changes(before: str, after: str) -> list[str]:
    """What a fix changed in the file's interface that could stop other files from compiling."""
    old, new = api_signatures(before), api_signatures(after)
    problems = []
    for cls, info in old.items():
        now = new.get(cls)
        if now is None:
            problems.append(f"class {cls} was removed or renamed")
            continue
        for member in sorted(info["members"] - now["members"]):
            problems.append(f"{cls}: '{member}' was removed or its signature changed")
        if info["constructors"] == 0 and now["constructors"] > 0:
            problems.append(f"{cls}: a constructor was added, which removes the default no-argument constructor")
    return problems


def _block_kind(before: str) -> tuple[str, str | None]:
    tail = before.strip()
    m = re.search(r"\b(?:class|interface|enum|record)\s+([A-Za-z_$][\w$]*)[^{;()]*(?:\([^)]*\))?[^{;()]*$", tail)
    if m and not re.search(r"\bnew\s", tail[max(0, m.start() - 5):m.start()]):
        return "class", m.group(1)
    if re.search(r"\bnew\s+[\w.$<>\[\], ?]+\s*\([^)]*\)\s*$", tail):
        return "anonymous", None
    if re.search(r"\)\s*(?:throws\s+[\w.$,\s]+)?$", tail) and not re.search(
            r"(?:^|[\s;{}])(?:if|for|while|switch|catch|synchronized|try)\s*\(", tail[-300:]):
        return "method", None
    return "block", None


def _signature_key(header: str) -> str:
    """Visibility + return type + name + parameter types (parameter names don't matter to callers)."""
    header = re.sub(r"\s+", " ", header).strip()
    m = re.search(r"([A-Za-z_$][\w$]*)\s*\((.*)\)\s*(throws .*)?$", header)
    if not m:
        return header
    prefix = re.sub(rf"\b(?:final|synchronized|native|strictfp|abstract|default)\b\s*", "", header[:m.start()]).strip()
    types = []
    depth, current = 0, ""
    for ch in m.group(2) + ",":
        depth += ch in "<("
        depth -= ch in ">)"
        if ch == "," and depth == 0:
            param = re.sub(r"\bfinal\b", "", current).strip()
            if param:
                types.append(re.sub(r"\s*[A-Za-z_$][\w$]*\s*(\[\s*\])*$", "", param).strip() or param)
            current = ""
        else:
            current += ch
    return f"{prefix} {m.group(1)}({', '.join(types)})".strip()


def _strip_strings_and_comments(text: str) -> str:
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j == -1 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j == -1 else j + 2
        elif c in "\"'":
            j = i + 1
            while j < n and text[j] != c:
                j += 2 if text[j] == "\\" else 1
            out.append(c + c)
            i = j + 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


# ---------------------------------------------------------------- Kotlin

_KT_FUN = re.compile(r"\bfun\s+(?:<[^>]*>\s*)?(?:([\w.<>?, ]+)\.)?([A-Za-z_][\w]*)\s*\(")
_KT_CLASS = re.compile(r"\b(?:class|interface|object)\s+([A-Za-z_][\w]*)")


def kotlin_api(text: str) -> dict:
    """Non-private functions (top level and class members) and constructors of a Kotlin file.

    Functions inside anonymous objects (object : X { ... }), lambdas and other functions are left out."""
    code = _strip_strings_and_comments(text)
    blocks = _kotlin_blocks(code)
    members, ctors, classes = set(), {}, set()
    for m in _KT_FUN.finditer(code):
        parent = _innermost(blocks, m.start())
        if parent is not None and parent["kind"] != "class":
            continue
        line_start = code.rfind("\n", 0, m.start()) + 1
        modifiers = code[line_start:m.start()]
        if re.search(r"\bprivate\b", modifiers):
            continue
        params, after = _paren_contents(code, m.end() - 1)
        ret = re.match(r"\s*:\s*([\w.<>?, ]+?)\s*(?:[={]|$|\n)", code[after:after + 200])
        owner = parent["name"] if parent else ""
        receiver = f"{m.group(1)}." if m.group(1) else ""
        members.add(f"{owner}::{receiver}{m.group(2)}({', '.join(_kotlin_types(params))})"
                    f"{': ' + ret.group(1).strip() if ret else ''}")
    for m in _KT_CLASS.finditer(code):
        if re.search(r"\bprivate\b", code[code.rfind("\n", 0, m.start()) + 1:m.start()]):
            continue
        name = m.group(1)
        classes.add(name)
        rest = code[m.end():m.end() + 400]
        primary = re.match(r"\s*(?:<[^>]*>)?\s*(?:(?:public|internal|protected)\s+)?(?:constructor\s*)?\(", rest)
        sigs = set()
        if primary and not code[max(0, m.start() - 10):m.start()].strip().endswith("object"):
            params, _ = _paren_contents(code, m.end() + primary.end() - 1)
            sigs.add(f"{name}({', '.join(_kotlin_types(params))})")
        ctors[name] = sigs
    for m in re.finditer(r"\bconstructor\s*\(", code):
        parent = _innermost(blocks, m.start())
        if parent and parent["kind"] == "class" and not re.search(
                r"\bprivate\b", code[code.rfind("\n", 0, m.start()) + 1:m.start()]):
            params, _ = _paren_contents(code, m.end() - 1)
            ctors.setdefault(parent["name"], set()).add(f"{parent['name']}({', '.join(_kotlin_types(params))})")
    return {"members": members, "constructors": ctors, "classes": classes}


def kotlin_breaking_changes(before: str, after: str) -> list[str]:
    old, new = kotlin_api(before), kotlin_api(after)
    problems = [f"class {c} was removed or renamed" for c in sorted(old["classes"] - new["classes"])]
    problems += [f"'{m}' was removed or its signature changed" for m in sorted(old["members"] - new["members"])]
    for cls, sigs in old["constructors"].items():
        now = new["constructors"].get(cls, set())
        for sig in sorted(sigs - now):
            problems.append(f"constructor {sig} was removed or changed")
        if not sigs and now:
            problems.append(f"{cls}: a constructor was added, which removes the default no-argument constructor")
    return problems


def measure_kotlin(root: Path, kotlin_files: list[str]) -> list[dict]:
    """Kotlin functions with a block body over the same SonarSource limits as Java."""
    issues = []
    for rel in kotlin_files:
        text = (root / rel).read_text(errors="replace")
        code = _strip_strings_and_comments_keep_lines(text)
        blocks = _kotlin_blocks(code)
        for m in _KT_FUN.finditer(code):
            params, after = _paren_contents(code, m.end() - 1)
            body = next((b for b in blocks if b["kind"] == "function" and b["start"] >= after
                         and code[after:b["start"]].count("\n") <= 3 and "=" not in code[after:b["start"]]), None)
            if body is None:
                continue  # expression body, or abstract
            start_line = code.count("\n", 0, m.start()) + 1
            end_line = code.count("\n", 0, body["end"]) + 1
            base = {"file": rel, "line": start_line, "end_line": end_line, "method": m.group(2),
                    "lines": end_line - start_line + 1, "parameters": len(_kotlin_types(params))}
            if base["lines"] > MAX_METHOD_LINES:
                issues.append({**base, "rule_id": "long-method", **STANDARDS["long-method"]})
            if base["parameters"] > MAX_PARAMETERS:
                issues.append({**base, "rule_id": "too-many-parameters", **STANDARDS["too-many-parameters"]})
    return issues


def _kotlin_blocks(code: str) -> list[dict]:
    blocks, stack, last = [], [], 0
    for i, ch in enumerate(code):
        if ch == "{":
            before = code[last:i]
            tail = before.strip()
            if re.search(r"\bobject\s*:", tail) or re.search(r"\bobject\s*$", tail):
                kind, name = "anonymous", None
            elif (m := re.search(r"\b(?:class|interface|object)\s+([A-Za-z_]\w*)[^{]*$", tail)):
                kind, name = "class", m.group(1)
            elif re.search(r"\bfun\b[^{]*$", tail):
                kind, name = "function", None
            else:
                kind, name = "block", None
            stack.append({"kind": kind, "name": name, "start": i})
            last = i + 1
        elif ch == "}":
            if stack:
                b = stack.pop()
                b["end"] = i
                blocks.append(b)
            last = i + 1
        elif ch in ";\n" and not stack:
            last = i + 1
        elif ch == ";":
            last = i + 1
    return blocks


def _innermost(blocks: list[dict], offset: int) -> dict | None:
    inside = [b for b in blocks if b["start"] < offset < b["end"]]
    return max(inside, key=lambda b: b["start"]) if inside else None


def _paren_contents(code: str, open_index: int) -> tuple[str, int]:
    depth = 0
    for i in range(open_index, len(code)):
        if code[i] == "(":
            depth += 1
        elif code[i] == ")":
            depth -= 1
            if depth == 0:
                return code[open_index + 1:i], i + 1
    return code[open_index + 1:], len(code)


def _kotlin_types(params: str) -> list[str]:
    """'a: Int, b: List<String> = emptyList()' -> ['Int', 'List<String>'] (names and defaults don't matter)."""
    out, depth, current = [], 0, ""
    for ch in params + ",":
        depth += ch in "<([{"
        depth -= ch in ">)]}"
        if ch == "," and depth == 0:
            p = re.sub(r"@\w+(\([^)]*\))?", " ", current).strip()
            p = re.sub(r"^(?:(?:private|public|internal|protected|override|open)\s+)*(?:val|var)\s+", "", p)
            if p:
                typ = p.split(":", 1)[1] if ":" in p else p
                typ = typ.split("=", 1)[0]
                vararg = "vararg " if p.startswith("vararg ") else ""
                out.append(vararg + re.sub(r"\s+", "", typ))
            current = ""
        else:
            current += ch
    return out


def _strip_strings_and_comments_keep_lines(text: str) -> str:
    """Like _strip_strings_and_comments, but keeps newlines so line numbers still match."""
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j == -1 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j == -1 else j + 2
            out.append("\n" * text.count("\n", i, j))
            i = j
        elif c in "\"'":
            j = i + 1
            while j < n and text[j] != c:
                j += 2 if text[j] == "\\" else 1
            out.append(c + "\n" * text.count("\n", i, j) + c)
            i = j + 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


# ---------------------------------------------------------------- JavaScript / TypeScript

_JS_EXPORT_DECL = re.compile(r"\bexport\s+(?:default\s+)?(?:declare\s+)?(?:async\s+)?"
                             r"(?:function\*?|class|const|let|var|interface|type|enum|abstract\s+class)\s+([A-Za-z_$][\w$]*)")
_JS_EXPORT_LIST = re.compile(r"\bexport\s+(?:type\s+)?\{([^}]*)\}")
_JS_COMMONJS = re.compile(r"\b(?:module\.)?exports\.([A-Za-z_$][\w$]*)\s*=")


def js_exports(text: str) -> set[str]:
    """Names other files can import from this file (ES modules and CommonJS)."""
    code = _strip_strings_and_comments(text)
    names = set(_JS_EXPORT_DECL.findall(code)) | set(_JS_COMMONJS.findall(code))
    for group in _JS_EXPORT_LIST.findall(code):
        for item in group.split(","):
            item = item.strip()
            if item:
                names.add(re.split(r"\s+as\s+", item)[-1].strip())
    if re.search(r"\bexport\s+default\b", code) or re.search(r"\bmodule\.exports\s*=", code):
        names.add("default")
    return names


def js_breaking_changes(before: str, after: str) -> list[str]:
    """Exports a fix removed: other files that import them would break."""
    return [f"export '{name}' was removed or renamed" for name in sorted(js_exports(before) - js_exports(after))]
