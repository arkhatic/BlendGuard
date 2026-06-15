# SPDX-License-Identifier: GPL-3.0-or-later
# BlendGuard detection engine, v0.3.
#
# Pure-Python, NO bpy import. Static analysis only: it never executes scanned code.
#
# v0.2 hardening: capability-based rules, normalization, multi-codec decoder,
#   entropy, AST confirmation, driver mode, campaign IOCs, safety caps.
# v0.3 adds: .blend file-block parsing to isolate text datablocks for the disk
#   scan (with a whole-file fallback), and OSL script-node detection.
#
# Severity: CLEAN < INFO < SUSPICIOUS < DANGEROUS  (+ INCOMPLETE for unreadable input)

import re
import ast
import math
import struct
import base64
import zlib
import gzip
import codecs

CLEAN = "CLEAN"
INFO = "INFO"
SUSPICIOUS = "SUSPICIOUS"
DANGEROUS = "DANGEROUS"
INCOMPLETE = "INCOMPLETE"

_ORDER = {CLEAN: 0, INFO: 1, SUSPICIOUS: 2, DANGEROUS: 3}

MAX_INPUT = 2_000_000
MAX_DEPTH = 3
MAX_DECODE_BYTES = 4_000_000
MAX_CANDIDATES = 48


def worst(a, b):
    a2 = SUSPICIOUS if a == INCOMPLETE else a
    b2 = SUSPICIOUS if b == INCOMPLETE else b
    return a if _ORDER.get(a2, 2) >= _ORDER.get(b2, 2) else b


_RULES = [
    ("url",            r"https?://[^\s'\"]+", "C", "url", "Hardcoded URL"),
    ("ip",             r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "C", "ip", "Hardcoded IP address"),
    ("appdata",        r"(?i)%APPDATA%|%LOCALAPPDATA%|AppData[\\/]+Roaming", "C", "appdata", "App-data path"),
    ("file_write",     r"\bopen\s*\([^)]*['\"](?:w|wb|a|ab)['\"]|\.write_(?:bytes|text)\s*\(|\bos\.(?:remove|unlink|write|open)\s*\(|\bio\.open\s*\(|shutil\.(?:rmtree|move|copy\w*)\b", "C", "fileio", "Filesystem write or delete"),
    ("script_drop",    r"\bopen\s*\(\s*['\"][^'\"\n]{0,200}\.(?:py|pyw|pyc|pth|bat|cmd|ps1|psm1|vbs|scr|sh|js|exe|dll)['\"]\s*,\s*['\"](?:w|wb|a|ab|x)|['\"][^'\"\n]{0,200}\.(?:py|pyw|pyc|pyo|pth|bat|cmd|ps1|psm1|vbs|vbe|scr|sh|js|exe|dll|command|desktop)['\"][\s\S]{0,300}?(?:\.write_(?:bytes|text)\s*\(|\bopen\s*\([^)]*['\"](?:w|wb|a|ab|x))", "S", "drop", "Writes an executable or script file (dropper)"),
    ("decode_call",    r"base64\.(?:b64decode|urlsafe_b64decode|standard_b64decode|b85decode|a85decode|b32decode)\s*\(|bytes\.fromhex\s*\(|binascii\.unhexlify\s*\(|codecs\.decode\s*\([^)]*(?:hex|rot_?13|base64|zlib|uu)", "C", "decode", "Runtime decoding"),
    ("tempfile",       r"\btempfile\.(?:NamedTemporaryFile|mkstemp|gettempdir)\b", "C", "temp", "Temp-file use"),
    ("autorun_hook",   r"bpy\.app\.handlers|@persistent\b|bpy\.app\.timers\.register", "C", "autorun", "Auto-run handler or timer"),
    ("danger_import",  r"\b(?:import|from)\s+(?:ctypes|winreg|marshal|socket)\b", "C", "dimport", "Imports a sensitive module"),
    ("osl_script",     r"ShaderNodeScript|\.osl\b|#\s*include\s*[<\"]stdosl", "C", "osl", "OSL script node"),

    ("exec_eval",      r"\b(?:exec|eval)\s*\(", "S", "dynexec", "Dynamic code execution"),
    ("dyn_import",     r"__import__\s*\(", "S", "dynimport", "Dynamic __import__()"),
    ("import_then_call", r"__import__\s*\([^)]*\)\s*\.\s*\w+", "S", "import_call", "Calls a method on an __import__ result"),
    ("getattr_import", r"getattr\s*\(\s*__import__", "S", "getattr_import", "getattr against __import__"),
    ("os_exec",        r"\bos\.(?:system|popen|startfile)\s*\(|\bos\.exec[lv]\w*\s*\(", "S", "os_exec", "Executes via os"),
    ("subprocess_call", r"\bsubprocess\.(?:Popen|run|call|check_output|check_call|getoutput)\s*\(", "S", "subprocess", "Spawns a subprocess"),
    ("shell",          r"(?i)\b(?:powershell|cmd\.exe|/bin/sh|bash\s+-c)\b", "S", "shell", "Shell invocation"),
    ("ps_enc",         r"(?i)-enc(?:odedcommand)?\b|FromBase64String", "S", "psenc", "PowerShell encoded command"),
    ("net_send",       r"\burlopen\s*\(|\brequests\.(?:get|post|put|head)\s*\(|\bsocket\.socket\s*\(|\.sendall\s*\(|http\.client\.HTTPS?Connection|\.connect\s*\(\s*\(", "S", "net", "Network connection"),
    ("ctypes_use",     r"\bctypes\.(?:windll|cdll|CDLL|WinDLL|cast|memmove|create_string_buffer)\b", "S", "ctypes", "Native code via ctypes"),
    ("deserialize",    r"\b(?:marshal|pickle)\.loads?\s*\(", "S", "deserial", "Deserializes code or objects"),
    ("winreg_use",     r"(?i)winreg\.(?:OpenKey|SetValueEx|CreateKey)|reg\s+add\b", "S", "winreg", "Windows registry write"),

    ("obf_chr",        r"\.join\s*\([^)]{0,40}chr\s*\(|chr\s*\(\s*\w+\s*\)\s*for\s+\w+\s+in|(?:chr\s*\(\s*\d+\s*\)\s*\+?\s*){3,}", "O", "obf_chr", "Builds code from chr()"),
    ("obf_rev",        r"\[::-1\]", "O", "obf_rev", "Reversed string or bytes"),

    ("exfil_discord",  r"(?i)discord(?:app)?\.com/api/webhooks", "X", "exfil_discord", "Discord webhook exfiltration"),
    ("exfil_telegram", r"(?i)api\.telegram\.org/bot", "X", "exfil_tg", "Telegram bot exfiltration"),
    ("loader_workers", r"(?i)https?://[a-z0-9.-]+\.workers\.dev\b", "X", "loader_cf", "Cloudflare Workers loader"),
    ("persistence",    r"(?i)schtasks|CurrentVersion\\+Run|Startup\\+|launchctl\b|crontab\b", "X", "persist", "Persistence mechanism"),
    ("stealer_paths",  r"(?i)Local Storage[\\/]+leveldb|cookies\.sqlite|Login\s?Data|wallet\.dat|seed\s?phrase|\\Discord\\|Opera Software|Mozilla[\\/]+Firefox[\\/]+Profiles", "X", "stealer", "Credential or wallet theft path"),
]

_COMPILED = [(i, re.compile(rx), cls, cat, desc) for (i, rx, cls, cat, desc) in _RULES]
_SCRIPT_HINT = re.compile(r"\bimport\s+\w+|\bdef\s+\w+\s*\(|\bclass\s+\w+|bpy\.")
_STRLIT = re.compile(r"'([^'\\]{16,})'|\"([^\"\\]{16,})\"")
_B64ISH = re.compile(r"^[A-Za-z0-9+/=_-]+$")
_HEXISH = re.compile(r"^[0-9A-Fa-f]+$")


def _ctx(code, pos, span=70):
    a = max(0, pos - 12); b = min(len(code), pos + span)
    return ("…" if a > 0 else "") + code[a:b].replace("\n", " ").replace("\r", " ").strip() + ("…" if b < len(code) else "")


def _entropy(s):
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _normalize(code):
    out = code
    for _ in range(12):
        new = re.sub(r"(['\"])(.*?)\1\s*\+\s*(['\"])(.*?)\3",
                     lambda m: m.group(1) + m.group(2) + m.group(4) + m.group(1), out)
        if new == out:
            break
        out = new

    def _esc(m):
        try:
            return codecs.decode(m.group(0).encode("latin-1"), "unicode_escape")
        except Exception:
            return m.group(0)
    out = re.sub(r"(?:\\x[0-9A-Fa-f]{2}|\\[0-7]{1,3}|\\u[0-9A-Fa-f]{4})+", _esc, out)
    return out


def _match_rules(text):
    found = []
    for rid, rx, cls, cat, desc in _COMPILED:
        m = rx.search(text)
        if m:
            found.append({"rule": rid, "class": cls, "cat": cat, "desc": desc, "snippet": _ctx(text, m.start())})
    return found


def _string_candidates(code):
    cands = []
    for m in _STRLIT.finditer(code):
        s = m.group(1) or m.group(2)
        if len(s) >= 16:
            cands.append(s)
        if len(cands) >= MAX_CANDIDATES:
            break
    return cands


def _try_decode(s):
    attempts = []
    for fn in (base64.b64decode, base64.urlsafe_b64decode, base64.b32decode, base64.b85decode, base64.a85decode):
        try:
            attempts.append(fn(s))
        except Exception:
            pass
    if _HEXISH.match(s) and len(s) % 2 == 0:
        try:
            attempts.append(bytes.fromhex(s))
        except Exception:
            pass
    try:
        attempts.append(codecs.encode(s, "rot_13").encode("latin-1", "ignore"))
    except Exception:
        pass
    for b in list(attempts):
        for dec in (zlib.decompress, gzip.decompress):
            try:
                r = dec(b)
                if len(r) <= MAX_DECODE_BYTES:
                    attempts.append(r)
            except Exception:
                pass
    out = []
    for b in attempts:
        if not b or len(b) > MAX_DECODE_BYTES:
            continue
        try:
            t = b.decode("utf-8")
        except Exception:
            try:
                t = b.decode("latin-1")
            except Exception:
                continue
        if len(t) >= 8 and sum((c.isprintable() or c in "\n\t") for c in t) > 0.85 * len(t):
            out.append(t)
    return out


def _ast_findings(code):
    try:
        tree = ast.parse(code)
    except Exception:
        return []
    out = []

    def dotted(node):
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = dotted(node.value)
            return (base + "." + node.attr) if base else node.attr
        return ""

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = dotted(node.func)
            if name in ("exec", "eval"):
                out.append(("dynexec", "Dynamic code execution (ast)"))
            elif name == "__import__":
                out.append(("dynimport", "Dynamic __import__() (ast)"))
            elif name in ("os.system", "os.popen", "os.startfile"):
                out.append(("os_exec", "Executes via os (ast)"))
            elif name.startswith("subprocess."):
                out.append(("subprocess", "Spawns a subprocess (ast)"))
            elif name == "getattr" and node.args and isinstance(node.args[0], ast.Call) and dotted(node.args[0].func) == "__import__":
                out.append(("getattr_import", "getattr against __import__ (ast)"))
    seen = set(); ded = []
    for cat, desc in out:
        if cat not in seen:
            seen.add(cat); ded.append({"rule": "ast_" + cat, "class": "S", "cat": cat, "desc": desc, "snippet": ""})
    return ded


def analyze_code(code, source="script", _depth=0, _budget=None):
    if not code:
        return {"findings": [], "critical": False, "source": source}
    if len(code) > MAX_INPUT:
        code = code[:MAX_INPUT]
    if _budget is None:
        _budget = [MAX_DECODE_BYTES]

    norm = _normalize(code)
    findings = _match_rules(code)
    if norm != code:
        seen = {f["rule"] for f in findings}
        for f in _match_rules(norm):
            if f["rule"] not in seen:
                findings.append(f)
    findings += _ast_findings(code)

    for s in _string_candidates(code):
        if (_B64ISH.match(s) or _HEXISH.match(s)) and len(s) >= 40 and _entropy(s) > 4.3:
            findings.append({"rule": "entropy_blob", "class": "O", "cat": "obf_entropy", "desc": "High-entropy encoded blob", "snippet": s[:60] + "…"})
            break

    if _depth < MAX_DEPTH:
        for s in _string_candidates(code):
            if _budget[0] <= 0:
                break
            for dec in _try_decode(s):
                _budget[0] -= len(dec)
                sub = analyze_code(dec, source, _depth + 1, _budget)
                strong = [f for f in sub["findings"] if f["class"] in ("S", "O", "X")]
                if strong:
                    findings.append({"rule": "decoded_payload", "class": "X", "cat": "decoded", "desc": "Obfuscated blob decodes to suspicious code", "snippet": dec[:60] + "…"})
                    for f in strong[:4]:
                        g = dict(f); g["rule"] = "decoded:" + f["rule"]; g["desc"] = "[decoded] " + f["desc"]; findings.append(g)
                    break

    critical = any(f["class"] == "X" for f in findings)
    return {"findings": findings, "critical": critical, "source": source}


def _verdict(findings, has_script, driver=False):
    cats = {f["cat"] for f in findings if f["class"] in ("S", "O")}
    crit = any(f["class"] == "X" for f in findings)
    if driver:
        return DANGEROUS if (crit or cats) else CLEAN
    if crit or len(cats) >= 2:
        return DANGEROUS
    if len(cats) == 1:
        return SUSPICIOUS
    if has_script or any(f["class"] == "C" for f in findings):
        return INFO
    return CLEAN


def severity_of(code, driver=False):
    a = analyze_code(code)
    return _verdict(a["findings"], bool(_SCRIPT_HINT.search(code)), driver)


def scan_items(items):
    overall = CLEAN
    results = []
    for it in items:
        body = it.get("body", "") or ""
        driver = it.get("kind") == "driver"
        a = analyze_code(body)
        sev = _verdict(a["findings"], bool(_SCRIPT_HINT.search(body)), driver)
        if it.get("registered") and sev == CLEAN:
            sev = INFO
        overall = worst(overall, sev)
        row = dict(it); row.update({"severity": sev, "findings": a["findings"], "critical": a["critical"]})
        results.append(row)
    return {"severity": overall, "items": results}


# .blend container handling (v0.3)
def _read_blend_bytes(path, max_bytes=128 * 1024 * 1024):
    with open(path, "rb") as fh:
        raw = fh.read(max_bytes)
    if raw[:2] == b"\x1f\x8b":
        try:
            raw = gzip.decompress(raw)
        except Exception:
            pass
    elif raw[:4] == b"\x28\xb5\x2f\xfd":
        for mod in ("zstandard", "zstd"):
            try:
                m = __import__(mod)
                raw = m.ZstdDecompressor().decompress(raw) if mod == "zstandard" else m.decompress(raw)
                break
            except Exception:
                continue
    return raw


def _iter_blocks(raw):
    """Yield (code, data) for each .blend file-block. Best-effort, defensive."""
    if raw[:7] != b"BLENDER":
        return
    ptr = 4 if raw[7:8] == b"_" else 8
    endian = "<" if raw[8:9] == b"v" else ">"
    pos, n = 12, len(raw)
    hdr = 4 + 4 + ptr + 4 + 4
    while pos + hdr <= n:
        code = raw[pos:pos + 4]
        try:
            size = struct.unpack(endian + "i", raw[pos + 4:pos + 8])[0]
        except Exception:
            break
        start = pos + hdr
        if size < 0 or start + size > n:
            break
        yield code, raw[start:start + size]
        if code[:4] == b"ENDB":
            break
        pos = start + size


def _printable_runs(b, minlen=6):
    out, cur = [], bytearray()
    for byte in b:
        if 32 <= byte < 127 or byte in (9, 10, 13):
            cur.append(byte)
        else:
            if len(cur) >= minlen:
                out.append(cur.decode("latin-1"))
            cur = bytearray()
    if len(cur) >= minlen:
        out.append(cur.decode("latin-1"))
    return out


def _extract_blend_text(raw):
    """Isolate text from TX/DATA blocks; fall back to whole-file printable scan."""
    chunks, total, blocks = [], 0, 0
    try:
        for code, data in _iter_blocks(raw):
            blocks += 1
            if code[:2] == b"TX" or code[:4] == b"DATA":
                for r in _printable_runs(data, 6):
                    chunks.append(r); total += len(r)
            if total > MAX_INPUT:
                break
    except Exception:
        pass
    text = "\n".join(chunks)
    if len(text) < 32:   # parser found little structure -> scan the whole file
        text = "\n".join(_printable_runs(raw, 6))[:MAX_INPUT]
    return text


def scan_blend_file(path):
    try:
        raw = _read_blend_bytes(path)
    except Exception as exc:
        return {"path": path, "severity": INCOMPLETE, "note": "Could not read file: %s" % exc, "findings": [], "critical": False, "has_script": False}
    if raw[:7] != b"BLENDER":
        return {"path": path, "severity": INCOMPLETE,
                "note": "File is compressed (zstd) or not a standard .blend; static text extraction unavailable. Open with Auto-Run OFF and use the in-session inspector.",
                "findings": [], "critical": False, "has_script": False}
    text = _extract_blend_text(raw)
    a = analyze_code(text, "blend-static")
    has_script = bool(_SCRIPT_HINT.search(text))
    sev = _verdict(a["findings"], has_script)
    note = "" if has_script else "No embedded Python detected in static text."
    return {"path": path, "severity": sev, "note": note, "findings": a["findings"], "critical": a["critical"], "has_script": has_script}
