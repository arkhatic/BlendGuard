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
    ("winreg_use",     r"(?i)winreg\.(?:SetValueEx|CreateKey\w*|DeleteKey\w*|DeleteValue|SaveKey)|reg\s+add\b", "X", "winreg", "Windows registry write"),

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


_SOLO_INFO = {"net", "subprocess"}  # capabilities that need a partner to be suspicious


def _verdict(findings, has_script, driver=False):
    cats = {f["cat"] for f in findings if f["class"] in ("S", "O")}
    crit = any(f["class"] == "X" for f in findings)
    if driver:
        return DANGEROUS if (crit or cats) else CLEAN
    hard = cats - _SOLO_INFO
    n = len(cats)
    if crit or len(hard) >= 2 or (len(hard) >= 1 and n >= 2):
        return DANGEROUS
    if len(hard) >= 1 or n >= 2:
        return SUSPICIOUS
    if n == 1 or has_script or any(f["class"] == "C" for f in findings):
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


# --------------------------------------------------------------------------
# .blend container handling (v0.3)
# --------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# v0.4: per-finding explanations + a report split into neutral inventory and
# real security concerns. Keyed by category. Context-class signals deliberately
# do NOT appear here as concerns; they are normal in legitimate scripts.
# ---------------------------------------------------------------------------
RULE_INFO = {
    # critical / high: rarely or never legitimate in a .blend script
    "exfil_discord": {"sev": "critical", "label": "Discord webhook",
        "what": "Posts data to a Discord webhook URL.",
        "danger": "Webhooks are a standard data-exfiltration channel; a scene file has no reason to call Discord's message API.",
        "legit": "Effectively never in a .blend script."},
    "exfil_tg": {"sev": "critical", "label": "Telegram bot API",
        "what": "Talks to the Telegram bot API.",
        "danger": "Common exfiltration / C2 channel.",
        "legit": "Effectively never in a .blend script."},
    "loader_cf": {"sev": "critical", "label": "Cloudflare Workers loader",
        "what": "Fetches from a *.workers.dev URL.",
        "danger": "Workers domains are a frequent malware staging/loader host in current campaigns.",
        "legit": "Rare. A few tools legitimately use Workers, so treat as a strong hint, not proof."},
    "persist": {"sev": "critical", "label": "Persistence mechanism",
        "what": "Touches an OS autostart location (Run key, Startup folder, launchd, cron).",
        "danger": "Establishing persistence is malware behaviour, not something a 3D file does.",
        "legit": "None in this context."},
    "stealer": {"sev": "critical", "label": "Credential/wallet path",
        "what": "References a browser, credential, or wallet store (leveldb, Login Data, wallet.dat, Firefox profiles).",
        "danger": "These are exactly the files infostealers read.",
        "legit": "None in a .blend script."},
    "winreg": {"sev": "high", "label": "Windows registry write",
        "what": "Writes to the Windows registry (SetValueEx / CreateKey / reg add).",
        "danger": "A scene file writing the registry is never legitimate; used for persistence or config tampering.",
        "legit": "Reading a key can be benign, but this rule targets writes specifically."},
    "decoded": {"sev": "critical", "label": "Obfuscated payload",
        "what": "An encoded blob in the file decodes to code that itself contains dangerous calls.",
        "danger": "Layered encoding exists to hide a payload from inspection; a blob that unpacks to exec/os/network is a strong malware sign.",
        "legit": "Almost none."},

    # review: real capabilities, often legitimate. Surfaced with context, not condemned.
    "dynexec": {"sev": "review", "label": "Dynamic code execution (exec/eval)",
        "what": "Runs code assembled at runtime via exec() or eval().",
        "danger": "The usual way an obfuscated or fetched payload is executed.",
        "legit": "Some advanced tools metaprogram or evaluate user expressions. Uncommon but not malicious by itself."},
    "dynimport": {"sev": "review", "label": "Dynamic __import__()",
        "what": "Imports a module whose name is computed at runtime.",
        "danger": "Used to hide which module is in play (e.g. os, socket) from a scanner.",
        "legit": "Rare in normal add-ons; common in obfuscators and plugin loaders."},
    "import_call": {"sev": "review", "label": "Call on an __import__ result",
        "what": "Imports a module by name and immediately calls into it.",
        "danger": "A compact way to call os/subprocess without writing the names plainly.",
        "legit": "Uncommon outside obfuscation."},
    "getattr_import": {"sev": "review", "label": "getattr against __import__",
        "what": "Reaches into a dynamically imported module via getattr.",
        "danger": "Indirection used to evade name-based detection.",
        "legit": "Rare."},
    "os_exec": {"sev": "review", "label": "Executes via os",
        "what": "Runs a program via os.system / os.popen / os.startfile.",
        "danger": "Direct command execution; dangerous if the command is built from untrusted input.",
        "legit": "Occasionally used to open a file or launch a helper. Look at what it runs."},
    "subprocess": {"sev": "review", "label": "Spawns a subprocess",
        "what": "Runs an external program.",
        "danger": "Command execution; concerning when the command is attacker-controlled or fed by network/obfuscation.",
        "legit": "Legitimate and common: invoking ffmpeg, renderers, exporters, compilers. Pipeline tools do this constantly. Read WHAT it runs before worrying."},
    "shell": {"sev": "review", "label": "Shell invocation",
        "what": "Invokes a shell (powershell, cmd, /bin/sh).",
        "danger": "Shell one-liners are a common malware execution method.",
        "legit": "Rare in add-ons; usually worth a look."},
    "psenc": {"sev": "review", "label": "PowerShell encoded command",
        "what": "Uses -EncodedCommand or FromBase64String.",
        "danger": "Encoded PowerShell exists almost exclusively to hide a command.",
        "legit": "None expected in a .blend."},
    "net": {"sev": "review", "label": "Network connection",
        "what": "Opens a network connection (urlopen / requests / socket).",
        "danger": "Needed to exfiltrate data or pull a second stage; matters most alongside credential/file access or obfuscation.",
        "legit": "Very common and legitimate: update checks, fetching assets, license validation, API calls. A URL whose response you decode is normal. Network access alone is not malware."},
    "ctypes": {"sev": "review", "label": "Native code via ctypes",
        "what": "Calls into native libraries through ctypes.",
        "danger": "Lets Python run arbitrary native code or shellcode.",
        "legit": "Some hardware or OS-integration add-ons use ctypes. Uncommon but real."},
    "deserial": {"sev": "review", "label": "marshal/pickle.loads",
        "what": "Deserializes objects with pickle or marshal.",
        "danger": "Deserializing untrusted data can execute code.",
        "legit": "Some tools cache state with pickle. A risky pattern, not always malicious."},
    "drop": {"sev": "review", "label": "Writes an executable/script file",
        "what": "Writes a file whose name is a script or executable (.py, .pth, .bat, .ps1, .exe...).",
        "danger": "Dropping a program to disk is a stager move; a .pth into site-packages auto-runs on the next Python start.",
        "legit": "Uncommon. Some code generators emit .py files. Worth a look, not proof of malice."},
    "obf_chr": {"sev": "review", "label": "Code built from chr()",
        "what": "Assembles strings from chr() arithmetic or character lists.",
        "danger": "A way to spell a forbidden token without writing it.",
        "legit": "Almost none; occasionally minification."},
    "obf_rev": {"sev": "review", "label": "Reversed string/bytes",
        "what": "Reverses a string or byte sequence at runtime.",
        "danger": "Used to hide a literal from inspection.",
        "legit": "Rare."},
    "obf_entropy": {"sev": "review", "label": "High-entropy blob",
        "what": "Contains a long, high-randomness encoded-looking string.",
        "danger": "Often a packed payload that could not be decoded.",
        "legit": "Occasionally embedded binary data (an icon, a font). Context-dependent."},

    # informational: normal in legitimate scripts. Never shown as concerns.
    "url": {"sev": "info", "label": "Hardcoded URL", "what": "Contains a URL.",
        "danger": "None by itself.", "legit": "Docs links, update checks, asset and API endpoints. Completely normal."},
    "ip": {"sev": "info", "label": "Hardcoded IP", "what": "Contains an IP address.",
        "danger": "None by itself.", "legit": "Normal for self-hosted services or LAN tools."},
    "appdata": {"sev": "info", "label": "App-data path", "what": "References an app-data folder.",
        "danger": "None by itself.", "legit": "Add-ons store config and caches there routinely."},
    "fileio": {"sev": "info", "label": "Writes a file", "what": "Writes or deletes a file.",
        "danger": "None by itself.", "legit": "Every exporter writes files. Only writing an executable (see drop) is treated as a concern."},
    "decode": {"sev": "info", "label": "Runtime decoding", "what": "Decodes base64/hex at runtime.",
        "danger": "None by itself.", "legit": "Decoding an embedded icon, parsing an API response, unpacking data. Only matters if what is decoded is itself code, which the engine checks separately."},
    "temp": {"sev": "info", "label": "Temp file", "what": "Uses a temporary file.",
        "danger": "None.", "legit": "Ubiquitous and harmless."},
    "dimport": {"sev": "info", "label": "Imports a sensitive module", "what": "Imports ctypes/winreg/marshal/socket.",
        "danger": "None by itself; the import only matters if the module is actually used dangerously.", "legit": "Plenty of tools import socket or ctypes for benign reasons."},
    "osl": {"sev": "info", "label": "OSL script node", "what": "Contains an OSL shader script node.",
        "danger": "Low; OSL is far more constrained than Python.", "legit": "Normal in advanced shading setups."},
}


def _rank(sev):
    return {"critical": 0, "high": 1, "review": 2, "info": 3}.get(sev, 4)


def concerns(scan_result):
    """Return only the security-relevant findings (strong/critical), de-duplicated
    by category and enriched with plain-English explanations. Context-class
    signals are intentionally excluded; they are normal in legitimate scripts."""
    out, seen = [], set()
    for it in scan_result.get("items", []):
        for f in it.get("findings", []):
            if f.get("class") in ("S", "O", "X") and f.get("cat") not in seen:
                seen.add(f.get("cat"))
                info = RULE_INFO.get(f.get("cat"), {})
                out.append({
                    "cat": f.get("cat"),
                    "severity": info.get("sev", "review"),
                    "label": info.get("label", f.get("desc", "")),
                    "what": info.get("what", ""),
                    "danger": info.get("danger", ""),
                    "legit": info.get("legit", ""),
                    "where": it.get("name", ""),
                })
    out.sort(key=lambda c: _rank(c["severity"]))
    return out


def will_run(items):
    """Neutral inventory of what would auto-run on open. Not a threat assessment."""
    kind = lambda k: sum(1 for i in items if i.get("kind") == k)
    return {"scripts": kind("text"), "drivers": kind("driver"), "osl": kind("osl"),
            "registered": sum(1 for i in items if i.get("registered"))}
