# BlendGuard rule reference

BlendGuard reports two things: a neutral inventory of **what would auto-run** when you open a file (scripts, drivers, handlers, OSL nodes), and a short list of **security concerns**. Only the items below marked Critical, High, or Review ever appear as concerns. Informational signals are listed for completeness but are never flagged on their own, because they are normal in legitimate scripts.

A file only reaches SUSPICIOUS or DANGEROUS when a real capability is present, and network or subprocess alone is treated as Informational-to-Review (it needs a second signal, such as download *and* execute, to escalate).

## Critical: rarely or never legitimate in a .blend

### Cloudflare Workers loader

- **What it is:** Fetches from a *.workers.dev URL.
- **When it is dangerous:** Workers domains are a frequent malware staging/loader host in current campaigns.
- **When it is legitimate:** Rare. A few tools legitimately use Workers, so treat as a strong hint, not proof.

### Credential/wallet path

- **What it is:** References a browser, credential, or wallet store (leveldb, Login Data, wallet.dat, Firefox profiles).
- **When it is dangerous:** These are exactly the files infostealers read.
- **When it is legitimate:** None in a .blend script.

### Discord webhook

- **What it is:** Posts data to a Discord webhook URL.
- **When it is dangerous:** Webhooks are a standard data-exfiltration channel; a scene file has no reason to call Discord's message API.
- **When it is legitimate:** Effectively never in a .blend script.

### Obfuscated payload

- **What it is:** An encoded blob in the file decodes to code that itself contains dangerous calls.
- **When it is dangerous:** Layered encoding exists to hide a payload from inspection; a blob that unpacks to exec/os/network is a strong malware sign.
- **When it is legitimate:** Almost none.

### Persistence mechanism

- **What it is:** Touches an OS autostart location (Run key, Startup folder, launchd, cron).
- **When it is dangerous:** Establishing persistence is malware behaviour, not something a 3D file does.
- **When it is legitimate:** None in this context.

### Telegram bot API

- **What it is:** Talks to the Telegram bot API.
- **When it is dangerous:** Common exfiltration / C2 channel.
- **When it is legitimate:** Effectively never in a .blend script.

## High: almost never legitimate

### Windows registry write

- **What it is:** Writes to the Windows registry (SetValueEx / CreateKey / reg add).
- **When it is dangerous:** A scene file writing the registry is never legitimate; used for persistence or config tampering.
- **When it is legitimate:** Reading a key can be benign, but this rule targets writes specifically.

## Review: real capabilities, often legitimate; surfaced with context

### Call on an __import__ result

- **What it is:** Imports a module by name and immediately calls into it.
- **When it is dangerous:** A compact way to call os/subprocess without writing the names plainly.
- **When it is legitimate:** Uncommon outside obfuscation.

### Code built from chr()

- **What it is:** Assembles strings from chr() arithmetic or character lists.
- **When it is dangerous:** A way to spell a forbidden token without writing it.
- **When it is legitimate:** Almost none; occasionally minification.

### Dynamic __import__()

- **What it is:** Imports a module whose name is computed at runtime.
- **When it is dangerous:** Used to hide which module is in play (e.g. os, socket) from a scanner.
- **When it is legitimate:** Rare in normal add-ons; common in obfuscators and plugin loaders.

### Dynamic code execution (exec/eval)

- **What it is:** Runs code assembled at runtime via exec() or eval().
- **When it is dangerous:** The usual way an obfuscated or fetched payload is executed.
- **When it is legitimate:** Some advanced tools metaprogram or evaluate user expressions. Uncommon but not malicious by itself.

### Executes via os

- **What it is:** Runs a program via os.system / os.popen / os.startfile.
- **When it is dangerous:** Direct command execution; dangerous if the command is built from untrusted input.
- **When it is legitimate:** Occasionally used to open a file or launch a helper. Look at what it runs.

### getattr against __import__

- **What it is:** Reaches into a dynamically imported module via getattr.
- **When it is dangerous:** Indirection used to evade name-based detection.
- **When it is legitimate:** Rare.

### High-entropy blob

- **What it is:** Contains a long, high-randomness encoded-looking string.
- **When it is dangerous:** Often a packed payload that could not be decoded.
- **When it is legitimate:** Occasionally embedded binary data (an icon, a font). Context-dependent.

### marshal/pickle.loads

- **What it is:** Deserializes objects with pickle or marshal.
- **When it is dangerous:** Deserializing untrusted data can execute code.
- **When it is legitimate:** Some tools cache state with pickle. A risky pattern, not always malicious.

### Native code via ctypes

- **What it is:** Calls into native libraries through ctypes.
- **When it is dangerous:** Lets Python run arbitrary native code or shellcode.
- **When it is legitimate:** Some hardware or OS-integration add-ons use ctypes. Uncommon but real.

### Network connection

- **What it is:** Opens a network connection (urlopen / requests / socket).
- **When it is dangerous:** Needed to exfiltrate data or pull a second stage; matters most alongside credential/file access or obfuscation.
- **When it is legitimate:** Very common and legitimate: update checks, fetching assets, license validation, API calls. A URL whose response you decode is normal. Network access alone is not malware.

### PowerShell encoded command

- **What it is:** Uses -EncodedCommand or FromBase64String.
- **When it is dangerous:** Encoded PowerShell exists almost exclusively to hide a command.
- **When it is legitimate:** None expected in a .blend.

### Reversed string/bytes

- **What it is:** Reverses a string or byte sequence at runtime.
- **When it is dangerous:** Used to hide a literal from inspection.
- **When it is legitimate:** Rare.

### Shell invocation

- **What it is:** Invokes a shell (powershell, cmd, /bin/sh).
- **When it is dangerous:** Shell one-liners are a common malware execution method.
- **When it is legitimate:** Rare in add-ons; usually worth a look.

### Spawns a subprocess

- **What it is:** Runs an external program.
- **When it is dangerous:** Command execution; concerning when the command is attacker-controlled or fed by network/obfuscation.
- **When it is legitimate:** Legitimate and common: invoking ffmpeg, renderers, exporters, compilers. Pipeline tools do this constantly. Read WHAT it runs before worrying.

### Writes an executable/script file

- **What it is:** Writes a file whose name is a script or executable (.py, .pth, .bat, .ps1, .exe...).
- **When it is dangerous:** Dropping a program to disk is a stager move; a .pth into site-packages auto-runs on the next Python start.
- **When it is legitimate:** Uncommon. Some code generators emit .py files. Worth a look, not proof of malice.

## Informational: normal in legitimate scripts; never shown as a concern

### App-data path

- **What it is:** References an app-data folder.
- **When it is dangerous:** None by itself.
- **When it is legitimate:** Add-ons store config and caches there routinely.

### Hardcoded IP

- **What it is:** Contains an IP address.
- **When it is dangerous:** None by itself.
- **When it is legitimate:** Normal for self-hosted services or LAN tools.

### Hardcoded URL

- **What it is:** Contains a URL.
- **When it is dangerous:** None by itself.
- **When it is legitimate:** Docs links, update checks, asset and API endpoints. Completely normal.

### Imports a sensitive module

- **What it is:** Imports ctypes/winreg/marshal/socket.
- **When it is dangerous:** None by itself; the import only matters if the module is actually used dangerously.
- **When it is legitimate:** Plenty of tools import socket or ctypes for benign reasons.

### OSL script node

- **What it is:** Contains an OSL shader script node.
- **When it is dangerous:** Low; OSL is far more constrained than Python.
- **When it is legitimate:** Normal in advanced shading setups.

### Runtime decoding

- **What it is:** Decodes base64/hex at runtime.
- **When it is dangerous:** None by itself.
- **When it is legitimate:** Decoding an embedded icon, parsing an API response, unpacking data. Only matters if what is decoded is itself code, which the engine checks separately.

### Temp file

- **What it is:** Uses a temporary file.
- **When it is dangerous:** None.
- **When it is legitimate:** Ubiquitous and harmless.

### Writes a file

- **What it is:** Writes or deletes a file.
- **When it is dangerous:** None by itself.
- **When it is legitimate:** Every exporter writes files. Only writing an executable (see drop) is treated as a concern.

