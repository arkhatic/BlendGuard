# BlendGuard

**See what a `.blend` will auto-run before you trust it.**

A free, GPL, transparency-first security add-on for Blender. It shows what a file would auto-run, without executing it, so you can decide before you trust it. Static analysis only, and **no network access**.

## Why

`.blend` files can embed Python, which is legitimate for rigging and automation but is abused: malicious files spread through asset sites, pirated bundles, and lookalike domains carry information-stealers (for example StealC V2) that run the moment a file opens with "Auto Run Python Scripts" enabled, then harvest Discord tokens, browser credentials, and crypto wallets. Blender's safe default keeps auto-run off and warns, but does not show you *what* a file would have run. BlendGuard fills that gap.

## What it does

- Enumerates embedded text scripts, Python driver expressions, OSL script nodes, and registered handlers, then scores them CLEAN / INFO / SUSPICIOUS / DANGEROUS, without executing anything.
- Resists evasion: normalizes string concatenation and escapes, decodes base64/85/32, hex, rot13, zlib, and gzip (recursively, with caps), flags high-entropy blobs, and confirms dangerous calls via AST.
- Knows the campaign tradecraft: Cloudflare Workers loaders, PowerShell `-enc`, and browser/wallet/Discord theft paths.
- A load-time guard inspects on open and warns; a disk scan triages a file before you open it by parsing the `.blend` block structure (with a whole-file fallback), and reports `INCOMPLETE` rather than a false "clean" when it cannot fully read a compressed file.

## Install

Blender 4.2 LTS or newer. Edit > Preferences > Get Extensions > (dropdown) > Install from Disk, and pick the `BlendGuard-*.zip`.

## Use

Keep **Auto-Run Python Scripts OFF**, open the file, and read the verdict in the BlendGuard sidebar tab (press `N`), or let the on-open guard surface it. Only enable scripts for files you have inspected and trust.

## Honest limits

Static analysis is a heuristic; determined obfuscation can evade any scanner, so treat BlendGuard as defense in depth, not a guarantee. Keeping Auto-Run off remains your primary protection.

## Privacy and license

No telemetry, no network. GPL-3.0-or-later. See `LICENSE`.
