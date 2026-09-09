---
name: stig-scan-windows
description: Check a Windows system (Windows 11, Windows Server) against its DISA STIG and report, in plain English, where it stands. Use this skill whenever the user asks to scan, audit, assess or check a Windows machine against a STIG, mentions a Windows checkpack, or says anything like "scan this PC", "run the STIG checks on this server", "how compliant is this Windows box" — even if they do not name the tool. It drives stig-scan (Module 2) on the Windows profile through PowerShell, never approves a check on the user's behalf, and never runs anything a human has not approved.
---

# Scan a Windows system against its STIG

Same procedure as stig-scan-macos — locate → author → verify → review → the
human approves → scan → explain — with the Windows profile. Read that skill
for the full step text; this file carries only what is different on Windows.

The guiding principle is unchanged: **nothing executes unless a named human
has read it and approved it, and nothing that can change the system ever
executes.**

## What is different on Windows

**Checks run in PowerShell.** The scanner launches `pwsh` or
`powershell.exe` with `-NoProfile -NonInteractive`. Python 3.9+ must be
installed on the Windows host (python.org or the Microsoft Store build).

**Author with the Windows profile.**

```powershell
python -m stigprep parse U_MS_Windows_11_V2R9_STIG.zip --format json
python -m stigscan author out\*windows_11*_checklist.json -o checkpacks\windows-11-v2r9.json --platform windows
```

**DISA's Windows check text is not commands; the extractor maps four
shapes.** Tell the user which shape each check came from when they review:

| DISA writes | The check becomes | Confidence |
|---|---|---|
| Registry Hive / Path / Value Name / Value | `Get-ItemProperty` on that value, compared to the stated value | high |
| `AuditPol /get` plus a "Category >> Subcategory - Success" line | `auditpol /get /subcategory:"…" /r`, regex on the CSV | medium |
| A gpedit path **with** a `Secedit /Export` fallback and a key name | `secedit /export` to a temp file, read that key, delete the file | high |
| A quoted read-only cmdlet with an acceptance sentence | that cmdlet | medium |

A gpedit path **without** a secedit fallback, Computer Management, Server
Manager, or an interview question is MANUAL. Anything else is UNSUPPORTED
for a human or AI author. On Windows 11 V2R9 about 60 percent of rules
reduce to a check; on Windows Server 2019 V3R8 about 57 percent. Say the
numbers `author` prints.

**Most checks need an elevated shell.** Registry policy keys, `auditpol` and
`secedit` all require it. `author` marks those `requires_root`; the scan
skips them unless PowerShell was started with "Run as administrator". Show
the user how many before they run, and let them choose.

**The safety gate refuses anything that changes the system** — any `Set-`,
`New-`, `Remove-`, `Enable-`, `Disable-`, `Install-` cmdlet, `reg add`,
`auditpol /set`, `secedit /configure`, `sc config`, `netsh` outside `show`,
`manage-bde -on/-off`, file writes, network clients. The one exception is
`Remove-Item $f -Force` on the scratch file the secedit read creates; any
other `Remove-Item` is refused. A check that trips the gate is reported as
ERROR, never pass or fail.

**Empty output is not evidence.** A registry value that does not exist
returns nothing; the STIG's own sentence ("does not exist or is not
configured as specified, this is a finding") makes absence a finding, and
the extractor records that sentence as the source. Explain that when it
happens rather than calling it a bug.

## Example

Input: "scan this Windows 11 laptop against the STIG".

Actions: `author --platform windows` → 257 rules, 154 reducible, 15 manual,
88 unsupported → `verify` → `review --severity high --show` → user approves
a handful by name → scan from an elevated PowerShell with `--record` →
report: "N of 257 rules were actually evaluated; … ; the rest not evaluated
(unreviewed, not yet authored, or need elevation)."
