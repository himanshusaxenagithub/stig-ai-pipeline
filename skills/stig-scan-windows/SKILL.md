---
name: stig-scan-windows
description: Placeholder for scanning a Windows system against its DISA STIG. Not yet supported — use this skill only to tell the user what exists today, what does not, and what they can do instead. Triggers on requests to scan, audit or check a Windows machine against a STIG.
---

# Scan a Windows system against its STIG — not yet supported

## What to tell the user

Windows scanning is **not available in this release**. Say so in the first
sentence. Do not attempt to author or run Windows checks by other means.

## What exists

* The Windows safety profile in `stigscan/platforms/windows.py`: the
  read-only PowerShell cmdlets and commands a check may use, and the
  mutating forms it may not. `verify` and `review` work on a Windows pack.
* `stigscan author --platform windows` runs, and marks every rule
  UNSUPPORTED with the note "no extractor for platform 'windows' in this
  release", so a Windows pack can hold human- or AI-authored checks once a
  process for authoring them exists.
* `stigscan scan` refuses a Windows pack with a clear error.

## What does not exist, and why

DISA writes Windows check text as registry paths, Group Policy paths and GUI
steps, not as commands. Reducing that to executable checks needs a different
authoring approach from the shell-snippet extractor used for macOS and
Linux — most likely a registry-path-to-`Get-ItemProperty` mapping plus an
AI-assisted pass for the rest, all landing UNREVIEWED as on other platforms.
That is planned work, not shipped work.

## What the user can do today

* `stig-to-tracker` and `stig-explain` both work on Windows STIGs: the
  Windows 11 V2R9 guide is fully parsed and annotated (257 rules). Offer to
  build or open that tracker so they can work the checklist by hand.
* If they need automated evidence now, the DISA SCAP benchmark for their
  Windows release with a SCAP-validated scanner is the supported route.
