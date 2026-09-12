# Changelog

## v0.5.0 — 2026-09-11

### Added — a page instead of a terminal

- `stigui`: a local web interface covering the whole method — choose a guide,
  read the rules in plain English, read and approve each check under your own
  name, scan, read the report, download the outputs. Standard library only.
  Served on `127.0.0.1`, guarded by a one-time token and a loopback-only Host
  check, so no other page or process on the machine can drive it.
- `Start.command` (macOS) and `Start.bat` (Windows): double-click to open it.
- **STIG Checker**, the double-click program: on a Mac a real application bundle
  with its own icon, on Windows `STIG Checker.bat` beside a `program` folder.
  Started from the desktop it runs in *app mode* — files in the per-user
  application folder, a second double-click reopens the page instead of starting
  a second copy, a Quit button and a Show files button on the page, and it stops
  itself once nobody has had the page open for ten minutes. The command line is
  unchanged. `Build.command` / `Build.bat` produce it, and `Read me.txt` beside it
  gives the exact first-open steps for an unsigned program on macOS 15+, older
  macOS and Windows. `--sign` / `--notarize` are there for when there is an
  Apple Developer ID, and are marked as not yet exercised.
- `packaging/build_portable.py`: assembles a folder that carries its own
  Python, so someone with no Python and no administrator rights can unzip it
  and double-click. Run once per platform. Nothing is packed or compiled —
  the code ships as the same .py files that are on GitHub, which keeps the
  "read exactly what this runs" argument intact and avoids the antivirus
  false positives that packers attract. No source change was needed: the
  folder has the same shape as a checkout, so annotations, check packs and
  the page are found the same way.
- `stigprep fetch`: download the official DISA package by name, so nobody has to
  find it on public.cyber.mil and unzip it. The page leads with the two machines
  this is for — MacBook and Windows PC — and picks the right macOS release from
  the version actually running, so nobody has to know whether they are on Tahoe
  or Sequoia. The page offers those two machines only, and refuses a request for
  any other guide with the command to use instead — servers, Linux and databases
  are for someone who administers systems for a living, and the command line
  serves that person better than a wizard does. Verified against a pinned digest where one is
  recorded and always against the validated rule count; the validated release is
  tried first so the filed explanations attach; a blocked network prints the
  download page rather than a stack trace.
- A shipped check pack is copied into the work folder the first time it is
  opened, so a person's approvals survive `git pull` and the packs published
  here stay unreviewed as documented.
- README: a Windows first-run section covering the PATH checkbox, the need for
  a fresh shell, and the nested folder that Windows creates when unpacking a ZIP.

### Fixed

- `--explain` found no filed explanations when it was handed a DISA `.zip`
  rather than the XCCDF inside it, because filed sets are named after the XCCDF.
  The lookup now tries the source name, then each XCCDF member of the archive,
  and finally the filed set sharing the most rule identifiers with the
  benchmark — so a renamed release still finds its explanations. The command
  documented in the README (`parse <stig>.zip --explain`) works as written.


## v0.4.0 — 2026-09-09

### Added — Windows scanning

- `stigscan/platforms/windows.py` now carries an extractor. DISA writes
  Windows check text as structured descriptions rather than commands; four
  regular shapes are mapped to read-only PowerShell: registry
  hive/path/value → `Get-ItemProperty`; `AuditPol` plus a subcategory line
  → `auditpol /get /subcategory /r`; a gpedit path with a `Secedit /Export`
  fallback → `secedit /export` to a scratch file and one key read; a quoted
  read-only cmdlet with an acceptance sentence → that cmdlet. GUI-only
  procedures are MANUAL; the rest stay UNSUPPORTED for a human.
- Authored packs: `checkpacks/windows-11-v2r9.json` (257 rules, 154
  reducible, 15 manual), `checkpacks/windows-server-2019-v3r8.json` (282,
  160 reducible, 23 manual). Both entirely unreviewed, by design.
- `skills/stig-scan-windows/` — the scanning skill for Windows, replacing
  the placeholder.
- Windows safety gate: `Remove-Item` is permitted only as
  `Remove-Item $f -Force` on the secedit scratch file; every other form is
  refused.
- 8 new tests (84 total).

## v0.3.0 — 2026-09-06

### Added — platform profiles for `stig-scan`

- `stigscan/platforms/` — one module per operating system carrying what
  actually differs: the read-only binary allowlist, the forbidden mutating
  forms, the shell, and how DISA writes check text for that platform. The
  scanner core (packs, review, approval digests, safety gate, runner,
  report) is unchanged and platform-neutral.
- `macos` — the reference profile; the previous allowlist, unchanged.
- `linux` — Ubuntu / RHEL family. Allowlist of ~110 read-only tools, a
  forbidden list covering `systemctl`, `sysctl -w`, `ufw`, `auditctl -w`,
  package managers, account and firewall changes, boot configuration.
  Extractor handles DISA's prompt-line-plus-sample-output check text and
  maps the unambiguous acceptance sentences; the rest stay UNSUPPORTED.
  Authored packs: `checkpacks/ubuntu-24.04-v1r6.json` (72 of 194 rules
  reducible), `checkpacks/rhel-9-v2r9.json` (156 of 445). Both ship
  entirely unreviewed, by design.
- `windows` — safety vocabulary only (read-only cmdlets, mutating forms).
  No extractor: `author` marks every rule UNSUPPORTED with a note; `scan`
  refuses a Windows pack.
- Packs record `platform`; `scan` refuses to run a pack on a different
  platform than it declares. Legacy packs without the field load as macOS.
- `stigscan author --platform {macos,linux,windows}` (default: the host).
- 16 new tests (77 total).

### Added — skills

- `skills/stig-explain/` — plain-English explanations:
  the assistant writes summary / triage / automation / caution for ten
  rules at a time; a helper validates and files them into the checklist
  and `annotations/`, which `--explain` also reads.
- `skills/stig-scan-macos/`, `skills/stig-scan-linux/` — drive Module 2
  end to end; the assistant reads, explains and reports, the human
  approves, the scanner runs only approved checks.
- `skills/stig-scan-windows/` — states plainly that Windows scanning is not
  yet supported and what to do instead.
- `annotations/` — complete explanation sets for seven STIGs, 1,440 rules,
  produced with the skill: Windows 11 V2R9, Windows Server 2019 V3R8,
  RHEL 9 V2R9, Ubuntu 24.04 V1R6, macOS 26 V1R3, SQL Server 2022 Instance
  V1R4 and Database V1R3.

### Removed

- The direct API annotation path and `--model`. Explanations are produced
  with the stig-explain skill and committed; the parser attaches them.

### Changed

- `not_equals` with empty output is now ERROR ("no output to evaluate"),
  not PASS. "Anything but X" is only evidence if there was an answer.
- `make_tracker.py` adds four explanation columns when annotations exist.
- `--explain` now only attaches filed explanations (repository `annotations/` and a local cache). No network calls, no account, no key anywhere in the tool.
- stig-to-tracker plausibility ceiling raised to 500 rules (RHEL 9 V2R9
  carries 445).

## v0.2.0 — 2026-08-20

### Added — module 2, `stig-scan`

- `stigscan author` derives candidate checks from a stig-prep checklist by
  parsing DISA check text. On the macOS 26 V1R3 STIG this reduces 153 of 160
  rules to an executable command and an explicit acceptance criterion.
- Human review gate: `review`, `approve`, `reject`, `verify`. Approval freezes
  a SHA-256 digest over the executable content of a check; post-approval edits
  are detected as drift and refused at scan time.
- Static safety gate — read-only binary allowlist plus a forbidden-construct
  denylist — enforced in the orchestrator, so a check judged unsafe is
  reported as `error` rather than as a compliance verdict, regardless of
  runner.
- `stigscan scan` produces JSON (for module 3) and Markdown (for humans),
  both leading with an explicit statement of how many rules actually produced
  evidence.
- Recorded-fixture runner: `--record` captures a scan as a durable artifact,
  `--fixtures` replays it on any platform, including CI hosts that cannot run
  macOS commands.
- `checkpacks/macos-26-v1r3.json` — 160 candidate checks for Apple macOS 26
  (Tahoe) V1R3, shipped entirely unreviewed by design.
- `docs/REVIEW_WORKFLOW.md`.
- 50 new tests (61 total).

### Notes

Building the authoring step produced a finding worth recording: the macOS
STIG check text is structured enough that a deterministic parser recovers the
command and expected value for 95.6% of rules exactly. A language model was
not used for that bulk, because a parser cannot hallucinate and the model
would have added risk without adding capability. The model's role is scoped
to the residue — the rules with no machine-readable acceptance criterion.

## v0.1.0 — 2026-08-04

- Module 1, `stig-prep`: parse any DISA STIG (XCCDF) into Markdown / JSON /
  CSV checklists, with optional AI triage and plain-English explanations.
- `skills/stig-to-tracker/`: AI skill packaging the parse-to-Excel workflow.
