# Changelog

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
