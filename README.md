# stig-ai-pipeline

**Apply Department of Defense security checklists to your own systems without a compliance specialist.**
An open-source, AI-enabled toolkit consisting of AI skills and scripts that turns any DISA STIG into a plain-English plan, explains every rule, and checks a machine against it — with a human approving every check before it runs. Free, MIT licence, no account, no API key.

**New here?** Read the two-page overview with a worked example: [docs/overview.pdf](docs/overview.pdf).

## Why this exists

The US Department of Defense publishes free cybersecurity checklists called **STIGs** (Security Technical Implementation Guides) for almost every common system — Windows, Linux, macOS, SQL Server and hundreds more. Each one lists a few hundred settings that make the system secure against cyberattacks. They are the most thorough baselines available, and anyone can download them.

Almost nobody outside government uses them. Each guide is a few hundred rules written for a security auditor; applying one means reading every rule, understanding it, ranking it by risk, and translating it into a change on a real machine. That takes a specialist, and most organisations do not have one. So the checklists sit unused, and the systems stay less secure than they could be for free.

This toolkit does the interpreting. Scanners like OpenSCAP can already tell you *that* you have 169 findings; this project handles the last mile — what each finding actually asks of you, which fixes are safe to make today, and what could go wrong — with explicit flags for the rules where a human must decide.

## Who it is for

| If you are… | This gives you… |
|---|---|
| **An IT generalist** at a school district, clinic, small bank, municipal agency, or any organisation without a security team | A ranked, plain-English plan for securing each system, in one command, and a way to check your work |
| **A managed service provider** looking after many small clients | One repeatable method across Windows, Linux, macOS and SQL Server, with a dated report per client per scan |
| **A sysadmin at a DoD contractor or federal agency** where STIG compliance is mandatory | The translation from guide to tracker done for you, and evidence for the accreditation package that says exactly what was and was not evaluated |
| **A security engineer** who already knows STIGs | A parser that reads any XCCDF as DISA ships it, explanation sets you can reuse, and a scanner whose safety model you can audit line by line |
| **Someone answering "are our systems secure?"** to a board, an auditor, a customer or a cyber-insurer | A recognised baseline (each rule maps to NIST 800-53 through DISA's own identifiers) and a report to hand over instead of an opinion |

## What you get

- **A week of specialist work in one command.** `parse` turns a 300-page guide into a tracker: one row per rule, severity ranked, full check and fix text, as Excel, CSV, JSON or Markdown.
- **Every rule explained.** What it makes you do and why, a rating (quick win / needs a policy pushed out / needs a decision / can break things), whether it can be scripted, and what could go wrong. Seven STIGs and 1,440 rules are explained already and shipped in this repository; the `stig-explain` skill produces more with the AI assistant you already have.
- **A scan you can trust.** `stig-scan` checks a machine against its guide. Every check is unreviewed until a named person reads and approves it; approval freezes a fingerprint of the exact command; a safety gate refuses anything that could change the system; and the report says first how many rules were actually evaluated. AI may help write a check. It never runs one.
- **Nothing to buy and nothing to sign up for.** Python 3.9+, no dependencies, no API key, no vendor. Works with any AI assistant that supports skills, or with none.

## Roadmap

| Module | Status | What it does |
|---|---|---|
| **1. stig-prep** | ✅ this release | Parse any DISA STIG (XCCDF) into engineer-friendly checklists (Markdown / JSON / CSV) with optional AI triage & plain-English explanations |
| **2. stig-scan** | ✅ v0.2 (macOS), v0.3 (Linux), v0.4 (Windows) | Run human-approved, content-frozen STIG checks against the local system and record pass/fail with an explicit evidence-coverage statement. Platform profiles: macOS, Linux, Windows |
| 3. stig-assess | planned | AI-assisted assessment: interpret scan results, draft POA&M entries |
| 4. stig-harden | planned | Generate remediation scripts for findings, with human-review gates |

Everything is STIG-agnostic: the tools parse standard XCCDF, so the same
code works for Windows 11, Windows Server, RHEL, Ubuntu, macOS, SQL Server,
or any other STIG that DISA publishes.

## Quick start

Requires Python 3.9+ (already on your Mac if you have Xcode command line
tools: `xcode-select --install`). No third-party packages needed.

```bash
# 1. Get the official STIG for your OS (auto-detects macOS 15 vs 26)
./scripts/download_stig.sh

# 2. Generate the checklist
python3 -m stigprep parse U_Apple_macOS_15_V1R7_STIG.zip

# Outputs land in ./out/:
#   *_checklist.md    — human-friendly checklist, grouped by severity
#   *_checklist.json  — structured data for the downstream modules
#   *_checklist.csv   — track your progress in a spreadsheet
```

Don't have the STIG handy? Try it on the bundled 6-rule sample first:

```bash
python3 -m stigprep parse samples/sample_macos15_stig.xml
```

## Plain-English explanations

Every rule can carry a plain-English summary, a triage bucket (`quick-win`,
`config-profile`, `needs-judgment`, `risky-change`), an automation flag and a
one-line caution. No account, no key, no external service.

**Already in the repository.** `annotations/` ships complete explanation
sets. Parse the matching STIG with `--explain` and they are attached:

```
python3 -m stigprep parse U_MS_Windows_11_V2R9_STIG.zip --explain
#  explanations: all 257 rules annotated from filed sets
```

Currently shipped, 1,440 rules across seven STIGs: Microsoft Windows 11 V2R9 (257), Windows Server 2019 V3R8 (282), Red Hat Enterprise Linux 9 V2R9 (445), Ubuntu 24.04 LTS V1R6 (194), Apple macOS 26 V1R3 (160), SQL Server 2022 Instance V1R4 (79) and Database V1R3 (23).

**Produce them for any other STIG.** The `stig-explain` skill
(`skills/stig-explain/`) lets the AI assistant you already have write the
four fields, ten rules at a time. A helper script hands it the next batch,
validates every answer — rejecting the batch if a rating is invalid, a field
is missing, or a command appears that is not in the rule's own text — and
files the results into the checklist and into `annotations/`. That is how the
Windows 11 set was produced. Commit the file and every later user gets it.

## Module 2: stig-scan

`stig-prep` tells you what the STIG asks. `stig-scan` tells you where the
machine actually stands — without ever letting a language model decide what
runs on your system.

DISA's check text is prose written for a human auditor, so something has to
turn it into executable logic. The design rule here is that **AI is allowed
in the authoring loop and never in the execution loop**:

```
STIG check text  ──author──▶  candidate check  ──human review──▶  frozen check  ──scan──▶  evidence
                 (offline)      (UNREVIEWED)        (you)          (digest)
```

Approving a check records a SHA-256 digest over exactly the fields that
determine what executes — the command, the comparator, the expected value.
If any of them is edited afterwards, the digest no longer matches and the
check is reported as **DRIFTED** and refused. An approval always refers to
specific bytes a human actually read.

### Platforms

The core is platform-neutral; what differs lives in `stigscan/platforms/`,
one module per operating system: the read-only allowlist, the forbidden
mutating forms, the shell, and how the extractor reads DISA's check text.

| Profile | Scan | Extractor | Packs shipped |
|---|---|---|---|
| `macos` | ✅ | ✅ shell snippet + acceptance sentence | `macos-26-v1r3` (160 rules, 153 reducible) |
| `linux` | ✅ | ✅ prompt lines + mapped sentence shapes | `ubuntu-24.04-v1r6` (194, 72 reducible), `rhel-9-v2r9` (445, 156 reducible) |
| `windows` | ✅ PowerShell | ✅ registry / auditpol / secedit / quoted cmdlet shapes | `windows-11-v2r9` (257, 154 reducible), `windows-server-2019-v3r8` (282, 160 reducible) |

A pack records its platform; `scan` will not run a pack on a host of a
different platform. Every shipped pack is entirely unreviewed.

### Workflow

```bash
# 1. Derive candidate checks from the module 1 checklist (nothing is approved yet)
python3 -m stigprep parse U_Apple_macOS_26_V1R3_STIG_Manual-xccdf.xml --format json
python3 -m stigscan author out/*_checklist.json -o checkpacks/macos-26-v1r3.json

# 2. Read exactly what would execute, highest severity first
python3 -m stigscan review checkpacks/macos-26-v1r3.json --severity high --show

# 3. Freeze the ones you accept, under your own name
python3 -m stigscan approve checkpacks/macos-26-v1r3.json \
    --by "Your Name" --id APPL-26-005001 --id APPL-26-002064

# 4. Audit the pack at any time (drift, safety objections, review coverage)
python3 -m stigscan verify checkpacks/macos-26-v1r3.json

# 5. Scan. Only approved, unmodified checks run.
python3 -m stigscan scan checkpacks/macos-26-v1r3.json -o out/
```

### The scanner will not run arbitrary code

Every check passes a static safety gate before execution, enforced in the
orchestrator so it applies no matter where the output comes from. Two
independent rules must both hold: every executable named in the command is
on a read-only allowlist, and no forbidden construct appears — mutating
subcommands (`defaults write`, `csrutil disable`, `launchctl unload`), file
redirection, network clients, privilege escalation, or destructive verbs.
A check that fails the gate is reported as **ERROR**, never as pass or fail.

Checks that embed `sudo` are rewritten to declare `requires_root` instead,
so the scanner tells you up front which checks need privilege rather than
prompting for a password halfway through a run.

### Reports say what did *not* run

An automated compliance report is only as honest as its coverage statement,
so every scan reports one:

> **11 of 13 rules (84.6%) were actually evaluated on this host.** The
> remaining 2 produced no compliance evidence and must not be counted as
> either compliant or non-compliant.

Outcomes are `pass`, `fail`, `error`, `manual` and `skipped`, and the three
that are not pass/fail are never folded into "fail". Every skip is reported
with its reason. Results from checks forced with `--include-unreviewed` are
flagged untrusted in both the JSON and the Markdown.

### Reproducible scans

```bash
# Capture a scan as a durable artifact
python3 -m stigscan scan checkpacks/macos-26-v1r3.json --record evidence/2026-08-20/

# Replay it anywhere — including CI on a platform that cannot run macOS commands
python3 -m stigscan scan checkpacks/macos-26-v1r3.json --fixtures evidence/2026-08-20/
```

Recording turns a scan into evidence that can be re-examined months later
instead of a claim about something that happened once on somebody's laptop.

### What the macOS 26 pack looks like

Authored from the official Apple macOS 26 (Tahoe) V1R3 STIG, 160 rules:

| | count |
|---|---:|
| Reducible to a command | 153 |
| No machine-readable acceptance criterion (GUI or interview) | 7 |
| High extractor confidence | 64 |
| Medium — multi-line snippet, confirm it is self-contained | 81 |
| Low — safety gate objection or ambiguity, needs a decision | 8 |

The pack ships with **every entry unreviewed**. That is not an oversight;
an approval is worthless if it was not made by the person accountable for
the system.

## AI skill: plain-English explanations

`skills/stig-explain/` lets any AI assistant that supports skills produce the
summary / triage / automation / caution fields, ten rules
at a time. A helper script hands the assistant the next batch
and validates and files the answers. Results land in the checklist JSON and in
`annotations/<stig>.ai-cache.json`, which `--explain` attaches — so
annotations committed to this repository are available to every user, with or
without an assistant. `annotations/` carries complete sets for seven STIGs
(1,440 rules).

## AI skills: scanning

`skills/stig-scan-macos/` and `skills/stig-scan-linux/` let an assistant drive
Module 2 end to end — author, verify, walk the user through review, then scan
and explain the report. The assistant never approves a check and never runs
an unreviewed one; those lines are in the skill text and enforced by the
scanner. `skills/stig-scan-windows/` drives it on Windows through PowerShell.

## AI skill: one-command tracker

`skills/stig-to-tracker/` packages this workflow as a reusable AI skill.
Installed into an AI assistant that supports skills (such as Claude), it
turns a single instruction like *"parse the STIG file"* into the full
chain: locate the STIG, run stig-prep, validate the rule count, build a
formatted Excel tracker, and flag anomalies for human review.

The tracker builder also works standalone:

```bash
pip install openpyxl   # the only extra dependency, used just for this step
python3 -m stigprep parse U_Apple_macOS_15_V1R7_STIG.zip --format json
python3 skills/stig-to-tracker/scripts/make_tracker.py \
    out/*_checklist.json macos_stig_tracker.xlsx
```

The workbook has three sheets: **Summary** (counts by severity), **Tracker**
(one row per rule, CAT I first, status dropdowns, owner/date/notes columns),
and **Details** (full check and fix text per rule).

## Options

```
python3 -m stigprep parse <stig.zip|xccdf.xml>
    -o, --out DIR     output directory (default: ./out)
    --format LIST     md,json,csv (default: all)
    --explain         attach plain-English explanations filed in annotations/
```

## Tests

```bash
python3 -m unittest discover -s tests
```

## Notes

- `samples/sample_macos15_stig.xml` is a 6-rule illustrative excerpt for
  testing the parser — its text is abbreviated and its severities are
  illustrative. Never harden a system from the sample; use the official
  package from [public.cyber.mil](https://public.cyber.mil/stigs/downloads/).
- This project is built entirely on publicly released DISA STIG content.

## License

MIT
