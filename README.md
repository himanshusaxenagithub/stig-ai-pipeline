# stig-ai-pipeline

**AI-assisted STIG compliance tooling.** Turn DISA STIGs from 300-page
checklists into something an engineer can actually work through — parsed,
prioritized, explained in plain English, and (eventually) checked and
remediated automatically.

Scanners like OpenSCAP can already tell you *that* you have 169 findings.
The hard part is the last mile: understanding what each finding actually
asks of you, deciding which ones are safe to fix right now, and turning
check text into remediation — that translation layer is what this project
uses an LLM for, with explicit flags for the rules where a human must
decide.

## Roadmap

| Module | Status | What it does |
|---|---|---|
| **1. stig-prep** | ✅ this release | Parse any DISA STIG (XCCDF) into engineer-friendly checklists (Markdown / JSON / CSV) with optional AI triage & plain-English explanations |
| **2. stig-scan** | ✅ v0.2 (macOS), v0.3 (Linux) | Run human-approved, content-frozen STIG checks against the local system and record pass/fail with an explicit evidence-coverage statement. Platform profiles: macOS, Linux; Windows safety vocabulary only |
| 3. stig-assess | planned | AI-assisted assessment: interpret scan results, draft POA&M entries |
| 4. stig-harden | planned | Generate remediation scripts for findings, with human-review gates |

Everything is STIG-agnostic: the tools parse standard XCCDF, so the same
code works for the Apple macOS 15/26 STIGs, Ubuntu, RHEL, or any other
STIG that DISA publishes.

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

## AI triage & explanations

Every rule can carry a plain-English summary, a triage bucket (`quick-win`,
`config-profile`, `needs-judgment`, `risky-change`), an automation flag and a
one-line caution. There are three ways to get them; the first two need no
API key and no account.

**1. Already in the repository.** `annotations/` ships complete explanation
sets. Parse the matching STIG and they are picked up automatically:

```
python3 -m stigprep parse U_MS_Windows_11_V2R9_STIG.zip --explain
#  -> 257 rules annotated from annotations/, 0 API calls
```

Currently shipped: Microsoft Windows 11 V2R9 (257 rules). More follow.

**2. With the AI assistant you already have.** The `stig-explain` skill
(`skills/stig-explain/`) lets any assistant that supports skills write the
same four fields, ten rules at a time. A helper script hands it the next
batch, validates every answer — rejecting the batch if a rating is invalid,
a field is missing, or a command appears that is not in the rule's own text
— and files the results into the checklist and into `annotations/`. See the
skill for the loop; it is how the Windows 11 set was produced.

**3. Direct API call.** With an [Anthropic API key](https://console.anthropic.com/)
stig-prep can annotate any rules not already covered:

```
export ANTHROPIC_API_KEY="sk-ant-..."

# Cheap test drive: annotate just 5 rules first
python3 -m stigprep parse U_Apple_macOS_15_V1R7_STIG.zip --explain --limit 5

# Full run (results are cached next to the STIG file and in annotations/ — re-runs are free)
python3 -m stigprep parse U_Apple_macOS_15_V1R7_STIG.zip --explain
```

Whichever path produced them, the annotations land in the same place and the
same format, so a set generated once is available to every later user.

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
| `windows` | ✗ refused | ✗ every rule UNSUPPORTED | — |

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

## AI skill: plain-English explanations without an API key

`skills/stig-explain/` lets any AI assistant that supports skills produce the
same summary / triage / automation / caution fields as `--explain`, ten rules
at a time, with no API key. A helper script hands the assistant the next batch
and validates and files the answers. Results land in the checklist JSON and in
`annotations/<stig>.ai-cache.json`, which `--explain` also reads — so
annotations committed to this repository are available to every user, with or
without an assistant. `annotations/` currently carries the complete Windows 11
V2R9 set (257 rules).

## AI skills: scanning

`skills/stig-scan-macos/` and `skills/stig-scan-linux/` let an assistant drive
Module 2 end to end — author, verify, walk the user through review, then scan
and explain the report. The assistant never approves a check and never runs
an unreviewed one; those lines are in the skill text and enforced by the
scanner. `skills/stig-scan-windows/` exists to say plainly that Windows
scanning is not yet supported.

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
    --explain         AI annotations (needs ANTHROPIC_API_KEY)
    --model NAME      Anthropic model (default: claude-sonnet-4-5)
    --limit N         annotate at most N un-cached rules
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
