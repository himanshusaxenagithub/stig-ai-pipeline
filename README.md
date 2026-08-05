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
| 2. stig-scan | planned | Run STIG checks against the local system and record pass/fail |
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

With an [Anthropic API key](https://console.anthropic.com), stig-prep
annotates every rule with a plain-English summary, a triage bucket, and
an automation flag:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."

# Cheap test drive: annotate just 5 rules first
python3 -m stigprep parse U_Apple_macOS_15_V1R7_STIG.zip --explain --limit 5

# Full run (results are cached next to the STIG file — re-runs are free)
python3 -m stigprep parse U_Apple_macOS_15_V1R7_STIG.zip --explain
```

Triage buckets:

- `quick-win` — fast and low-risk to apply now
- `config-profile` — needs an MDM/configuration profile deployed
- `needs-judgment` — depends on your environment; a human must decide
- `risky-change` — can lock you out or break workflows if applied blindly

The AI layer is deliberately conservative: it never invents commands that
aren't in the STIG's own check/fix text, unknown triage values are
downgraded to `needs-judgment`, and every annotation is labeled with the
model that produced it. **AI output is an aid, not an authority — the
official DISA STIG text is always the source of truth.**

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
