---
name: stig-to-tracker
description: Convert a DISA STIG into a formatted Excel implementation tracker in one step. Use this skill whenever the user asks to parse a STIG, mentions a STIG file or XCCDF file (names like U_Apple_macOS_26_V1R3_STIG.zip or *_Manual-xccdf.xml), wants a STIG checklist, compliance tracker, or spreadsheet for tracking STIG implementation, or says anything like "parse the stig file", "make a tracker from this STIG", or "turn this STIG into Excel" — even if they do not name the tool. It locates the STIG, runs the stig-prep parser, validates the results, builds a styled .xlsx tracker with status dropdowns, and flags anything unusual for human review.
---

# STIG → Excel tracker

Turn a DISA STIG (zip or XCCDF XML) into an Excel workbook a team can work
from: one row per rule, severity color-coding, status dropdowns, and a
details sheet with every rule's check and fix text. The pipeline is:
locate → parse → validate → build tracker → report.

The guiding principle: **the STIG's own text is the source of truth.** This
skill reformats it; it never invents, summarizes, or omits rule content.
Anything odd found along the way gets flagged to the user, not silently fixed.

## Step 1 — Locate the inputs

Two things are needed: a STIG file and the stig-prep parser.

**The STIG file.** If the user gave a path, use it. Otherwise look for
`U_*_STIG*.zip` or `*xccdf*.xml` in the working directory, uploads, or the
folder they mention. If several match, ask which one rather than guessing —
parsing the wrong product's STIG produces a plausible-looking but useless
tracker. Either the zip or the XML inside it works; the parser accepts both.

**The parser.** stig-prep is a zero-dependency Python package (Python 3.9+).
Check for it with `python3 -c "import stigprep"` from the repo root. If it is
not present, clone it: `git clone https://github.com/himanshusaxenagithub/AI-STIG-Repo`
and run from inside that directory (or add it to PYTHONPATH).

## Step 2 — Parse

From the stig-prep repo root:

```bash
python3 -m stigprep parse <path-to-stig.zip-or-xccdf.xml> -o <outdir> --format json
```

The parser prints the rule count and severity breakdown (e.g. `282 rules —
34 CAT I, 234 CAT II, 14 CAT III`) and writes a `*_checklist.json`. That JSON
is the input for the tracker builder. If the user also wants the Markdown or
CSV forms, drop `--format json` and all three are produced.

## Step 3 — Validate before building

Compare the parser's printed rule count against expectations: a real OS STIG
has roughly 150–500 rules (RHEL 9 V2R9 carries 445). A count of 0 or a handful means the wrong file was
parsed (for example, a sample or a stylesheet) — stop and tell the user rather
than shipping an empty tracker. Also confirm the parsed title matches the
product the user asked about.

## Step 4 — Build the tracker

```bash
python3 scripts/make_tracker.py <outdir>/<name>_checklist.json <product>_stig_tracker.xlsx
```

(`scripts/make_tracker.py` ships with this skill; it needs `openpyxl`.)

The workbook it produces has three sheets:

- **Summary** — STIG title, version, release date, rule counts by CAT, and
  the count of flagged anomalies. This is the at-a-glance sheet.
- **Tracker** — one row per rule, sorted CAT I first: rule ID, CAT (color
  coded: red/amber/blue), severity, requirement title, a Status dropdown
  (Open / In progress / Implemented / Not applicable / Risk accepted), and
  empty Owner / Target date / Notes columns for the team to fill in.
  Header row frozen, autofilter on.
- **Details** — the full discussion, check text, and fix text for every rule,
  so nobody has to go back to the raw XML to understand a requirement.

## Step 5 — Report and deliver

The script prints `flagged for review: N` with the list (missing severities,
empty check/fix text, duplicate IDs). Surface these to the user explicitly —
they are usually parser edge cases or unusual STIG content, and a human
should look at each one. Never present a tracker with warnings as if it were
clean.

Then deliver the .xlsx to the user with a one-line summary of what it
contains (product, rule count, CAT breakdown, flags). If the file can be
sent or saved to their machine, do that rather than only leaving it on disk.

## Example

Input: "parse the stig file" (a `U_Apple_macOS_26_V1R3_STIG.zip` sits in the
user's downloads).

Actions: clone/locate stig-prep → `python3 -m stigprep parse U_Apple_macOS_26_V1R3_STIG.zip -o out --format json`
→ check count (~250 rules, plausible) → `python3 scripts/make_tracker.py out/*_checklist.json macos26_stig_tracker.xlsx`
→ deliver.

Output message: "macOS 26 STIG tracker ready: 250 rules (18 CAT I), 0 flagged
for review — Summary, Tracker, and Details sheets inside."
