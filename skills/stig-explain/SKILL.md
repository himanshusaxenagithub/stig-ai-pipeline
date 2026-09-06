---
name: stig-explain
description: Explain DISA STIG rules in plain English, ten at a time, and file the explanations so anyone gets them for free. Use this skill whenever the user asks to explain a STIG, annotate a checklist, add plain-English summaries or triage ratings to STIG rules, or says anything like "explain these rules", "what do these STIG findings mean", "annotate the tracker", "add explanations to the checklist" — even if they do not name the tool. It works on the *_checklist.json that stig-prep produces, needs no account or external service, and writes results into both the checklist and a shared annotations file that stig-prep's --explain attaches.
---

# STIG → plain-English explanations

Take a stig-prep checklist and, for every rule, add four short fields a
generalist administrator can act on. You are the AI that writes them; a small
script hands you the rules and files your answers. The pipeline is:
locate → next batch → explain → merge → repeat → rebuild tracker.

The guiding principle: **the rule's own check and fix text is the source of
truth.** You restate it in plain language; you never invent commands,
settings, paths or consequences that are not in that text. If the text does
not say how to do something, say that a human must look it up. Anything you
are unsure about gets `needs-judgment`, not a guess.

## Step 1 — Locate the inputs

You need a checklist JSON and this skill's helper script.

**The checklist.** A `*_checklist.json` produced by
`python3 -m stigprep parse <stig> --format json`. If there is none, run the
stig-to-tracker skill first (or the parse command) and come back.

**The helper.** `skills/stig-explain/scripts/annotate.py` in the stig-ai-pipeline
repository. Zero dependencies, Python 3.9+.

## Step 2 — Get the next batch

```bash
python3 skills/stig-explain/scripts/annotate.py next <checklist.json> --limit 10
```

Prints a JSON array of up to ten rules that have no explanation yet, each with
`stig_id`, `severity`, `title`, `discussion`, `check_text`, `fix_text`, and a
line on stderr saying how many remain. Ten is the default; go smaller if the
rules are long, never larger than 15.

## Step 3 — Explain the batch

For each rule write one object with exactly these keys:

- `stig_id` — copied verbatim.
- `summary` — one or two plain-English sentences (under 70 words): what
  this rule actually makes you do, and why it matters. No jargon that the
  rule itself does not use. Written for a competent administrator who is not
  a security specialist.
- `triage` — exactly one of:
  - `quick-win` — fast and low-risk to apply.
  - `config-profile` — needs a policy, profile or MDM setting pushed out.
  - `needs-judgment` — depends on the environment or mission; a human must decide.
  - `risky-change` — can lock users out or break workflows if applied blindly.
- `automation` — `automatable` if both the check and the fix can be scripted
  from the text given, otherwise `manual`.
- `caution` — one sentence on what could go wrong when applying it, or `""`.

Save the array as `batch.json` (any path). Rules of the road:

- Every `stig_id` from the batch must be answered, none added.
- Do not paste commands into `summary` or `caution` unless they appear in the
  rule's check or fix text. The merge step rejects command-like text it cannot
  find there.
- Severity is already known; do not restate CAT levels in the summary.
- If two rules are near-duplicates, write each on its own merits anyway.

## Step 4 — Merge

```bash
python3 skills/stig-explain/scripts/annotate.py merge <checklist.json> batch.json --model <your-name>
```

`--model` is a label for who wrote the annotations (for example
`claude-desktop-2026-09`); it is stored with each rule so provenance is visible.

The script validates the whole batch — unknown ids, bad triage values, empty
summaries, over-long summaries, missing caution, suspicious commands — and
**rejects the whole batch if anything fails**, printing the reasons. Fix the
listed items and merge again. On success it prints
`merged 10, N remaining` and writes two things:

1. the `ai` field of each rule inside the checklist JSON, and
2. `annotations/<stig-source>.ai-cache.json` at the repository root, in the
   format stig-prep's `--explain` attaches. Commit that file: anyone who clones the repository
   then gets the explanations with no assistant at all.

## Step 5 — Repeat until done

```bash
python3 skills/stig-explain/scripts/annotate.py status <checklist.json>
```

Loop steps 2–4 while rules remain. Stopping part-way is fine; `next` always
resumes from the first un-annotated rule.

## Step 6 — Rebuild the tracker and report

```bash
python3 skills/stig-to-tracker/scripts/make_tracker.py <checklist.json> <product>_stig_tracker.xlsx
```

When explanations are present the Tracker sheet gains four columns — *What it
means*, *Triage*, *Scriptable*, *Caution* — and the Summary sheet reports how
many rules carry an explanation. Deliver the workbook with a one-line summary:
product, rules annotated, triage breakdown.

Tell the user plainly: these explanations are an aid, not an authority. The
decisions — what to apply, in what order, and what to accept as a risk — stay
with a human.

## Example

Input: "explain the Windows 11 STIG" (an `out/microsoft_windows_11_*_checklist.json`
exists from an earlier stig-to-tracker run).

Actions: `annotate.py next … --limit 10` → write ten objects → `annotate.py merge …`
→ repeat 26 times → `make_tracker.py …` → deliver.

Output message: "Windows 11 STIG explained: 257 of 257 rules annotated
(31 quick-win, 168 config-profile, 44 needs-judgment, 14 risky-change) —
tracker rebuilt with the four explanation columns; annotations committed to
annotations/U_MS_Windows_11_STIG_V2R9_Manual-xccdf.ai-cache.json."
