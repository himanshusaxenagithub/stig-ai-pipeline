---
name: stig-assess
description: Draft POA&M-style entries from a stig-scan report in plain English plus structured fields. Use this skill whenever the user asks to assess scan results, write a POA&M, plan of action and milestones, interpret STIG findings, or says anything like "what do these failures mean", "draft the POA&M", "turn the scan into findings" — even if they do not name the tool. It drives stig-assess (Module 3). It never marks a finding complete and never accepts residual risk on the user's behalf.
---

# Assess scan results and draft a POA&M

Turn a stig-scan report into Plan of Action and Milestones drafts a
generalist administrator can review. You are the assistant that reads,
explains and files wording; the human accepts each draft and is the only
one who can close an item. The pipeline is:
locate the scan → draft → review with the user → they approve wording →
they close later, if and when they decide.

The guiding principle: **AI helps author and interpret; humans approve;
AI never silently changes systems and never marks a POA&M complete.**
The module enforces the last two; your job is to make the human step
easy and honest.

## Step 1 — Locate the inputs

You need a scan report and this skill's helper.

**The scan.** A `*_scan.json` produced by `python3 -m stigscan scan …`.
If there is none, drive the matching stig-scan-* skill first and come
back. Markdown and PDF reports are for reading; the JSON is the input.

**Optional explanations.** A stig-prep `*_checklist.json` (especially
one parsed with `--explain`) or a filed `annotations/*.ai-cache.json`.
When those are present the drafts reuse the same plain-English summary
and caution as the checklist.

**The helper.** `skills/stig-assess/scripts/assess.py` in this
repository. Zero dependencies, Python 3.9+.

## Step 2 — Draft (machine, not you)

```bash
python3 -m stigassess draft out/<pack>_scan.json -o out/<pack>-poam.json \
    --checklist out/<product>_checklist.json
```

Default `--include` is `fail` only. Passing results are refused — a
pass is not a finding. Offer `--include fail,error,manual` when the
user also wants evaluation gaps and GUI/interview items listed; say
plainly those extra rows are **not** findings.

Tell the user what `draft` printed. Every item is DRAFT and UNREVIEWED.
**None is closed.**

## Step 3 — Refine wording in batches (optional)

The deterministic draft is enough to review. If the user wants you to
tighten the prose, take the next unfinished items:

```bash
python3 skills/stig-assess/scripts/assess.py next out/<pack>-poam.json --limit 10
```

For each item write one object with exactly these keys:

- `stig_id` — copied verbatim.
- `description` — two to five plain-English sentences: what failed (or
  why it could not be judged), what was observed, and that this is still
  a draft. Under 180 words. No jargon the scan or the filed explanation
  does not already use.
- `recommendation` — what a person should consider next. Not an order.
  Do not invent commands, paths, registry values or sysctl names that
  are not in the item's own `command`, `scan_detail`, or the rule's
  check/fix text if you have it.
- `resources` — a realistic placeholder such as `TBD — a person must
  estimate`, or a short estimate if the user supplied one.
- `scheduled_completion` — `""` unless the user gave a date.

Save the array as `batch.json`. Rules of the road:

- Every `stig_id` from the batch must be answered, none added.
- **Do not include `poam_status`, `review_status`, `closure_kind`,
  `closed_by`, or anything that would mark the item complete.** The
  merge step rejects the whole batch if those keys appear.
- Do not paste commands into `description` or `recommendation` unless
  they already appear in the item (or the rule text you were given).

Merge:

```bash
python3 skills/stig-assess/scripts/assess.py merge out/<pack>-poam.json batch.json --model <your-name>
```

The script validates the batch and **rejects it whole** if anything
fails. On success the wording is updated and review state is reset to
unreviewed so a person must read the new text.

## Step 4 — Review with the user

```bash
python3 -m stigassess review out/<pack>-poam.json --show
```

Lead with findings (scan failures), CAT I first. Then, separately,
evaluation gaps and manual inspections — never fold those into "fail".
If an item is marked UNTRUSTED, say so first: the underlying check was
not human-approved and is not accreditation evidence.

## Step 5 — The human approves wording

Give them the command. Approval freezes a digest of the wording and
moves the item from draft to **open**. It does not close the finding.

```bash
python3 -m stigassess approve out/<pack>-poam.json --by "Their Name" --id APPL-26-005001
```

**Never run `approve` yourself.** A machine's name on a POA&M is worth
nothing. If they ask you to approve for them, explain that and give
them the command.

## Step 6 — Closing stays with the human

Closing records one of `remediated`, `risk_accepted`, or
`not_applicable`, under their name, with a note. There is no default
close. There is no "the scan passed later, so close it" path.

```bash
python3 -m stigassess close out/<pack>-poam.json \
    --by "Their Name" --id APPL-26-005001 \
    --kind remediated --note "FileVault enabled; recovery key escrowed; re-scan pass"
```

**Never run `close` yourself.** Never suggest that a later passing scan
closes the item without them saying so. Offer the command; they type
their name.

## Step 7 — Render and hand over

```bash
python3 -m stigassess render out/<pack>-poam.json -o out/
python3 -m stigassess verify out/<pack>-poam.json
```

Deliver the Markdown (readable), JSON (next tool), and CSV (tracker).
Say plainly: these are drafts a person accepted or still needs to
accept; nothing was applied to a system; nothing was marked complete
unless they closed it.

## Example

Input: "draft a POA&M from this scan" with `out/macos-26-v1r3_scan.json`
present.

Actions: `draft` → 2 findings, 0 closed → show CAT I first → user
approves both by name → `render` → deliver.

Output message: "POA&M drafts for macos-26-v1r3: 2 findings (1 CAT I,
1 CAT II), both open under your name, 0 closed. Evaluation gaps were
not drafted. Nothing was applied to the Mac."
