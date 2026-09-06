---
name: stig-scan-macos
description: Check a Mac against its DISA STIG and report, in plain English, where it stands. Use this skill whenever the user asks to scan, audit, assess or check a Mac against a STIG, wants to know which STIG rules a macOS system passes or fails, mentions a checkpack, or says anything like "scan this Mac", "how compliant is this machine", "run the STIG checks" — even if they do not name the tool. It drives stig-scan (Module 2) on the macOS profile, never approves a check on the user's behalf, and never runs anything a human has not approved.
---

# Scan a Mac against its STIG

Turn the macOS STIG into a list of pass / fail / not-evaluated for the machine
in front of you. You are the assistant that reads, explains and reports; the
human approves what runs; the scanner runs only what was approved and only
if it passes the static safety gate. The pipeline is:
locate → author (if needed) → verify → review with the user → they approve →
scan → explain the results.

The guiding principle: **nothing executes unless a named human has read it
and approved it, and nothing that can change the system ever executes.**
The scanner enforces both; your job is to make the human step easy and honest.

## Step 1 — Locate the inputs

You need the stig-scan module and a checklist or a checkpack.

**The module.** `python3 -c "import stigscan"` from the stig-ai-pipeline
repository root. If it is missing, clone
`https://github.com/himanshusaxenagithub/stig-ai-pipeline`.

**The checkpack.** Look in `checkpacks/` for the macOS pack matching the STIG
version the user cares about (for example `macos-26-v1r3.json`). If there is
none, author one from the stig-prep checklist:

```bash
python3 -m stigprep parse U_Apple_macOS_26_V1R3_STIG.zip --format json
python3 -m stigscan author out/*macos*_checklist.json -o checkpacks/macos-26-v1r3.json --platform macos
```

Tell the user what `author` printed: how many rules reduced to a command,
how many are manual (GUI or interview), how many could not be reduced. All
of them are UNREVIEWED.

## Step 2 — Verify the pack

```bash
python3 -m stigscan verify checkpacks/macos-26-v1r3.json
```

Report the counts (approved / unreviewed / rejected / drifted) and any
safety-gate objections. If anything is DRIFTED, say so first: an approved
check was edited after approval and will not run until re-reviewed.

## Step 3 — Review with the user

Show the user exactly what would run, highest severity first:

```bash
python3 -m stigscan review checkpacks/macos-26-v1r3.json --severity high --show
```

For each check they ask about, read them the command, the expected result,
and the sentence from the STIG it was taken from (`expected_source`). If
`author_confidence` is `medium` or `low`, say why (the `author_note`). Do not
paraphrase a command; show it verbatim.

## Step 4 — The human approves

Give the user the command to approve the checks they have read, under their
own name:

```bash
python3 -m stigscan approve checkpacks/macos-26-v1r3.json --by "Their Name" --id APPL-26-000001 --id APPL-26-000002
```

`--all-high-confidence` approves every high-confidence check at once; offer
it only after they have looked at the list.

**Never run `approve` yourself.** Approval records a person's name against a
digest of the exact bytes that will execute; a machine's name there is worth
nothing. If the user asks you to approve for them, explain that and give
them the command.

## Step 5 — Scan

```bash
python3 -m stigscan scan checkpacks/macos-26-v1r3.json -o out/ --record evidence/$(date +%F)/
```

Checks marked `requires_root` are skipped unless the scan is run with `sudo`;
tell the user which ones and let them decide. `--record` keeps the raw
output so the scan can be replayed later with `--fixtures` — always record.

Never pass `--include-unreviewed` unless the user explicitly asks for it,
and if they do, say that every result from an unreviewed check is flagged
untrusted in the report.

## Step 6 — Explain the results

Open `out/<pack>_scan.md` and lead with the coverage line, verbatim:

> N of M rules (P%) were actually evaluated on this host.

Then, in this order: CAT I failures; other failures; errors (checks that
could not produce a result, and why); what was skipped and why. Never fold
errors or skips into "fail" and never present a partial scan as a
compliance percentage.

For every failure, if the stig-explain annotations exist for this STIG
(`annotations/`), give the plain-English summary, triage rating and caution
for that rule so the user knows what it means and how hard it is to fix.

End by saying plainly: this scan evaluated what a human approved and nothing
else; the decisions about what to fix, in what order, and what to accept as
a risk stay with them.

## Example

Input: "scan this Mac against the STIG" on a Mac with the repository present.

Actions: `verify` → 160 checks, 0 approved → show the 12 CAT I checks with
`review --severity high --show` → user approves 9 by name → `scan --record` →
report: "9 of 160 rules were actually evaluated; 7 pass, 2 fail (APPL-26-000012
FileVault not enabled — risky-change: enabling it needs the recovery key
escrowed first; APPL-26-002064 …); 151 not evaluated (148 unreviewed, 3 need
root)."
