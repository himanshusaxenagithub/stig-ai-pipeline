---
name: stig-harden
description: Draft human-reviewed remediation scripts from STIG scan findings. Use this skill whenever the user asks to fix STIG failures, generate a remediation script, harden a Mac or Windows PC, or says anything like "draft the fixes", "how do I remediate these findings", "write the defaults write / Set-ItemProperty" — even if they do not name the tool. It drives stig-harden (Module 4). It never applies an unreviewed script and never runs --apply-for-real on the user's behalf.
---

# Draft remediations — never apply unreviewed

Turn scan failures into platform-appropriate fix *drafts* a person can
read, approve, and only then choose to run. You are the assistant that
authors and explains; the human approves; the module refuses to apply
anything that is unreviewed, drifted, or running in CI. The pipeline is:
locate the scan → author drafts → review with the user → they approve →
they dry-run → they decide whether to apply.

The guiding principle: **AI never applies an unreviewed remediation.**
Show the script. Do not run it. `apply` without `--apply-for-real` is a
dry-run. `--apply-for-real` is refused in CI and still needs a name and
`--i-have-reviewed`.

## Step 1 — Locate the inputs

**The scan.** A `*_scan.json` from `python3 -m stigscan scan …`. If
there is none, drive the matching stig-scan-* skill first.

**Optional.** A stig-prep checklist (fix text) and the stig-scan check
pack (expected_source). Those make inversion more accurate.

**The helper.** `skills/stig-harden/scripts/harden.py`. Zero
dependencies, Python 3.9+.

## Step 2 — Author drafts

```bash
python3 -m stigharden author out/<pack>_scan.json -o out/<pack>-harden.json \
    --checklist out/*_checklist.json \
    --checkpack checkpacks/<pack>.json
```

`--platform macos|windows|linux` if the scan did not record one.
Tell the user the counts: script / manual / unsupported. Known invertible
shapes:

| Platform | Check shape | Draft |
|---|---|---|
| Windows | `Get-ItemProperty -Path … -Name …` | `Set-ItemProperty` of the expected value |
| Windows | `auditpol /get /subcategory:"…"` | `auditpol /set` when Success/Failure is clear |
| macOS | `defaults read DOMAIN KEY` | `defaults write` of the expected value |
| macOS | `launchctl print` + “disable” | `launchctl bootout` (low confidence) |
| Linux | `sysctl KEY` + “set to N” | `sysctl -w KEY=N` (persist is left to a person) |
| Linux | `systemctl is-enabled/is-active` | `enable` or `mask` (low confidence) |
| Any | STIG fix text already has `defaults write` / `Set-ItemProperty` / `sysctl -w` | that command |

High-risk forms (SIP, FileVault, `secedit /configure`, firmware) stay
**manual**. Destructive verbs, network clients, and nested interpreters
are refused. Passes are not drafted.

## Step 3 — Refine (optional)

```bash
python3 skills/stig-harden/scripts/harden.py next out/<pack>-harden.json --limit 10
```

For each item write one object:

- `stig_id` — copied verbatim.
- `script` — the exact commands, or `""` for a manual item.
- `rationale` — why this remediates the failed check, under 120 words.
- `mode` — `script` or `manual` (never `applied`).

**Do not include `apply_status`, `review_status`, `applied_by`, or
`approved_digest`.** The merge step rejects the whole batch if those
keys appear, if the script fails the safety gate, or if a high-risk
form is filed as `script`.

```bash
python3 skills/stig-harden/scripts/harden.py merge out/<pack>-harden.json batch.json --model <your-name>
```

## Step 4 — Review with the user

```bash
python3 -m stigharden review out/<pack>-harden.json --show
python3 -m stigharden show out/<pack>-harden.json --id APPL-26-002064
```

Read the script verbatim. Do not paraphrase a command. Say the
confidence and the shape it came from.

## Step 5 — The human approves

```bash
python3 -m stigharden approve out/<pack>-harden.json --by "Their Name" --id WN11-00-000031
```

Approval freezes a digest. **It does not apply the script.**

**Never run `approve` yourself.** Never run `apply`. If they ask you to
fix the machine, give them `show` and the dry-run command.

## Step 6 — Dry-run, then they decide

```bash
python3 -m stigharden apply out/<pack>-harden.json \
    --by "Their Name" --id WN11-00-000031 --i-have-reviewed
```

That is a dry-run. `--apply-for-real` executes and is **refused in CI**.
Do not pass `--apply-for-real`. Do not run apply in GitHub Actions or
any other automated job.

```bash
python3 -m stigharden script out/<pack>-harden.json -o out/remediations/
python3 -m stigharden verify out/<pack>-harden.json
```

`script` writes `.sh` / `.ps1` files for review. It does not execute
them.

## Example

Input: "draft fixes for the failed Windows registry checks."

Actions: `author --platform windows` → 3 script drafts, 1 manual → show
each `Set-ItemProperty` → user approves two by name → `apply` dry-run →
deliver the script files.

Output message: "3 registry drafts and 1 manual item. 2 approved under
your name. Dry-run only; nothing was applied to the PC."
