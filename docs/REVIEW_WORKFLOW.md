# Check review workflow

A check pack is executable security policy. This document describes how a
candidate check becomes an approved one, and why the process is shaped the
way it is.

## Why there is a review step at all

DISA publishes STIG check text as prose written for a human auditor. Turning
that prose into something a machine can run is an interpretive act, and
interpretation can be wrong in ways that are invisible in the output: a
command that measures the wrong thing still returns a clean `1`.

That risk does not go away by having a careful engineer do the interpreting,
and it gets sharper when a language model does it. So rather than trying to
make the authoring step trustworthy, the design assumes it is not, and puts
a human gate between authoring and execution.

## The four states

| State | Meaning | Executes? |
|---|---|---|
| `unreviewed` | Authored but not read by a human | No |
| `approved` | A named human read the command and accepted it | Yes |
| `rejected` | A named human read it and refused it | No |
| *drifted* | Approved, then edited | No — must be re-reviewed |

Drift is derived, not stored. `approve()` records a SHA-256 digest over the
stig_id, mode, command, comparator, expected value, and root requirement.
Every load recomputes it. A mismatch means the approval refers to bytes that
no longer exist, so the approval is void.

This is what makes AI-authored content auditable. Provenance alone ("a model
wrote this") is not enough — you need a guarantee that the thing a human
signed off on is the thing that ran.

## Reviewing

```bash
python3 -m stigscan review <pack> --severity high --show
```

For each check, read four things:

1. **The command.** Does it measure what the rule's title claims? The most
   common authoring error is a command that tests a *related* setting.
2. **The expected value and its source.** `expected_source` quotes the STIG
   sentence the value came from verbatim. Check that the quote says what the
   comparator does — `is not "1"` means `equals 1`, and an inverted
   comparator turns a finding into a pass.
3. **The safety gate line.** If `!!` appears, the gate objected. Decide
   whether the objection is a false positive worth an allowlist change, or a
   real problem worth rejecting the check.
4. **`requires_root`.** A check needing privilege that does not declare it
   will silently skip.

Confidence ratings from the extractor tell you where to spend attention:

- `high` — single-line command, clean acceptance sentence, gate clean.
- `medium` — multi-line snippet. Confirm it is self-contained: shell
  fragments lifted from a longer procedure sometimes depend on a variable
  set in a sentence the extractor discarded.
- `low` — the gate objected, or the check resisted reduction. Read these
  first; they are where errors live.

## Approving

```bash
python3 -m stigscan approve <pack> --by "Your Name" \
    --id APPL-26-005001 --id APPL-26-002064 --note "verified against V1R3 p.42"
```

Use your real name. The pack records who approved what and when, and that
record is the point.

`--all-high-confidence` bulk-approves every high-confidence check whose
command passes the safety gate. It is a convenience for re-authoring an
already-reviewed pack against a new STIG release. Do not use it on a pack
you have not read.

## Re-authoring against a new STIG release

When DISA ships V1R4, author a fresh pack and diff it against the reviewed
one. Checks whose digest is unchanged carry their approval forward; checks
whose command changed come back as unreviewed. Only the delta needs review,
which is what makes the workflow sustainable across releases.

## What is deliberately not automated

- **Approval.** There is no flag that approves everything.
- **Remediation.** The scanner never changes configuration. Fixing findings
  is module 4's job, behind its own gates.
- **Judgment about applicability.** A check that passes on a host where the
  rule does not apply is still a misleading result. The scanner reports what
  it measured; deciding what that means for a given system is module 3's job,
  and ultimately a person's.
