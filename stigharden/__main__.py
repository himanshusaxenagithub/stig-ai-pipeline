"""stig-harden — draft remediation scripts from scan findings.

Usage:
  python3 -m stigharden author  <scan.json> [-o harden.json]
                                [--checklist checklist.json]
                                [--checkpack pack.json]
                                [--platform macos|windows|linux]
  python3 -m stigharden review  <harden.json> [--status unreviewed] [--show]
  python3 -m stigharden approve <harden.json> --by NAME --id ID...
  python3 -m stigharden reject  <harden.json> --by NAME --id ID...
  python3 -m stigharden show    <harden.json> --id ID
  python3 -m stigharden script  <harden.json> [-o DIR]
  python3 -m stigharden verify  <harden.json>
  python3 -m stigharden apply   <harden.json> --by NAME --id ID... --i-have-reviewed
                                [--apply-for-real]

Typical flow:
  1. author  — invert known check shapes into unreviewed scripts
  2. review  — read exactly what would run
  3. approve — freeze the scripts you accept, under your own name
  4. apply   — dry-run by default; --apply-for-real is refused in CI

The authoring path never applies a change.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from .apply import ApplyError, apply_ids
from .author import author_from_path
from .pack import APPROVED, REJECTED, UNREVIEWED, PackError, RemediationPack
from .render import to_json, to_markdown, write_scripts
from .safety import audit

_CAT = {"high": "CAT I", "medium": "CAT II", "low": "CAT III"}


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def cmd_author(args) -> int:
    try:
        pack = author_from_path(
            args.scan,
            checklist=args.checklist,
            annotations=args.annotations,
            checkpack=args.checkpack,
            platform=args.platform,
            pack_id=args.pack_id,
        )
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    pack.save(args.out)
    s = pack.summary()
    print(f"Authored {s['total']} remediation draft(s) -> {args.out}  [platform: {pack.platform}]")
    print(f"  script {s['script']}  manual {s['manual']}  unsupported {s['unsupported']}")
    print("\nAll entries are UNREVIEWED. Nothing has been applied.")
    print(f"  python3 -m stigharden review {args.out} --show")
    return 0


def cmd_review(args) -> int:
    pack = RemediationPack.load(args.pack)
    rows = pack.remediations
    if args.status:
        rows = [r for r in rows if r.review_status == args.status]
    if args.severity:
        rows = [r for r in rows if r.severity == args.severity]
    if args.mode:
        rows = [r for r in rows if r.mode == args.mode]
    print(f"{len(rows)} remediation(s) matching\n")
    for r in rows:
        drift = "  [DRIFTED]" if r.is_drifted() else ""
        print(f"{r.stig_id}  {_CAT.get(r.severity, r.severity):7s} "
              f"{r.review_status:10s} mode={r.mode:11s} "
              f"apply={r.apply_status} shape={r.shape or '-'}{drift}")
        print(f"    {r.title}")
        if args.show:
            if r.author_note:
                print(f"    note: {r.author_note}")
            if r.script:
                print("    --- script ---")
                for line in r.script.splitlines():
                    print(f"    | {line}")
                problems = audit(r.script)
                if problems:
                    print(f"    !! safety gate: {'; '.join(problems)}")
            else:
                print(f"    (no script — {r.author_note})")
            print()
    return 0


def _targets(pack: RemediationPack, ids: list[str]):
    targets = []
    for sid in ids:
        r = pack.get(sid)
        if r is None:
            print(f"error: {sid} is not in this pack", file=sys.stderr)
            return None
        targets.append(r)
    return targets


def cmd_approve(args) -> int:
    pack = RemediationPack.load(args.pack)
    targets = _targets(pack, args.id)
    if targets is None:
        return 1
    stamp = _stamp()
    for r in targets:
        r.approve(args.by, stamp, args.note or "")
    pack.save(args.pack)
    print(f"Approved {len(targets)} script(s) as {args.by!r}; content digests frozen.")
    print("Nothing was applied.")
    for r in targets:
        print(f"  {r.stig_id}  {r.approved_digest[:23]}…")
    return 0


def cmd_reject(args) -> int:
    pack = RemediationPack.load(args.pack)
    targets = _targets(pack, args.id)
    if targets is None:
        return 1
    stamp = _stamp()
    for r in targets:
        r.reject(args.by, stamp, args.note or "")
    pack.save(args.pack)
    print(f"Rejected {len(targets)} remediation(s) as {args.by!r}.")
    return 0


def cmd_show(args) -> int:
    pack = RemediationPack.load(args.pack)
    r = pack.get(args.id)
    if r is None:
        print(f"error: {args.id} is not in this pack", file=sys.stderr)
        return 1
    print(f"# {r.stig_id}  review={r.review_status}  apply={r.apply_status}")
    print(f"# digest {r.digest()}")
    print(r.script or f"# no script ({r.mode}: {r.author_note})")
    return 0


def cmd_script(args) -> int:
    pack = RemediationPack.load(args.pack)
    dest = Path(args.out)
    written = write_scripts(pack, dest)
    md = dest / f"{pack.pack_id}.md"
    js = dest / f"{pack.pack_id}.json"
    md.write_text(to_markdown(pack), encoding="utf-8")
    js.write_text(to_json(pack), encoding="utf-8")
    print(f"Wrote {len(written)} script file(s) and reports -> {dest}")
    print("Nothing was executed.")
    for p in written:
        print(f"  {p}")
    return 0


def cmd_verify(args) -> int:
    pack = RemediationPack.load(args.pack)
    s = pack.summary()
    print(f"Pack: {pack.pack_id}  ({pack.stig_title} {pack.stig_version})")
    for k in ("total", "script", "manual", "unsupported", "unreviewed",
              "approved", "rejected", "drifted", "never_applied", "applied", "dry_run"):
        print(f"  {k:16s} {s[k]}")
    drifted = [r for r in pack.remediations if r.is_drifted()]
    if drifted:
        print("\nDRIFTED — approved script was modified afterwards:")
        for r in drifted:
            print(f"  {r.stig_id}: approved {r.approved_digest[:23]}… "
                  f"now {r.digest()[:23]}…")
    unsafe = [(r, audit(r.script)) for r in pack.remediations if r.script]
    unsafe = [(r, p) for r, p in unsafe if p]
    if unsafe:
        print(f"\nSafety gate objections ({len(unsafe)}):")
        for r, p in unsafe:
            print(f"  {r.stig_id} [{r.review_status}]: {'; '.join(p)}")
    bad = bool(drifted) or any(r.review_status == APPROVED for r, _ in unsafe)
    if bad:
        print("\nVERIFY FAILED", file=sys.stderr)
        return 2
    print("\nVerify OK")
    return 0


def cmd_apply(args) -> int:
    pack = RemediationPack.load(args.pack)
    try:
        report = apply_ids(
            pack,
            args.id,
            by=args.by,
            at=_stamp(),
            i_have_reviewed=args.i_have_reviewed,
            apply_for_real=args.apply_for_real,
        )
    except ApplyError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    pack.save(args.pack)
    for row in report.applied:
        print(f"{row.stig_id}: {row.detail}")
        if row.stdout.strip():
            print(row.stdout.rstrip())
    if args.apply_for_real:
        print("Executed on this host. Re-scan to see whether the finding cleared.")
    else:
        print("Dry-run only. Nothing was executed. Pass --apply-for-real to apply.")
    return 0 if report.ok else 2


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="stig-harden",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = ap.add_subparsers(dest="command", required=True)

    p = sub.add_parser("author", help="derive candidate remediations from a scan")
    p.add_argument("scan")
    p.add_argument("-o", "--out", default="out/harden.json")
    p.add_argument("--pack-id")
    p.add_argument("--checklist")
    p.add_argument("--annotations")
    p.add_argument("--checkpack", help="stig-scan check pack (expected_source, command)")
    p.add_argument("--platform", choices=["macos", "windows", "linux"])
    p.set_defaults(func=cmd_author)

    p = sub.add_parser("review", help="inspect drafted scripts")
    p.add_argument("pack")
    p.add_argument("--status", choices=[UNREVIEWED, APPROVED, REJECTED])
    p.add_argument("--severity", choices=["high", "medium", "low"])
    p.add_argument("--mode", choices=["script", "manual", "unsupported"])
    p.add_argument("--show", action="store_true")
    p.set_defaults(func=cmd_review)

    p = sub.add_parser("approve", help="freeze scripts you have read (does not apply)")
    p.add_argument("pack")
    p.add_argument("--by", required=True)
    p.add_argument("--id", action="append", required=True)
    p.add_argument("--note", default="")
    p.set_defaults(func=cmd_approve)

    p = sub.add_parser("reject", help="mark remediations as not to be applied")
    p.add_argument("pack")
    p.add_argument("--by", required=True)
    p.add_argument("--id", action="append", required=True)
    p.add_argument("--note", default="")
    p.set_defaults(func=cmd_reject)

    p = sub.add_parser("show", help="print one script (dry-run / review)")
    p.add_argument("pack")
    p.add_argument("--id", required=True)
    p.set_defaults(func=cmd_show)

    p = sub.add_parser("script", help="write script files and reports; do not execute")
    p.add_argument("pack")
    p.add_argument("-o", "--out", default="out/remediations")
    p.set_defaults(func=cmd_script)

    p = sub.add_parser("verify", help="integrity and safety audit")
    p.add_argument("pack")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("apply", help="dry-run by default; --apply-for-real is refused in CI")
    p.add_argument("pack")
    p.add_argument("--by", required=True)
    p.add_argument("--id", action="append", required=True)
    p.add_argument("--i-have-reviewed", action="store_true", dest="i_have_reviewed")
    p.add_argument("--apply-for-real", action="store_true",
                   help="execute approved scripts; refused when CI=true")
    p.set_defaults(func=cmd_apply)

    args = ap.parse_args(argv)
    try:
        return args.func(args)
    except PackError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except FileNotFoundError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
