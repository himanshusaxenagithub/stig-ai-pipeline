"""stig-assess — draft POA&M entries from a stig-scan report.

Usage:
  python3 -m stigassess draft   <scan.json> [-o poam.json]
                                [--checklist checklist.json]
                                [--annotations annotations.json]
                                [--include fail[,error,manual]]
  python3 -m stigassess review  <poam.json> [--status unreviewed] [--severity high] [--show]
  python3 -m stigassess approve <poam.json> --by NAME --id ID...
  python3 -m stigassess reject  <poam.json> --by NAME --id ID...
  python3 -m stigassess close   <poam.json> --by NAME --id ID... --kind KIND --note TEXT
  python3 -m stigassess reopen  <poam.json> --by NAME --id ID...
  python3 -m stigassess verify  <poam.json>
  python3 -m stigassess render  <poam.json> [-o DIR] [--format md,json,csv]

Typical flow:
  1. draft    — interpret scan failures as unreviewed POA&M wording
  2. review   — read the drafts
  3. approve  — a named person accepts the wording (item becomes open)
  4. close    — the same person, later, records remediated / risk accepted / N/A

The authoring path never closes a finding. ``close`` is the only command
that can, and it requires a name, a kind, and a note.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from .interpret import DEFAULT_STATUSES, GAP_STATUSES, draft_from_path
from .load import LoadError
from .poam import (
    APPROVED,
    CLOSED,
    CLOSURE_KINDS,
    DRAFT,
    OPEN,
    REJECTED,
    UNREVIEWED,
    PackError,
    PoamPack,
)
from .render import to_csv, to_json, to_markdown

_CAT = {"high": "CAT I", "medium": "CAT II", "low": "CAT III"}


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def cmd_draft(args) -> int:
    include = {p.strip() for p in args.include.split(",") if p.strip()}
    try:
        pack = draft_from_path(
            args.scan,
            checklist=args.checklist,
            annotations=args.annotations,
            include=include,
            pack_id=args.pack_id,
        )
    except (LoadError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    pack.save(args.out)
    s = pack.summary()
    print(f"Drafted {s['total']} POA&M item(s) -> {args.out}")
    print(f"  findings {s['findings']}  evaluation gaps {s['evaluation_gaps']}  "
          f"manual {s['manual']}")
    if s["untrusted"]:
        print(f"  WARNING: {s['untrusted']} draft(s) rest on untrusted scan results")
    print("\nAll entries are DRAFT and UNREVIEWED. Nothing is closed.")
    print(f"  python3 -m stigassess review {args.out} --show")
    return 0


def cmd_review(args) -> int:
    pack = PoamPack.load(args.pack)
    rows = pack.entries
    if args.status:
        rows = [e for e in rows if e.review_status == args.status]
    if args.poam_status:
        rows = [e for e in rows if e.poam_status == args.poam_status]
    if args.severity:
        rows = [e for e in rows if e.severity == args.severity]
    print(f"{len(rows)} item(s) matching\n")
    for e in rows:
        drift = "  [DRIFTED]" if e.is_drifted() else ""
        trust = "" if e.trusted else "  [UNTRUSTED]"
        print(f"{e.stig_id}  {_CAT.get(e.severity, e.severity):7s} "
              f"poam={e.poam_status:6s} review={e.review_status:10s} "
              f"kind={e.kind}{drift}{trust}")
        print(f"    {e.weakness}")
        if args.show:
            print(f"    {e.description}")
            print(f"    recommend: {e.recommendation}")
            if e.caution:
                print(f"    caution: {e.caution}")
            print()
    return 0


def _targets(pack: PoamPack, ids: list[str]):
    targets = []
    for sid in ids:
        e = pack.get(sid)
        if e is None:
            print(f"error: {sid} is not in this pack", file=sys.stderr)
            return None
        targets.append(e)
    return targets


def cmd_approve(args) -> int:
    pack = PoamPack.load(args.pack)
    targets = _targets(pack, args.id)
    if targets is None:
        return 1
    stamp = _stamp()
    for e in targets:
        e.approve(args.by, stamp, args.note or "")
    pack.save(args.pack)
    print(f"Approved {len(targets)} draft(s) as {args.by!r}; wording digests frozen.")
    print("Items are OPEN. They are not closed.")
    for e in targets:
        print(f"  {e.stig_id}  {e.approved_digest[:23]}…")
    return 0


def cmd_reject(args) -> int:
    pack = PoamPack.load(args.pack)
    targets = _targets(pack, args.id)
    if targets is None:
        return 1
    stamp = _stamp()
    for e in targets:
        e.reject(args.by, stamp, args.note or "")
    pack.save(args.pack)
    print(f"Rejected {len(targets)} draft(s) as {args.by!r}.")
    return 0


def cmd_close(args) -> int:
    pack = PoamPack.load(args.pack)
    targets = _targets(pack, args.id)
    if targets is None:
        return 1
    stamp = _stamp()
    for e in targets:
        e.close(args.by, stamp, args.kind, args.note)
    pack.save(args.pack)
    print(f"Closed {len(targets)} item(s) as {args.by!r} ({args.kind}).")
    return 0


def cmd_reopen(args) -> int:
    pack = PoamPack.load(args.pack)
    targets = _targets(pack, args.id)
    if targets is None:
        return 1
    stamp = _stamp()
    for e in targets:
        e.reopen(args.by, stamp, args.note or "")
    pack.save(args.pack)
    print(f"Reopened {len(targets)} item(s) as {args.by!r}.")
    return 0


def cmd_verify(args) -> int:
    pack = PoamPack.load(args.pack)
    s = pack.summary()
    print(f"Pack: {pack.pack_id}  ({pack.stig_title} {pack.stig_version})")
    for k in ("total", "findings", "evaluation_gaps", "manual",
              "draft", "open", "closed", "unreviewed", "approved",
              "rejected", "drifted", "untrusted"):
        print(f"  {k:18s} {s[k]}")
    drifted = [e for e in pack.entries if e.is_drifted()]
    if drifted:
        print("\nDRIFTED — approved wording was modified afterwards:")
        for e in drifted:
            print(f"  {e.stig_id}: approved {e.approved_digest[:23]}… "
                  f"now {e.digest()[:23]}…")
    closed_without_human = [
        e for e in pack.entries
        if e.poam_status == CLOSED and not (e.closed_by and e.closure_note)
    ]
    if closed_without_human:
        print("\nVERIFY FAILED — closed item missing a person or a note:", file=sys.stderr)
        for e in closed_without_human:
            print(f"  {e.stig_id}", file=sys.stderr)
        return 2
    if drifted:
        print("\nVERIFY FAILED", file=sys.stderr)
        return 2
    print("\nVerify OK")
    return 0


def cmd_render(args) -> int:
    pack = PoamPack.load(args.pack)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    formats = {f.strip().lower() for f in args.format.split(",") if f.strip()}
    writers = {
        "md": (f"{pack.pack_id}.md", to_markdown),
        "json": (f"{pack.pack_id}.json", to_json),
        "csv": (f"{pack.pack_id}.csv", to_csv),
    }
    unknown = formats - set(writers)
    if unknown:
        print(f"error: unknown format(s): {', '.join(sorted(unknown))}", file=sys.stderr)
        return 1
    for fmt in sorted(formats):
        name, fn = writers[fmt]
        path = out_dir / name
        path.write_text(fn(pack), encoding="utf-8")
        print(f"  wrote {path}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="stig-assess",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = ap.add_subparsers(dest="command", required=True)

    p = sub.add_parser("draft", help="interpret a scan report as unreviewed POA&M drafts")
    p.add_argument("scan", help="*_scan.json from stig-scan")
    p.add_argument("-o", "--out", default="out/poam.json")
    p.add_argument("--pack-id")
    p.add_argument("--checklist", help="stig-prep *_checklist.json (fix text + explanations)")
    p.add_argument("--annotations", help="filed annotations/*.ai-cache.json")
    p.add_argument(
        "--include",
        default="fail",
        help="comma-separated scan statuses to draft (default: fail). "
             "Add error,manual for evidence gaps. pass is refused.",
    )
    p.set_defaults(func=cmd_draft)

    p = sub.add_parser("review", help="inspect drafted items")
    p.add_argument("pack")
    p.add_argument("--status", choices=[UNREVIEWED, APPROVED, REJECTED])
    p.add_argument("--poam-status", choices=[DRAFT, OPEN, CLOSED])
    p.add_argument("--severity", choices=["high", "medium", "low"])
    p.add_argument("--show", action="store_true")
    p.set_defaults(func=cmd_review)

    p = sub.add_parser("approve", help="accept draft wording under your name (does not close)")
    p.add_argument("pack")
    p.add_argument("--by", required=True)
    p.add_argument("--id", action="append", required=True)
    p.add_argument("--note", default="")
    p.set_defaults(func=cmd_approve)

    p = sub.add_parser("reject", help="reject draft wording")
    p.add_argument("pack")
    p.add_argument("--by", required=True)
    p.add_argument("--id", action="append", required=True)
    p.add_argument("--note", default="")
    p.set_defaults(func=cmd_reject)

    p = sub.add_parser("close", help="human-only: record remediated / risk accepted / N/A")
    p.add_argument("pack")
    p.add_argument("--by", required=True)
    p.add_argument("--id", action="append", required=True)
    p.add_argument("--kind", required=True, choices=list(CLOSURE_KINDS))
    p.add_argument("--note", required=True, help="why this item is being closed")
    p.set_defaults(func=cmd_close)

    p = sub.add_parser("reopen", help="human-only: clear a closure")
    p.add_argument("pack")
    p.add_argument("--by", required=True)
    p.add_argument("--id", action="append", required=True)
    p.add_argument("--note", default="")
    p.set_defaults(func=cmd_reopen)

    p = sub.add_parser("verify", help="integrity audit of a POA&M pack")
    p.add_argument("pack")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("render", help="write Markdown / JSON / CSV")
    p.add_argument("pack")
    p.add_argument("-o", "--out", default="out")
    p.add_argument("--format", default="md,json,csv")
    p.set_defaults(func=cmd_render)

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
