"""stig-scan — run frozen, human-reviewed STIG checks against a live system.

Usage:
  python3 -m stigscan author <checklist.json> -o <pack.json> [--pack-id ID]
  python3 -m stigscan review <pack.json> [--status unreviewed] [--severity high] [--show]
  python3 -m stigscan approve <pack.json> --by NAME (--id ID... | --all-high-confidence)
  python3 -m stigscan reject  <pack.json> --by NAME --id ID... [--note TEXT]
  python3 -m stigscan verify  <pack.json>
  python3 -m stigscan scan    <pack.json> [-o DIR] [--fixtures DIR] [--record DIR]
                                          [--include-unreviewed] [--severity high]

Typical flow:
  1. author   — derive candidate checks from the stig-prep checklist
  2. review   — read what will be executed
  3. approve  — freeze the checks you accept, under your own name
  4. scan     — execute only what is approved and unmodified since approval
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date, datetime, timezone
from pathlib import Path

from .extract import build_pack
from .pack import CheckPack, PackError, APPROVED, UNREVIEWED, REJECTED, MODE_SHELL
from .report import to_json, to_markdown
from .runner import ShellRunner, FixtureRunner
from .safety import audit
from . import platforms
from .scan import run_scan, SEVERITY_LABEL


def _today() -> str:
    return date.today().isoformat()


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def cmd_author(args) -> int:
    checklist = json.loads(Path(args.checklist).read_text(encoding="utf-8"))
    pack_id = args.pack_id or Path(args.out).stem
    platform = args.platform or platforms.detect()
    prof = platforms.get(platform)
    pack = build_pack(checklist, pack_id, _today(), platform=prof.NAME)
    pack.save(args.out)
    s = pack.summary()
    print(f"Authored {s['total']} candidate checks -> {args.out}  [platform: {prof.NAME}]")
    if not prof.EXTRACTOR:
        print(f"  NOTE: no extractor for {prof.NAME!r} in this release; every rule is "
              "UNSUPPORTED and needs human or AI authoring")
    print(f"  {sum(1 for c in pack.checks if c.mode == MODE_SHELL)} reducible to a command, "
          f"{s['manual']} manual, {s['unsupported']} unsupported")
    conf = {}
    for c in pack.checks:
        conf[c.author_confidence] = conf.get(c.author_confidence, 0) + 1
    print(f"  confidence: " + ", ".join(f"{k}={v}" for k, v in sorted(conf.items())))
    print("\nAll entries are UNREVIEWED. Nothing will execute until you approve it:")
    print(f"  python3 -m stigscan review {args.out} --show")
    return 0


def cmd_review(args) -> int:
    pack = CheckPack.load(args.pack)
    rows = pack.checks
    if args.status:
        rows = [c for c in rows if c.review_status == args.status]
    if args.severity:
        rows = [c for c in rows if c.severity == args.severity]
    if args.confidence:
        rows = [c for c in rows if c.author_confidence == args.confidence]
    if args.mode:
        rows = [c for c in rows if c.mode == args.mode]

    print(f"{len(rows)} check(s) matching\n")
    for c in rows:
        drift = "  [DRIFTED]" if c.is_drifted() else ""
        print(f"{c.stig_id}  {SEVERITY_LABEL.get(c.severity, c.severity):7s} "
              f"{c.review_status:10s} conf={c.author_confidence:6s} mode={c.mode}{drift}")
        print(f"    {c.title}")
        if args.show:
            if c.author_note:
                print(f"    note: {c.author_note}")
            if c.mode == MODE_SHELL:
                print(f"    expect: {c.comparator} {c.expected!r}   "
                      f"(from: {c.expected_source[:80]!r})")
                if c.requires_root:
                    print("    requires root")
                print("    --- command ---")
                for line in c.command.splitlines():
                    print(f"    | {line}")
                problems = audit(c.command, pack.platform)
                if problems:
                    print(f"    !! safety gate: {'; '.join(problems)}")
            else:
                print(f"    (no command — {c.author_note})")
            print()
    return 0


def cmd_approve(args) -> int:
    pack = CheckPack.load(args.pack)
    targets: list = []
    if args.all_high_confidence:
        targets = [c for c in pack.checks
                   if c.mode == MODE_SHELL and c.author_confidence == "high"
                   and c.review_status != APPROVED and not audit(c.command, pack.platform)]
    for sid in args.id or []:
        c = pack.get(sid)
        if c is None:
            print(f"error: {sid} is not in this pack", file=sys.stderr)
            return 1
        targets.append(c)

    if not targets:
        print("nothing to approve")
        return 0

    stamp = _stamp()
    for c in targets:
        try:
            c.approve(args.by, stamp, args.note or "")
        except PackError as e:
            print(f"error: {e}", file=sys.stderr)
            return 1
    pack.save(args.pack)
    print(f"Approved {len(targets)} check(s) as {args.by!r}; content digests frozen.")
    for c in targets:
        print(f"  {c.stig_id}  {c.approved_digest[:23]}…")
    return 0


def cmd_reject(args) -> int:
    pack = CheckPack.load(args.pack)
    stamp = _stamp()
    n = 0
    for sid in args.id:
        c = pack.get(sid)
        if c is None:
            print(f"error: {sid} is not in this pack", file=sys.stderr)
            return 1
        c.reject(args.by, stamp, args.note or "")
        n += 1
    pack.save(args.pack)
    print(f"Rejected {n} check(s) as {args.by!r}.")
    return 0


def cmd_verify(args) -> int:
    pack = CheckPack.load(args.pack)
    s = pack.summary()
    print(f"Pack: {pack.pack_id}  ({pack.stig_title} {pack.stig_version})")
    for k in ("total", "approved", "unreviewed", "rejected", "manual", "unsupported",
              "drifted", "runnable"):
        print(f"  {k:12s} {s[k]}")

    drifted = [c for c in pack.checks if c.is_drifted()]
    if drifted:
        print("\nDRIFTED — approved content was modified afterwards:")
        for c in drifted:
            print(f"  {c.stig_id}: approved {c.approved_digest[:23]}… "
                  f"now {c.digest()[:23]}…")

    unsafe = [(c, audit(c.command, pack.platform)) for c in pack.checks
              if c.mode == MODE_SHELL and c.command]
    unsafe = [(c, p) for c, p in unsafe if p]
    if unsafe:
        print(f"\nSafety gate objections ({len(unsafe)}):")
        for c, p in unsafe:
            print(f"  {c.stig_id} [{c.review_status}]: {'; '.join(p)}")

    bad = bool(drifted) or any(c.review_status == APPROVED for c, _ in unsafe)
    if bad:
        print("\nVERIFY FAILED", file=sys.stderr)
        return 2
    print("\nVerify OK")
    return 0


def cmd_scan(args) -> int:
    pack = CheckPack.load(args.pack)
    prof = platforms.get(pack.platform)
    if args.fixtures:
        runner = FixtureRunner(args.fixtures)
    else:
        if not prof.SUPPORTED:
            print(f"error: scanning is not supported for platform {prof.NAME!r} in this "
                  "release (fixtures replay still works)", file=sys.stderr)
            return 2
        here = platforms.detect()
        if here != prof.NAME:
            print(f"error: this pack was authored for {prof.NAME!r} but this host is "
                  f"{here!r}; refusing to run its commands here", file=sys.stderr)
            return 2
        runner = ShellRunner(timeout=args.timeout, record_dir=args.record, platform=prof.NAME)

    report = run_scan(
        pack, runner,
        include_unreviewed=args.include_unreviewed,
        only_ids=set(args.id) if args.id else None,
        severities={args.severity} if args.severity else None,
    )

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / f"{pack.pack_id}_scan.json").write_text(to_json(report), encoding="utf-8")
    (out_dir / f"{pack.pack_id}_scan.md").write_text(to_markdown(report), encoding="utf-8")

    c = report.counts()
    print(f"Scanned {pack.pack_id} on {report.host.get('hostname')}")
    print(f"  pass {c['pass']}  fail {c['fail']}  error {c['error']}  "
          f"manual {c['manual']}  skipped {c['skipped']}")
    cat1 = report.cat1_failures()
    if cat1:
        print(f"  CAT I failures: {len(cat1)}")
        for r in cat1:
            print(f"    {r.stig_id}  {r.title[:64]}")
    print(f"  wrote {out_dir / (pack.pack_id + '_scan.json')}")
    print(f"  wrote {out_dir / (pack.pack_id + '_scan.md')}")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="stig-scan", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)

    p = sub.add_parser("author", help="derive candidate checks from a stig-prep checklist")
    p.add_argument("checklist")
    p.add_argument("-o", "--out", required=True)
    p.add_argument("--pack-id")
    p.add_argument("--platform", choices=list(platforms.NAMES),
                   help="profile to author for (default: the platform this command runs on)")
    p.set_defaults(func=cmd_author)

    p = sub.add_parser("review", help="inspect what a pack would execute")
    p.add_argument("pack")
    p.add_argument("--status", choices=[UNREVIEWED, APPROVED, REJECTED])
    p.add_argument("--severity", choices=["high", "medium", "low"])
    p.add_argument("--confidence", choices=["high", "medium", "low"])
    p.add_argument("--mode", choices=["shell", "manual", "unsupported"])
    p.add_argument("--show", action="store_true", help="print the full command text")
    p.set_defaults(func=cmd_review)

    p = sub.add_parser("approve", help="freeze checks you have read and accept")
    p.add_argument("pack")
    p.add_argument("--by", required=True, help="your name — recorded in the pack")
    p.add_argument("--id", action="append")
    p.add_argument("--all-high-confidence", action="store_true")
    p.add_argument("--note", default="")
    p.set_defaults(func=cmd_approve)

    p = sub.add_parser("reject", help="mark checks as not to be executed")
    p.add_argument("pack")
    p.add_argument("--by", required=True)
    p.add_argument("--id", action="append", required=True)
    p.add_argument("--note", default="")
    p.set_defaults(func=cmd_reject)

    p = sub.add_parser("verify", help="integrity and safety audit of a pack")
    p.add_argument("pack")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("scan", help="execute approved checks and write a report")
    p.add_argument("pack")
    p.add_argument("-o", "--out", default="out")
    p.add_argument("--fixtures", help="replay recorded output instead of running commands")
    p.add_argument("--record", help="record live command output into this directory")
    p.add_argument("--include-unreviewed", action="store_true",
                   help="development only; results are marked untrusted")
    p.add_argument("--severity", choices=["high", "medium", "low"])
    p.add_argument("--id", action="append")
    p.add_argument("--timeout", type=int, default=30)
    p.set_defaults(func=cmd_scan)

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
