"""stig-prep — turn a DISA STIG package into an engineer-friendly checklist.

Usage:
  python3 -m stigprep parse <stig.zip | xccdf.xml> [options]

Options:
  -o, --out DIR        output directory (default: ./out)
  --format LIST        comma-separated: md,json,csv (default: all three)
  --explain            attach plain-English explanations filed in annotations/
                       un-cached rules (useful for a cheap test run)

Examples:
  python3 -m stigprep parse U_Apple_macOS_15_V1R7_STIG.zip
  python3 -m stigprep parse U_MS_Windows_11_V2R9_STIG.zip --explain
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from .parser import parse_stig
from .render import to_markdown, to_json, to_csv
from .explain import explain, ExplainError


def _slug(text: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9]+", "_", text).strip("_").lower() or "stig"
    return slug[:48].rstrip("_")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="stig-prep",
        description="Turn a DISA STIG package into an engineer-friendly checklist.",
    )
    sub = ap.add_subparsers(dest="command", required=True)

    p = sub.add_parser("parse", help="parse a STIG and generate checklists")
    p.add_argument("stig", help="path to DISA STIG .zip or XCCDF .xml")
    p.add_argument("-o", "--out", default="out", help="output directory")
    p.add_argument("--format", default="md,json,csv",
                   help="comma-separated output formats (md,json,csv)")
    p.add_argument("--explain", action="store_true",
                   help="attach plain-English explanations filed in annotations/ "
                        "(produced with the stig-explain skill)")

    args = ap.parse_args(argv)

    stig_path = Path(args.stig)
    if not stig_path.exists():
        print(f"error: {stig_path} not found", file=sys.stderr)
        return 1

    try:
        benchmark = parse_stig(stig_path)
    except Exception as e:
        print(f"error: could not parse {stig_path.name}: {e}", file=sys.stderr)
        return 1

    counts = {"high": 0, "medium": 0, "low": 0}
    for r in benchmark.rules:
        counts[r.severity] = counts.get(r.severity, 0) + 1
    print(f"Parsed: {benchmark.title}")
    print(f"  {len(benchmark.rules)} rules — "
          f"{counts.get('high', 0)} CAT I, {counts.get('medium', 0)} CAT II, "
          f"{counts.get('low', 0)} CAT III")

    if args.explain:
        n = explain(benchmark, stig_path)
        print(f"  explanations attached: {n} of {len(benchmark.rules)} rules")

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    base = _slug(benchmark.title or stig_path.stem)

    formats = {f.strip().lower() for f in args.format.split(",") if f.strip()}
    writers = {
        "md": (f"{base}_checklist.md", to_markdown),
        "json": (f"{base}_checklist.json", to_json),
        "csv": (f"{base}_checklist.csv", to_csv),
    }
    unknown = formats - set(writers)
    if unknown:
        print(f"error: unknown format(s): {', '.join(sorted(unknown))}",
              file=sys.stderr)
        return 1

    for fmt in sorted(formats):
        name, fn = writers[fmt]
        path = out_dir / name
        path.write_text(fn(benchmark), encoding="utf-8")
        print(f"  wrote {path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
