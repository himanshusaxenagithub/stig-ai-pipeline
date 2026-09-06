#!/usr/bin/env python3
"""Build a formatted Excel implementation tracker from a stig-prep JSON checklist.

Usage:
    python3 make_tracker.py <checklist.json> <output.xlsx>

Input:  the *_checklist.json produced by `python3 -m stigprep parse <stig>`.
Output: an .xlsx workbook with three sheets:
    Summary  - STIG metadata + counts by severity and status
    Tracker  - one row per rule: ID, CAT, title, status dropdown, owner, notes
    Details  - full discussion / check / fix text per rule, for reference

Zero third-party deps beyond openpyxl. No formulas that need recalculation:
summary counts are written as values at build time.
"""

import json
import sys
from pathlib import Path

from openpyxl import Workbook
from openpyxl.styles import Alignment, Border, Font, PatternFill, Side
from openpyxl.utils import get_column_letter
from openpyxl.worksheet.datavalidation import DataValidation

# GitHub-dark-inspired palette, readable in Excel's light UI
HEADER_FILL = PatternFill("solid", fgColor="1F2937")
HEADER_FONT = Font(color="FFFFFF", bold=True, size=11)
CAT_FILLS = {
    "CAT I": PatternFill("solid", fgColor="FDE2E2"),
    "CAT II": PatternFill("solid", fgColor="FFF4D6"),
    "CAT III": PatternFill("solid", fgColor="DDEBF7"),
}
CAT_FONTS = {
    "CAT I": Font(color="B91C1C", bold=True),
    "CAT II": Font(color="92600A", bold=True),
    "CAT III": Font(color="1D4ED8", bold=True),
}
THIN = Side(style="thin", color="D1D5DB")
BORDER = Border(left=THIN, right=THIN, top=THIN, bottom=THIN)
STATUSES = ["Open", "In progress", "Implemented", "Not applicable", "Risk accepted"]


def die(msg):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)


def load(path):
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        die(f"cannot read {path}: {e}")
    if "rules" not in data or not isinstance(data["rules"], list):
        die("input JSON has no 'rules' list - is this a stig-prep checklist file?")
    return data


def anomalies(rules):
    """Return a list of human-readable warnings the caller should surface."""
    warns = []
    seen = set()
    for r in rules:
        sid = r.get("stig_id") or r.get("rule_id") or "?"
        if sid in seen:
            warns.append(f"duplicate rule id: {sid}")
        seen.add(sid)
        if not r.get("severity"):
            warns.append(f"{sid}: missing severity")
        if not (r.get("check_text") or "").strip():
            warns.append(f"{sid}: empty check text")
        if not (r.get("fix_text") or "").strip():
            warns.append(f"{sid}: empty fix text")
    if not rules:
        warns.append("zero rules parsed - wrong file?")
    return warns


def style_header(ws, ncols, row=1):
    for c in range(1, ncols + 1):
        cell = ws.cell(row=row, column=c)
        cell.fill = HEADER_FILL
        cell.font = HEADER_FONT
        cell.alignment = Alignment(vertical="center")
        cell.border = BORDER


def build(data, out_path):
    rules = data["rules"]
    warns = anomalies(rules)
    cat_order = {"CAT I": 0, "CAT II": 1, "CAT III": 2}
    rules = sorted(rules, key=lambda r: (cat_order.get(r.get("cat", ""), 3),
                                         r.get("stig_id") or ""))

    wb = Workbook()

    # ---- Summary ----
    s = wb.active
    s.title = "Summary"
    s.column_dimensions["A"].width = 26
    s.column_dimensions["B"].width = 70
    meta = [
        ("STIG", data.get("title", "")),
        ("Version", str(data.get("version", ""))),
        ("Release info", data.get("release_info", "")),
        ("Source file", data.get("source_file", "")),
        ("Total rules", len(rules)),
    ]
    for cat in ("CAT I", "CAT II", "CAT III"):
        meta.append((f"{cat} rules", sum(1 for r in rules if r.get("cat") == cat)))
    meta.append(("Parser warnings", len(warns)))
    n_ai = sum(1 for r in rules if (r.get("ai") or {}).get("summary"))
    if n_ai:
        meta.append(("Rules with plain-English explanation", f"{n_ai} of {len(rules)}"))
    for i, (k, v) in enumerate(meta, start=1):
        s.cell(row=i, column=1, value=k).font = Font(bold=True)
        s.cell(row=i, column=2, value=v)
    if warns:
        s.cell(row=len(meta) + 2, column=1, value="Flagged for review").font = Font(bold=True, color="B91C1C")
        for j, w in enumerate(warns[:200]):
            s.cell(row=len(meta) + 3 + j, column=2, value=w)

    # ---- Tracker ----
    t = wb.create_sheet("Tracker")
    headers = ["#", "Rule ID", "CAT", "Severity", "Requirement", "Status", "Owner", "Target date", "Notes"]
    widths = [5, 18, 9, 10, 72, 15, 12, 13, 40]
    has_ai = any((r.get("ai") or {}).get("summary") for r in rules)
    if has_ai:
        headers += ["What it means", "Triage", "Scriptable", "Caution"]
        widths += [60, 15, 12, 45]
    for c, (h, w) in enumerate(zip(headers, widths), start=1):
        t.cell(row=1, column=c, value=h)
        t.column_dimensions[get_column_letter(c)].width = w
    style_header(t, len(headers))

    dv = DataValidation(type="list", formula1='"' + ",".join(STATUSES) + '"',
                        allow_blank=True, showDropDown=False)
    t.add_data_validation(dv)

    for i, r in enumerate(rules, start=2):
        cat = r.get("cat", "")
        t.cell(row=i, column=1, value=i - 1)
        t.cell(row=i, column=2, value=r.get("stig_id", ""))
        cc = t.cell(row=i, column=3, value=cat)
        if cat in CAT_FILLS:
            cc.fill = CAT_FILLS[cat]
            cc.font = CAT_FONTS[cat]
        t.cell(row=i, column=4, value=r.get("severity", ""))
        tc = t.cell(row=i, column=5, value=r.get("title", ""))
        tc.alignment = Alignment(wrap_text=True, vertical="top")
        sc = t.cell(row=i, column=6, value="Open")
        dv.add(sc)
        if has_ai:
            ai = r.get("ai") or {}
            for col, key in zip((10, 11, 12, 13), ("summary", "triage", "automation", "caution")):
                c = t.cell(row=i, column=col, value=ai.get(key, ""))
                c.alignment = Alignment(wrap_text=True, vertical="top")
        for col in range(1, len(headers) + 1):
            t.cell(row=i, column=col).border = BORDER

    t.freeze_panes = "A2"
    t.auto_filter.ref = f"A1:{get_column_letter(len(headers))}{len(rules) + 1}"

    # ---- Details ----
    d = wb.create_sheet("Details")
    dheaders = ["Rule ID", "CAT", "Requirement", "Why it matters", "How to check", "How to fix", "CCIs"]
    dwidths = [18, 9, 45, 55, 65, 65, 22]
    for c, (h, w) in enumerate(zip(dheaders, dwidths), start=1):
        d.cell(row=1, column=c, value=h)
        d.column_dimensions[get_column_letter(c)].width = w
    style_header(d, len(dheaders))
    for i, r in enumerate(rules, start=2):
        vals = [r.get("stig_id", ""), r.get("cat", ""), r.get("title", ""),
                r.get("discussion", ""), r.get("check_text", ""), r.get("fix_text", ""),
                ", ".join(r.get("ccis", []) or [])]
        for c, v in enumerate(vals, start=1):
            cell = d.cell(row=i, column=c, value=v)
            cell.alignment = Alignment(wrap_text=True, vertical="top")
    d.freeze_panes = "A2"

    wb.save(out_path)
    return len(rules), warns


def main():
    if len(sys.argv) != 3:
        die("usage: make_tracker.py <checklist.json> <output.xlsx>")
    data = load(sys.argv[1])
    n, warns = build(data, sys.argv[2])
    print(f"wrote {sys.argv[2]}: {n} rules")
    if warns:
        print(f"flagged for review: {len(warns)}")
        for w in warns[:20]:
            print(f"  - {w}")
        if len(warns) > 20:
            print(f"  ... and {len(warns) - 20} more (see Summary sheet)")
    else:
        print("flagged for review: 0")


if __name__ == "__main__":
    main()
