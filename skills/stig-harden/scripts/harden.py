#!/usr/bin/env python3
"""Hand an AI assistant the next remediation drafts, then file its answers.

Usage:
    python3 harden.py next   <harden.json> [--limit 10]
    python3 harden.py merge  <harden.json> <batch.json> [--model NAME]
    python3 harden.py status <harden.json>

Merge writes script / rationale / mode only. The script is run through
the same safety gate as stigharden. Batches that set apply/review state,
include a high-risk form as mode=script, or fail the gate are rejected
whole. Zero third-party dependencies. Python 3.9+.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from stigharden.safety import audit, high_risk  # noqa: E402

ALLOWED = {"stig_id", "script", "rationale", "mode"}
FORBIDDEN = {
    "apply_status", "applied_by", "applied_at", "apply_note",
    "review_status", "reviewed_by", "reviewed_at", "approved_digest",
}
RATIONALE_MAX_WORDS = 120


def die(msg, code=1):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(code)


def load_pack(path):
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        die(f"cannot read {path}: {e}")
    if not isinstance(data.get("remediations"), list):
        die("no 'remediations' list — is this a stig-harden file?")
    return data


def save_pack(path, data):
    Path(path).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def cmd_next(path, limit):
    data = load_pack(path)
    todo = [r for r in data["remediations"] if r.get("review_status") != "approved"][:limit]
    out = [{
        "stig_id": r.get("stig_id"),
        "severity": r.get("severity"),
        "title": r.get("title"),
        "platform": r.get("platform"),
        "mode": r.get("mode"),
        "shape": r.get("shape"),
        "script": r.get("script"),
        "rationale": r.get("rationale"),
        "check_command": r.get("check_command"),
        "expected": r.get("expected"),
        "actual": r.get("actual"),
        "author_note": r.get("author_note"),
    } for r in todo]
    print(json.dumps(out, indent=1, ensure_ascii=False))
    remaining = sum(1 for r in data["remediations"] if r.get("review_status") != "approved")
    print(f"# {len(out)} item(s) in this batch, {remaining} still unapproved", file=sys.stderr)


def validate(batch, by_id):
    problems = []
    if not isinstance(batch, list) or not batch:
        return ["batch must be a non-empty JSON array"]
    seen = set()
    for i, item in enumerate(batch):
        if not isinstance(item, dict):
            problems.append(f"item {i}: not an object")
            continue
        extra = set(item) - ALLOWED
        forbidden = extra & FORBIDDEN
        if forbidden:
            problems.append(
                f"item {i}: refused keys that would change review or apply "
                f"state: {sorted(forbidden)}"
            )
            continue
        if extra:
            problems.append(f"item {i}: unknown field(s): {sorted(extra)}")
        sid = item.get("stig_id")
        if sid not in by_id:
            problems.append(f"item {i}: unknown stig_id {sid!r}")
            continue
        if sid in seen:
            problems.append(f"{sid}: duplicated in batch")
        seen.add(sid)
        mode = item.get("mode")
        if mode not in {"script", "manual"}:
            problems.append(f"{sid}: mode must be script or manual, got {mode!r}")
        script = str(item.get("script") or "")
        if mode == "script" and not script.strip():
            problems.append(f"{sid}: script mode requires a script")
        if mode == "manual" and script.strip():
            problems.append(f"{sid}: manual mode must use an empty script")
        rationale = str(item.get("rationale") or "").strip()
        if not rationale:
            problems.append(f"{sid}: empty rationale")
        elif len(rationale.split()) > RATIONALE_MAX_WORDS:
            problems.append(
                f"{sid}: rationale too long ({len(rationale.split())} words, "
                f"max {RATIONALE_MAX_WORDS})"
            )
        if script:
            bad = audit(script)
            if bad:
                problems.append(f"{sid}: safety gate: {bad}")
            risk = high_risk(script)
            if risk and mode == "script":
                problems.append(f"{sid}: high-risk form cannot be mode=script: {risk}")
    return problems


def cmd_merge(path, batch_path, model):
    data = load_pack(path)
    try:
        batch = json.loads(Path(batch_path).read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        die(f"cannot read {batch_path}: {e}")
    by_id = {r.get("stig_id"): r for r in data["remediations"]}
    problems = validate(batch, by_id)
    if problems:
        print("rejected - nothing written:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        sys.exit(2)
    for item in batch:
        r = by_id[item["stig_id"]]
        r["script"] = str(item.get("script") or "")
        r["rationale"] = str(item["rationale"]).strip()
        r["mode"] = item["mode"]
        if item["mode"] != "script":
            r["language"] = "none"
        r["authored_by"] = model
        r["author_note"] = "script refined by assistant; still unreviewed"
        r["review_status"] = "unreviewed"
        r["reviewed_by"] = None
        r["reviewed_at"] = None
        r["approved_digest"] = None
        r["apply_status"] = "never_applied"
        r["applied_by"] = None
        r["applied_at"] = None
    save_pack(path, data)
    remaining = sum(1 for r in data["remediations"] if r.get("review_status") != "approved")
    print(f"merged {len(batch)}, {remaining} still unapproved")


def cmd_status(path):
    data = load_pack(path)
    rows = data["remediations"]
    n = len(rows)
    approved = sum(1 for r in rows if r.get("review_status") == "approved")
    applied = sum(1 for r in rows if r.get("apply_status") == "applied")
    print(f"{data.get('pack_id', path)}: {n} items, {approved} approved, {applied} applied")
    print("  (applied count must only grow when a named person passed --apply-for-real)")


def main(argv):
    if len(argv) < 3:
        die(__doc__.strip().split("\n\n")[1])
    cmd, path = argv[1], argv[2]
    if cmd == "next":
        limit = 10
        if "--limit" in argv:
            limit = int(argv[argv.index("--limit") + 1])
        cmd_next(path, limit)
    elif cmd == "merge":
        if len(argv) < 4:
            die("merge needs <harden.json> <batch.json>")
        model = "assistant-skill"
        if "--model" in argv:
            model = argv[argv.index("--model") + 1]
        cmd_merge(path, argv[3], model)
    elif cmd == "status":
        cmd_status(path)
    else:
        die(f"unknown command {cmd!r}")


if __name__ == "__main__":
    main(sys.argv)
