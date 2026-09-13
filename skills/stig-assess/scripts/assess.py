#!/usr/bin/env python3
"""Hand an AI assistant the next POA&M drafts to refine, then file its answers.

Usage:
    python3 assess.py next   <poam.json> [--limit 10]
    python3 assess.py merge  <poam.json> <batch.json> [--model NAME]
    python3 assess.py status <poam.json>

`next` prints items whose wording is still the deterministic template
(or that a person has not approved). `merge` writes refined
description / recommendation / resources / scheduled_completion only.

The script refuses any batch that tries to close an item, set a review
state, or invent command-like text that is not already on the item.
Zero third-party dependencies. Python 3.9+.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ALLOWED = {
    "stig_id",
    "description",
    "recommendation",
    "resources",
    "scheduled_completion",
}
FORBIDDEN = {
    "poam_status",
    "review_status",
    "closure_kind",
    "closed_by",
    "closed_at",
    "closure_note",
    "approved_digest",
    "reviewed_by",
    "reviewed_at",
}
DESCRIPTION_MAX_WORDS = 180


def die(msg, code=1):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(code)


def load_pack(path):
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        die(f"cannot read {path}: {e}")
    if not isinstance(data.get("entries"), list):
        die("no 'entries' list — is this a stig-assess POA&M file?")
    return data


def save_pack(path, data):
    Path(path).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def _needs_refine(entry):
    if entry.get("review_status") == "approved":
        return False
    note = entry.get("author_note") or ""
    return "no filed explanation" in note or not (entry.get("description") or "").strip()


def cmd_next(path, limit):
    data = load_pack(path)
    unapproved = [e for e in data["entries"] if e.get("review_status") != "approved"]
    todo = [e for e in unapproved if _needs_refine(e)]
    if len(todo) < limit:
        seen = {e.get("stig_id") for e in todo}
        for e in unapproved:
            if e.get("stig_id") in seen:
                continue
            todo.append(e)
            if len(todo) >= limit:
                break
    todo = todo[:limit]
    out = [{
        "stig_id": e.get("stig_id"),
        "severity": e.get("severity"),
        "kind": e.get("kind"),
        "title": e.get("title"),
        "weakness": e.get("weakness"),
        "finding_status": e.get("finding_status"),
        "scan_detail": e.get("scan_detail"),
        "actual": e.get("actual"),
        "expected": e.get("expected"),
        "command": e.get("command"),
        "description": e.get("description"),
        "recommendation": e.get("recommendation"),
        "triage": e.get("triage"),
        "caution": e.get("caution"),
        "trusted": e.get("trusted", True),
    } for e in todo]
    print(json.dumps(out, indent=1, ensure_ascii=False))
    remaining = sum(1 for e in data["entries"] if e.get("review_status") != "approved")
    print(f"# {len(out)} item(s) in this batch, {remaining} still unapproved", file=sys.stderr)


_MUTATING = re.compile(
    r"\b(defaults\s+write|sysctl\s+-w|set-itemproperty|new-itemproperty|"
    r"auditpol\s+/set|secedit\s+/configure|csrutil\s+(enable|disable)|"
    r"fdesetup\s+enable|launchctl\s+(bootout|disable|unload))\b",
    re.I,
)


def _suspicious_commands(item, entry):
    src = " ".join(str(entry.get(k) or "") for k in (
        "command", "scan_detail", "description", "recommendation",
        "caution", "actual", "expected",
    )).lower()
    text = " ".join(str(item.get(k, "")) for k in ("description", "recommendation")).lower()
    found = []
    for m in _MUTATING.finditer(text):
        phrase = re.sub(r"\s+", " ", m.group(0).lower())
        if phrase not in src:
            found.append(phrase)
    tools = (
        r"(?:reg|regedit|gpedit|auditpol|secedit|sc|net|powershell|bash|chmod|chown|"
        r"systemctl|sysctl|launchctl|defaults|manage-bde|dnf|apt|apt-get|rpm|"
        r"csrutil|fdesetup|set-\w+|new-\w+|remove-\w+)"
    )
    arglike = re.compile(r"[-/=:\\]|\d|^[a-z]+\.[a-z]")
    pat = re.compile(r"(?:^|[\s(])(?:(sudo)\s+)?(" + tools + r")\s+(\S+)")
    for m in pat.finditer(text):
        sudo, tool, arg = m.group(1), m.group(2), m.group(3).rstrip(".,;:)")
        if not (arglike.search(arg) or arg.isupper()):
            continue
        snippet = f"{tool} {arg}"
        if snippet not in src:
            found.append(("sudo " if sudo else "") + snippet)
    return found


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
                f"item {i}: refused keys that would change review or closure "
                f"state: {sorted(forbidden)}"
            )
            continue
        if extra - FORBIDDEN:
            problems.append(f"item {i}: unknown field(s): {sorted(extra)}")
        sid = item.get("stig_id")
        if sid not in by_id:
            problems.append(f"item {i}: unknown stig_id {sid!r}")
            continue
        if sid in seen:
            problems.append(f"{sid}: duplicated in batch")
        seen.add(sid)
        desc = str(item.get("description") or "").strip()
        if not desc:
            problems.append(f"{sid}: empty description")
        elif len(desc.split()) > DESCRIPTION_MAX_WORDS:
            problems.append(
                f"{sid}: description too long ({len(desc.split())} words, "
                f"max {DESCRIPTION_MAX_WORDS})"
            )
        if not str(item.get("recommendation") or "").strip():
            problems.append(f"{sid}: empty recommendation")
        if "resources" not in item:
            problems.append(f"{sid}: missing resources")
        if "scheduled_completion" not in item:
            problems.append(f"{sid}: missing scheduled_completion (use \"\" if none)")
        bad = _suspicious_commands(item, by_id[sid])
        if bad:
            problems.append(
                f"{sid}: command-like text not found on the item: {bad}"
            )
        closedish = (desc + " " + str(item.get("recommendation") or "")).lower()
        if re.search(r"\b(marked complete|poa&m complete|auto-closed|automatically closed)\b",
                     closedish):
            problems.append(f"{sid}: wording claims the POA&M is complete")
    return problems


def cmd_merge(path, batch_path, model):
    data = load_pack(path)
    try:
        batch = json.loads(Path(batch_path).read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        die(f"cannot read {batch_path}: {e}")
    by_id = {e.get("stig_id"): e for e in data["entries"]}
    problems = validate(batch, by_id)
    if problems:
        print("rejected - nothing written:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        sys.exit(2)
    for item in batch:
        e = by_id[item["stig_id"]]
        e["description"] = str(item["description"]).strip()
        e["recommendation"] = str(item["recommendation"]).strip()
        e["resources"] = str(item.get("resources") or "").strip()
        e["scheduled_completion"] = str(item.get("scheduled_completion") or "").strip()
        e["authored_by"] = model
        e["author_note"] = "wording refined by assistant; still unreviewed"
        e["review_status"] = "unreviewed"
        e["reviewed_by"] = None
        e["reviewed_at"] = None
        e["approved_digest"] = None
        e["poam_status"] = "draft"
    save_pack(path, data)
    remaining = sum(1 for e in data["entries"] if e.get("review_status") != "approved")
    print(f"merged {len(batch)}, {remaining} still unapproved")


def cmd_status(path):
    data = load_pack(path)
    entries = data["entries"]
    n = len(entries)
    approved = sum(1 for e in entries if e.get("review_status") == "approved")
    closed = sum(1 for e in entries if e.get("poam_status") == "closed")
    print(f"{data.get('pack_id', path)}: {n} items, {approved} approved, {closed} closed")
    print("  (closed count must only grow when a named person ran stigassess close)")


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
            die("merge needs <poam.json> <batch.json>")
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
