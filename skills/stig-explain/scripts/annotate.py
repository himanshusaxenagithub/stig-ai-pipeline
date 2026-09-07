#!/usr/bin/env python3
"""Hand an AI assistant the next batch of un-annotated STIG rules, then file
its answers. The assistant does the explaining; this script does the
bookkeeping.

Usage:
    python3 annotate.py next   <checklist.json> [--limit 10]
    python3 annotate.py merge  <checklist.json> <batch.json> [--model NAME]
    python3 annotate.py status <checklist.json>

`next` prints a JSON array of the next N rules that have no annotation yet:
    [{"stig_id", "severity", "title", "discussion", "check_text", "fix_text"}, ...]

`merge` reads the assistant's answers - a JSON array of objects with keys
    stig_id, summary, triage, automation, caution
- validates every one, writes them into the checklist JSON's per-rule "ai"
field, and mirrors them into annotations/<source>.ai-cache.json in the same
format stig-prep's --explain cache uses, so the two paths share one artifact.

Zero third-party dependencies. Never invents content: a batch that fails
validation is rejected whole, with the reasons printed, and nothing is written.
"""

import json
import re
import sys
from datetime import date
from pathlib import Path

TRIAGE = ["quick-win", "config-profile", "needs-judgment", "risky-change"]
AUTOMATION = ["automatable", "manual"]
TEXT_CAP = 1500          # same truncation --explain applies before sending
SUMMARY_MAX_WORDS = 70   # 1-2 plain sentences


def die(msg):
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(1)


def load(path):
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        die(f"cannot read {path}: {e}")
    if not isinstance(data.get("rules"), list):
        die("no 'rules' list - is this a stig-prep checklist file?")
    return data


def save(path, data):
    Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


def annotated(rule):
    ai = rule.get("ai") or {}
    return bool(ai.get("summary"))


def cache_path(data, checklist_path):
    src = Path(data.get("source_file") or Path(checklist_path).stem).name
    stem = re.sub(r"\.(xml|zip)$", "", src, flags=re.I)
    repo_root = Path(__file__).resolve().parents[3]
    d = repo_root / "annotations"
    d.mkdir(exist_ok=True)
    return d / f"{stem}.ai-cache.json"


def cmd_next(path, limit):
    data = load(path)
    todo = [r for r in data["rules"] if not annotated(r)][:limit]
    out = [{
        "stig_id": r.get("stig_id"),
        "severity": r.get("severity"),
        "title": r.get("title"),
        "discussion": (r.get("discussion") or "")[:TEXT_CAP],
        "check_text": (r.get("check_text") or "")[:TEXT_CAP],
        "fix_text": (r.get("fix_text") or "")[:TEXT_CAP],
    } for r in todo]
    print(json.dumps(out, indent=1, ensure_ascii=False))
    remaining = sum(1 for r in data["rules"] if not annotated(r))
    print(f"# {len(out)} rules in this batch, {remaining} un-annotated in total", file=sys.stderr)


def _suspicious_commands(item, rule):
    """Flag command-looking text in the answer that does not appear in the rule's
    own check/fix text. Prose mentions ("needs sudo rights", "set the sysctl
    to 1") are not commands: a tool name counts only when the very next token
    looks like an argument — a flag, a path, a dotted or assigned value, or a
    digit-bearing token — or when it is ``sudo <tool> <argument>``."""
    src = ((rule.get("check_text") or "") + (rule.get("fix_text") or "")).lower()
    text = " ".join(str(item.get(k, "")) for k in ("summary", "caution")).lower()
    tools = (r"(?:reg|regedit|gpedit|auditpol|secedit|sc|net|powershell|bash|chmod|chown|systemctl|"
             r"sysctl|launchctl|defaults|manage-bde|dnf|apt|apt-get|rpm|grep|awk|sed|cat|ls|find|mount|"
             r"ufw|iptables|nft|setsebool|semanage|useradd|usermod|passwd|chage|rm|mv|cp|dd|mkfs|kill|"
             r"set-\w+|get-\w+|new-\w+|remove-\w+)")
    arglike = re.compile(r"[-/=:\\]|\d|^[a-z]+\.[a-z]")
    found = []
    pat = re.compile(r"(?:^|[\s(])(?:(sudo)\s+)?(" + tools + r")\s+(\S+)")
    for m in pat.finditer(text):
        sudo, tool, arg = m.group(1), m.group(2), m.group(3).rstrip(".,;:)")
        if not (arglike.search(arg) or arg.isupper()):
            continue
        snippet = f"{tool} {arg}"
        if snippet not in src:
            found.append(("sudo " if sudo else "") + snippet)
    return found


def validate(batch, rules_by_id):
    problems = []
    if not isinstance(batch, list) or not batch:
        return ["batch must be a non-empty JSON array"]
    seen = set()
    for i, item in enumerate(batch):
        if not isinstance(item, dict):
            problems.append(f"item {i}: not an object"); continue
        sid = item.get("stig_id")
        if sid not in rules_by_id:
            problems.append(f"item {i}: unknown stig_id {sid!r}"); continue
        if sid in seen:
            problems.append(f"{sid}: duplicated in batch")
        seen.add(sid)
        s = str(item.get("summary", "")).strip()
        if not s:
            problems.append(f"{sid}: empty summary")
        elif len(s.split()) > SUMMARY_MAX_WORDS:
            problems.append(f"{sid}: summary too long ({len(s.split())} words, max {SUMMARY_MAX_WORDS})")
        if item.get("triage") not in TRIAGE:
            problems.append(f"{sid}: triage must be one of {TRIAGE}, got {item.get('triage')!r}")
        if item.get("automation") not in AUTOMATION:
            problems.append(f"{sid}: automation must be one of {AUTOMATION}, got {item.get('automation')!r}")
        if "caution" not in item:
            problems.append(f"{sid}: missing caution (use \"\" if none)")
        bad = _suspicious_commands(item, rules_by_id[sid])
        if bad:
            problems.append(f"{sid}: command-like text not found in the rule's check/fix text: {bad}")
    return problems


def cmd_merge(path, batch_path, model):
    data = load(path)
    try:
        batch = json.loads(Path(batch_path).read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        die(f"cannot read {batch_path}: {e}")
    rules_by_id = {r.get("stig_id"): r for r in data["rules"]}
    problems = validate(batch, rules_by_id)
    if problems:
        print("rejected - nothing written:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        sys.exit(2)

    cp = cache_path(data, path)
    cache = {}
    if cp.exists():
        try:
            cache = json.loads(cp.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            cache = {}

    for item in batch:
        sid = item["stig_id"]
        ai = {
            "summary": str(item["summary"]).strip(),
            "triage": item["triage"],
            "automation": item["automation"],
            "caution": str(item.get("caution", "")).strip(),
            "model": model,
            "date": date.today().isoformat(),
        }
        rules_by_id[sid]["ai"] = ai
        cache[f"{model}:{sid}"] = ai

    save(path, data)
    cp.write_text(json.dumps(cache, indent=1, ensure_ascii=False), encoding="utf-8")
    remaining = sum(1 for r in data["rules"] if not annotated(r))
    print(f"merged {len(batch)}, {remaining} remaining; cache: {cp.relative_to(cp.parents[1])}")


def cmd_status(path):
    data = load(path)
    n = len(data["rules"]); done = sum(1 for r in data["rules"] if annotated(r))
    print(f"{data.get('title','')}: {done}/{n} annotated, {n-done} remaining")
    if done:
        from collections import Counter
        c = Counter((r.get("ai") or {}).get("triage") for r in data["rules"] if annotated(r))
        print("  triage:", dict(c))


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
            die("merge needs <checklist.json> <batch.json>")
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
