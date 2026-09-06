"""Plain-English explanations for STIG rules.

Explanations are produced by the ``stig-explain`` skill: an AI assistant the
user already has writes, for each rule, a summary, a triage bucket, an
automation flag and a caution, and a helper script validates and files
them. The results live in two places, both in the same format:

* ``annotations/<stig-source>.ai-cache.json`` in this repository — the
  published sets, available to anyone who clones it;
* ``<stig-source>.ai-cache.json`` next to the STIG file — a local set the
  user produced themselves.

This module only *attaches* those explanations to a parsed benchmark. It
makes no network calls and needs no account or key. Nothing here invents
content: a rule with no filed explanation is left unannotated and reported.

No third-party dependencies.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

TRIAGE_VALUES = ["quick-win", "config-profile", "needs-judgment", "risky-change"]


class ExplainError(RuntimeError):
    pass


def _cache_path(source: Path) -> Path:
    return source.with_suffix(".ai-cache.json")


def _repo_annotations_path(source: Path) -> Path:
    return Path(__file__).resolve().parents[1] / "annotations" / _cache_path(source).name


def _load(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except json.JSONDecodeError:
        return {}


def load_annotations(source_path) -> dict[str, dict]:
    """Return {stig_id: annotation} from the repository set and the local
    cache. A local entry wins over a repository entry for the same rule."""
    source = Path(source_path)
    merged: dict[str, dict] = {}
    for store in (_repo_annotations_path(source), _cache_path(source)):
        for key, value in _load(store).items():
            sid = key.split(":", 1)[1] if ":" in key else key
            if isinstance(value, dict) and value.get("summary"):
                merged[sid] = value
    return merged


def explain(benchmark, source_path, progress: bool = True, **_ignored) -> int:
    """Attach filed explanations to ``benchmark.rules`` in place.

    Returns the number of rules annotated. Rules with no filed explanation
    are left as they are; when any remain, a note on stderr says how to
    produce them with the stig-explain skill.
    """
    ann = load_annotations(source_path)
    hit = 0
    missing = []
    for rule in benchmark.rules:
        entry = ann.get(rule.stig_id)
        if entry:
            rule.ai = {
                "summary": entry.get("summary", ""),
                "triage": entry.get("triage") if entry.get("triage") in TRIAGE_VALUES else "needs-judgment",
                "automation": entry.get("automation", "manual"),
                "caution": entry.get("caution", ""),
                "model": entry.get("model", ""),
            }
            hit += 1
        else:
            missing.append(rule.stig_id)

    if progress:
        total = len(benchmark.rules)
        if hit == total:
            print(f"  explanations: all {total} rules annotated from filed sets", file=sys.stderr)
        elif hit:
            print(f"  explanations: {hit} of {total} rules annotated; {len(missing)} have none yet",
                  file=sys.stderr)
        else:
            print(f"  explanations: none filed for this STIG yet", file=sys.stderr)
        if missing:
            print("  to produce them, run the stig-explain skill "
                  "(skills/stig-explain/SKILL.md) on this checklist", file=sys.stderr)
    return hit
