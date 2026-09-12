"""Plain-English explanations for STIG rules.

Explanations are produced by the ``stig-explain`` skill: an AI assistant the
user already has writes, for each rule, a summary, a triage bucket, an
automation flag and a caution, and a helper script validates and files
them. The results live in two places, both in the same format:

* ``annotations/<xccdf-name>.ai-cache.json`` in this repository — the
  published sets, available to anyone who clones it;
* ``<stig-source>.ai-cache.json`` next to the STIG file — a local set the
  user produced themselves.

This module only *attaches* those explanations to a parsed benchmark. It
makes no network calls and needs no account or key. Nothing here invents
content: a rule with no filed explanation is left unannotated and reported.

Filed sets are named after the XCCDF document, because that is what the
skill is run against. The source handed to ``parse`` may instead be the
DISA .zip that contains it, so the lookup tries, in order: the name of the
source itself, the name of each XCCDF member inside it when the source is a
zip, and finally whichever filed set shares the most rule identifiers with
the benchmark. The last of those keeps working when DISA renames a file
between releases.

No third-party dependencies.
"""

from __future__ import annotations

import json
import sys
import zipfile
from pathlib import Path

TRIAGE_VALUES = ["quick-win", "config-profile", "needs-judgment", "risky-change"]

CACHE_SUFFIX = ".ai-cache.json"


class ExplainError(RuntimeError):
    pass


def _cache_path(source: Path) -> Path:
    return source.with_suffix(CACHE_SUFFIX)


def _annotations_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "annotations"


def _xccdf_members(source: Path) -> list[str]:
    """Names of the XCCDF documents inside *source*, when it is a zip."""
    if source.suffix.lower() != ".zip" or not source.exists():
        return []
    try:
        with zipfile.ZipFile(source) as zf:
            return [Path(n).name for n in zf.namelist()
                    if n.lower().endswith(".xml") and "xccdf" in n.lower()]
    except (zipfile.BadZipFile, OSError):
        return []


def _candidate_names(source: Path) -> list[str]:
    """Filed-set filenames to try for *source*, most specific first."""
    names = [_cache_path(source).name]
    for member in _xccdf_members(source):
        names.append(Path(member).with_suffix(CACHE_SUFFIX).name)
    seen, ordered = set(), []
    for n in names:
        if n not in seen:
            seen.add(n)
            ordered.append(n)
    return ordered


def _load(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def _entries(raw: dict) -> dict[str, dict]:
    """Normalise one filed set into {stig_id: annotation}."""
    out: dict[str, dict] = {}
    for key, value in raw.items():
        sid = key.split(":", 1)[1] if ":" in key else key
        if isinstance(value, dict) and value.get("summary"):
            out[sid] = value
    return out


def _best_filed_set(rule_ids: set[str]) -> dict[str, dict]:
    """The filed set sharing the most rule identifiers with *rule_ids*.

    Used only when no filename matched, so that a renamed release still
    finds its explanations. Returns {} when nothing overlaps.
    """
    if not rule_ids:
        return {}
    best: dict[str, dict] = {}
    best_overlap = 0
    directory = _annotations_dir()
    if not directory.is_dir():
        return {}
    for path in sorted(directory.glob("*" + CACHE_SUFFIX)):
        entries = _entries(_load(path))
        overlap = len(rule_ids & set(entries))
        if overlap > best_overlap:
            best, best_overlap = entries, overlap
    return best


def load_annotations(source_path, rule_ids: set[str] | None = None) -> dict[str, dict]:
    """Return {stig_id: annotation} for *source_path*.

    The repository set is loaded first and the local cache beside the STIG
    second, so a local entry wins over a published one for the same rule.
    When neither is found by name and *rule_ids* is given, the filed set
    with the greatest identifier overlap is used instead.
    """
    source = Path(source_path)
    merged: dict[str, dict] = {}
    directory = _annotations_dir()
    for name in _candidate_names(source):
        merged.update(_entries(_load(directory / name)))
    for name in _candidate_names(source):
        merged.update(_entries(_load(source.parent / name)))
    if not merged and rule_ids:
        merged = _best_filed_set(rule_ids)
    return merged


def explain(benchmark, source_path, progress: bool = True, **_ignored) -> int:
    """Attach filed explanations to ``benchmark.rules`` in place.

    Returns the number of rules annotated. Rules with no filed explanation
    are left as they are; when any remain, a note on stderr says how to
    produce them with the stig-explain skill.
    """
    rule_ids = {r.stig_id for r in benchmark.rules}
    ann = load_annotations(source_path, rule_ids)
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
            print("  explanations: none filed for this STIG yet", file=sys.stderr)
        if missing:
            print("  to produce them, run the stig-explain skill "
                  "(skills/stig-explain/SKILL.md) on this checklist", file=sys.stderr)
    return hit
