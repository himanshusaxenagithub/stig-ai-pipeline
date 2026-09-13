"""Load a stig-scan report and optional explanations for drafting."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class LoadError(ValueError):
    pass


def load_scan(path: str | Path) -> dict[str, Any]:
    """Read a stig-scan JSON report. Accepts the file `scan` writes."""
    path = Path(path)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as e:
        raise LoadError(f"{path} not found") from e
    except json.JSONDecodeError as e:
        raise LoadError(f"{path}: not valid JSON: {e}") from e
    if not isinstance(raw, dict):
        raise LoadError(f"{path}: scan report must be a JSON object")
    results = raw.get("results")
    if not isinstance(results, list):
        raise LoadError(f"{path}: no 'results' list — is this a stig-scan report?")
    return raw


def load_explanations(
    checklist: str | Path | None = None,
    annotations: str | Path | None = None,
) -> dict[str, dict[str, Any]]:
    """Map stig_id -> {summary, triage, automation, caution, fix_text, check_text}.

    Checklist JSON from stig-prep wins for ``fix_text`` / ``check_text``.
    Filed annotation caches (``annotations/*.ai-cache.json``) and the
    per-rule ``ai`` object on a checklist supply the four explanation fields.
    """
    out: dict[str, dict[str, Any]] = {}

    if annotations:
        raw = _read_json(annotations)
        for key, val in raw.items():
            if not isinstance(val, dict):
                continue
            sid = key.split(":", 1)[-1]
            rec = out.setdefault(sid, {})
            for field in ("summary", "triage", "automation", "caution"):
                if val.get(field) and not rec.get(field):
                    rec[field] = val[field]

    if checklist:
        raw = _read_json(checklist)
        rules = raw.get("rules")
        if not isinstance(rules, list):
            raise LoadError(f"{checklist}: no 'rules' list — is this a stig-prep checklist?")
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            sid = rule.get("stig_id")
            if not sid:
                continue
            rec = out.setdefault(sid, {})
            for field in ("fix_text", "check_text", "title", "discussion"):
                if rule.get(field) and not rec.get(field):
                    rec[field] = rule[field]
            ai = rule.get("ai") or {}
            if isinstance(ai, dict):
                for field in ("summary", "triage", "automation", "caution"):
                    if ai.get(field):
                        rec[field] = ai[field]
    return out


def _read_json(path: str | Path) -> Any:
    path = Path(path)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as e:
        raise LoadError(f"{path} not found") from e
    except json.JSONDecodeError as e:
        raise LoadError(f"{path}: not valid JSON: {e}") from e
