"""A website (or CLI) selection: which rules a person asked to scan.

The public site never runs a check. It writes a small JSON document naming
the platform, the shipped pack, and the rule ids the person picked. The
local program reads that document, copies those checks into a working pack,
and leaves every one unreviewed — approval still happens on the machine
that will be scanned, under a name a human types.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .pack import CheckPack, PackError

SELECTION_FORMAT = 1


class SelectionError(ValueError):
    pass


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H%M%SZ")


def make_selection(
    *,
    platform: str,
    guide_key: str,
    source_pack: str,
    rule_ids: list[str],
    pack_id: str | None = None,
    pack_path: str = "",
    os_label: str = "",
) -> dict[str, Any]:
    ids = _unique(rule_ids)
    if not ids:
        raise SelectionError("select at least one rule")
    if platform not in ("macos", "windows", "linux"):
        raise SelectionError(f"unsupported platform {platform!r}")
    return {
        "selection_format": SELECTION_FORMAT,
        "created": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "platform": platform,
        "os_label": os_label or platform,
        "guide_key": guide_key,
        "source_pack": source_pack,
        "pack_id": pack_id or f"{source_pack}-selected",
        "pack_path": pack_path or f"checkpacks/{source_pack}-selected.json",
        "rule_ids": ids,
        "unreviewed": True,
        "note": (
            "Every check in this pack is unreviewed. A named person must read "
            "and approve each command on the machine being scanned before it runs."
        ),
    }


def load_selection(path: str | Path) -> dict[str, Any]:
    path = Path(path)
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise SelectionError(f"{path}: not valid JSON: {e}") from e
    if not isinstance(raw, dict):
        raise SelectionError(f"{path}: selection must be a JSON object")
    if raw.get("selection_format") != SELECTION_FORMAT:
        raise SelectionError(
            f"{path}: selection_format {raw.get('selection_format')!r} "
            f"is not supported (this build reads format {SELECTION_FORMAT})"
        )
    ids = raw.get("rule_ids") or []
    if not isinstance(ids, list) or not ids:
        raise SelectionError(f"{path}: rule_ids must be a non-empty list")
    raw["rule_ids"] = _unique(str(i) for i in ids)
    return raw


def write_selection(path: str | Path, selection: dict[str, Any]) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(selection, indent=2) + "\n", encoding="utf-8")
    return path


def apply_selection(pack: CheckPack, selection: dict[str, Any]) -> CheckPack:
    """Return a new pack containing only the selected rules.

    Review state is copied, not invented: a shipped pack stays unreviewed.
    The platform on the selection must match the pack.
    """
    want_platform = selection.get("platform")
    if want_platform and want_platform != pack.platform:
        raise SelectionError(
            f"this selection is for {want_platform} but the pack is {pack.platform}"
        )
    ids = selection.get("rule_ids") or []
    return pack.subset(ids, pack_id=selection.get("pack_id") or None)


def find_selection(root: Path) -> Path | None:
    """A selection.json sitting next to the program, if there is one."""
    candidate = root / "selection.json"
    return candidate if candidate.is_file() else None


def default_pack_id(source_pack: str) -> str:
    return f"{source_pack}-selected-{_stamp()}"


def _unique(ids) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in ids:
        sid = str(item).strip()
        if not sid or sid in seen:
            continue
        seen.add(sid)
        out.append(sid)
    return out
