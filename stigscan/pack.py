"""Check packs: the frozen, reviewable unit of executable STIG knowledge.

A check pack is a JSON document pairing STIG rule ids with the command that
tests them and the result that constitutes compliance. Each entry carries
its own provenance (who or what authored it), its review state, and — once
approved — a digest over its executable content.

The digest is the freeze. If a command or expected value is edited after
approval, the recomputed digest no longer matches `approved_digest` and the
entry is reported as DRIFTED. A drifted entry is never executed; it must be
re-reviewed. This is what makes an AI-authored check pack auditable: an
approval always refers to specific bytes a human actually read.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

PACK_FORMAT = 1

# Review states
UNREVIEWED = "unreviewed"
APPROVED = "approved"
REJECTED = "rejected"

# Execution modes
MODE_SHELL = "shell"          # runnable command
MODE_MANUAL = "manual"        # STIG requires human inspection (e.g. GUI)
MODE_UNSUPPORTED = "unsupported"  # could not be reduced to a command

COMPARATORS = {
    "equals", "not_equals", "contains", "regex",
    "int_eq", "int_ge", "int_le", "nonempty", "empty",
}


class PackError(RuntimeError):
    pass


@dataclass
class Check:
    stig_id: str
    group_id: str = ""
    severity: str = "medium"
    title: str = ""
    mode: str = MODE_SHELL
    command: str = ""
    comparator: str = "equals"
    expected: str = ""
    # Why the authoring step believed `expected` is correct — verbatim STIG text.
    expected_source: str = ""
    requires_root: bool = False
    manual_instruction: str = ""
    authored_by: str = "unknown"
    authored_at: str = ""
    author_confidence: str = "medium"   # high | medium | low
    author_note: str = ""
    review_status: str = UNREVIEWED
    reviewed_by: str | None = None
    reviewed_at: str | None = None
    review_note: str = ""
    approved_digest: str | None = None

    # ---- integrity -----------------------------------------------------
    def digest(self) -> str:
        """Hash over exactly the fields that determine what gets executed."""
        payload = json.dumps(
            {
                "stig_id": self.stig_id,
                "mode": self.mode,
                "command": self.command,
                "comparator": self.comparator,
                "expected": self.expected,
                "requires_root": self.requires_root,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return "sha256:" + hashlib.sha256(payload.encode()).hexdigest()

    def is_drifted(self) -> bool:
        return (
            self.review_status == APPROVED
            and self.approved_digest is not None
            and self.approved_digest != self.digest()
        )

    def is_runnable(self) -> bool:
        return (
            self.mode == MODE_SHELL
            and self.review_status == APPROVED
            and not self.is_drifted()
            and bool(self.command.strip())
        )

    def approve(self, by: str, at: str, note: str = "") -> None:
        if self.mode != MODE_SHELL:
            raise PackError(
                f"{self.stig_id}: only shell checks can be approved "
                f"(mode is {self.mode!r})"
            )
        if not self.command.strip():
            raise PackError(f"{self.stig_id}: refusing to approve an empty command")
        self.review_status = APPROVED
        self.reviewed_by = by
        self.reviewed_at = at
        self.review_note = note
        self.approved_digest = self.digest()

    def reject(self, by: str, at: str, note: str = "") -> None:
        self.review_status = REJECTED
        self.reviewed_by = by
        self.reviewed_at = at
        self.review_note = note
        self.approved_digest = None

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Check":
        known = {f for f in cls.__dataclass_fields__}
        unknown = set(d) - known
        if unknown:
            raise PackError(
                f"{d.get('stig_id', '?')}: unknown field(s): {', '.join(sorted(unknown))}"
            )
        return cls(**d)


@dataclass
class CheckPack:
    pack_id: str
    stig_title: str = ""
    stig_version: str = ""
    created: str = ""
    notes: str = ""
    pack_format: int = PACK_FORMAT
    platform: str = "macos"     # profile the pack was authored for
    checks: list[Check] = field(default_factory=list)

    # ---- io ------------------------------------------------------------
    @classmethod
    def load(cls, path: str | Path) -> "CheckPack":
        path = Path(path)
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raise PackError(f"{path}: not valid JSON: {e}") from e
        if raw.get("pack_format") != PACK_FORMAT:
            raise PackError(
                f"{path}: pack_format {raw.get('pack_format')!r} is not supported "
                f"(this build reads format {PACK_FORMAT})"
            )
        checks = [Check.from_dict(c) for c in raw.get("checks", [])]
        seen: set[str] = set()
        for c in checks:
            if c.stig_id in seen:
                raise PackError(f"{path}: duplicate stig_id {c.stig_id}")
            seen.add(c.stig_id)
            if c.comparator not in COMPARATORS:
                raise PackError(
                    f"{c.stig_id}: unknown comparator {c.comparator!r}; "
                    f"expected one of {', '.join(sorted(COMPARATORS))}"
                )
            if c.mode not in (MODE_SHELL, MODE_MANUAL, MODE_UNSUPPORTED):
                raise PackError(f"{c.stig_id}: unknown mode {c.mode!r}")
        return cls(
            pack_id=raw.get("pack_id", path.stem),
            stig_title=raw.get("stig_title", ""),
            stig_version=raw.get("stig_version", ""),
            created=raw.get("created", ""),
            notes=raw.get("notes", ""),
            platform=raw.get("platform", "macos"),
            checks=checks,
        )

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        body = {
            "pack_format": self.pack_format,
            "pack_id": self.pack_id,
            "stig_title": self.stig_title,
            "stig_version": self.stig_version,
            "created": self.created,
            "notes": self.notes,
            "platform": self.platform,
            "checks": [asdict(c) for c in self.checks],
        }
        path.write_text(json.dumps(body, indent=2) + "\n", encoding="utf-8")

    # ---- queries -------------------------------------------------------
    def get(self, stig_id: str) -> Check | None:
        for c in self.checks:
            if c.stig_id == stig_id:
                return c
        return None

    def summary(self) -> dict[str, int]:
        s = {
            "total": len(self.checks),
            "approved": 0, "unreviewed": 0, "rejected": 0,
            "drifted": 0, "manual": 0, "unsupported": 0, "runnable": 0,
        }
        for c in self.checks:
            if c.mode == MODE_MANUAL:
                s["manual"] += 1
            elif c.mode == MODE_UNSUPPORTED:
                s["unsupported"] += 1
            if c.is_drifted():
                s["drifted"] += 1
            elif c.review_status == APPROVED:
                s["approved"] += 1
            elif c.review_status == REJECTED:
                s["rejected"] += 1
            else:
                s["unreviewed"] += 1
            if c.is_runnable():
                s["runnable"] += 1
        return s
