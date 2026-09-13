"""Remediation packs: reviewable drafts of fix scripts.

Same integrity model as stig-scan and stig-assess. Approving a
remediation records a SHA-256 digest over the script a person read.
If the script is edited afterwards, the entry is DRIFTED and will not
apply until it is re-reviewed.

Apply state is separate from review state. Approval does not apply
anything. ``applied`` is recorded only after a successful
``--apply-for-real`` run by a named person.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

PACK_FORMAT = 1

UNREVIEWED = "unreviewed"
APPROVED = "approved"
REJECTED = "rejected"

MODE_SCRIPT = "script"
MODE_MANUAL = "manual"
MODE_UNSUPPORTED = "unsupported"

NEVER_APPLIED = "never_applied"
APPLIED = "applied"
DRY_RUN = "dry_run"

PLATFORMS = ("macos", "windows", "linux")
LANGUAGES = ("shell", "powershell", "none")
REVIEW_STATES = (UNREVIEWED, APPROVED, REJECTED)
MODES = (MODE_SCRIPT, MODE_MANUAL, MODE_UNSUPPORTED)
APPLY_STATES = (NEVER_APPLIED, APPLIED, DRY_RUN)


class PackError(RuntimeError):
    pass


@dataclass
class Remediation:
    stig_id: str
    group_id: str = ""
    severity: str = "medium"
    title: str = ""
    platform: str = "macos"
    mode: str = MODE_SCRIPT
    language: str = "shell"
    script: str = ""
    rationale: str = ""
    check_command: str = ""
    expected: str = ""
    comparator: str = ""
    actual: str = ""
    finding_status: str = "fail"
    requires_root: bool = False
    shape: str = ""
    authored_by: str = "unknown"
    authored_at: str = ""
    author_confidence: str = "medium"
    author_note: str = ""
    review_status: str = UNREVIEWED
    reviewed_by: str | None = None
    reviewed_at: str | None = None
    review_note: str = ""
    approved_digest: str | None = None
    apply_status: str = NEVER_APPLIED
    applied_by: str | None = None
    applied_at: str | None = None
    apply_note: str = ""

    def digest(self) -> str:
        payload = json.dumps(
            {
                "stig_id": self.stig_id,
                "platform": self.platform,
                "mode": self.mode,
                "language": self.language,
                "script": self.script,
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

    def is_approvable(self) -> bool:
        return self.mode == MODE_SCRIPT and bool(self.script.strip())

    def approve(self, by: str, at: str, note: str = "") -> None:
        by = (by or "").strip()
        if not by:
            raise PackError(f"{self.stig_id}: approval requires a person's name")
        if not self.is_approvable():
            raise PackError(
                f"{self.stig_id}: only a non-empty script can be approved "
                f"(mode is {self.mode!r})"
            )
        self.review_status = APPROVED
        self.reviewed_by = by
        self.reviewed_at = at
        self.review_note = note
        self.approved_digest = self.digest()

    def reject(self, by: str, at: str, note: str = "") -> None:
        by = (by or "").strip()
        if not by:
            raise PackError(f"{self.stig_id}: rejection requires a person's name")
        self.review_status = REJECTED
        self.reviewed_by = by
        self.reviewed_at = at
        self.review_note = note
        self.approved_digest = None

    def mark_apply(self, by: str, at: str, status: str, note: str = "") -> None:
        if status not in (APPLIED, DRY_RUN):
            raise PackError(f"{self.stig_id}: unknown apply status {status!r}")
        self.apply_status = status
        self.applied_by = by
        self.applied_at = at
        self.apply_note = note

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Remediation":
        known = {f for f in cls.__dataclass_fields__}
        unknown = set(d) - known
        if unknown:
            raise PackError(
                f"{d.get('stig_id', '?')}: unknown field(s): {', '.join(sorted(unknown))}"
            )
        return cls(**{k: v for k, v in d.items() if k in known})


@dataclass
class RemediationPack:
    pack_id: str
    stig_title: str = ""
    stig_version: str = ""
    source_scan: str = ""
    created: str = ""
    notes: str = ""
    pack_format: int = PACK_FORMAT
    platform: str = "macos"
    remediations: list[Remediation] = field(default_factory=list)

    @classmethod
    def load(cls, path: str | Path) -> "RemediationPack":
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
        rows = [Remediation.from_dict(r) for r in raw.get("remediations", [])]
        seen: set[str] = set()
        for r in rows:
            if r.stig_id in seen:
                raise PackError(f"{path}: duplicate stig_id {r.stig_id}")
            seen.add(r.stig_id)
            if r.review_status not in REVIEW_STATES:
                raise PackError(f"{r.stig_id}: unknown review_status {r.review_status!r}")
            if r.mode not in MODES:
                raise PackError(f"{r.stig_id}: unknown mode {r.mode!r}")
            if r.language not in LANGUAGES:
                raise PackError(f"{r.stig_id}: unknown language {r.language!r}")
            if r.apply_status not in APPLY_STATES:
                raise PackError(f"{r.stig_id}: unknown apply_status {r.apply_status!r}")
        return cls(
            pack_id=raw.get("pack_id", path.stem),
            stig_title=raw.get("stig_title", ""),
            stig_version=raw.get("stig_version", ""),
            source_scan=raw.get("source_scan", ""),
            created=raw.get("created", ""),
            notes=raw.get("notes", ""),
            platform=raw.get("platform", "macos"),
            remediations=rows,
        )

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        body = {
            "pack_format": self.pack_format,
            "pack_id": self.pack_id,
            "stig_title": self.stig_title,
            "stig_version": self.stig_version,
            "source_scan": self.source_scan,
            "created": self.created,
            "notes": self.notes,
            "platform": self.platform,
            "remediations": [asdict(r) for r in self.remediations],
        }
        path.write_text(json.dumps(body, indent=2) + "\n", encoding="utf-8")

    def get(self, stig_id: str) -> Remediation | None:
        for r in self.remediations:
            if r.stig_id == stig_id:
                return r
        return None

    def summary(self) -> dict[str, int]:
        s = {
            "total": len(self.remediations),
            "script": 0,
            "manual": 0,
            "unsupported": 0,
            "unreviewed": 0,
            "approved": 0,
            "rejected": 0,
            "drifted": 0,
            "never_applied": 0,
            "applied": 0,
            "dry_run": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }
        for r in self.remediations:
            s[r.mode] = s.get(r.mode, 0) + 1
            s[r.review_status] = s.get(r.review_status, 0) + 1
            s[r.apply_status] = s.get(r.apply_status, 0) + 1
            if r.is_drifted():
                s["drifted"] += 1
            if r.severity in s:
                s[r.severity] += 1
        return s
