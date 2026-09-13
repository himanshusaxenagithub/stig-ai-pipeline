"""POA&M packs: reviewable drafts of Plan of Action and Milestones entries.

A POA&M pack is a JSON document pairing scan findings with a plain-English
weakness statement and the structured fields an accreditation package
expects. Each entry carries provenance, review state, and — once a person
approves it — a digest over the wording they actually read.

The digest is the freeze. If the description or recommendation is edited
after approval, the recomputed digest no longer matches `approved_digest`
and the entry is reported as DRIFTED. A drifted entry cannot be closed
until it is re-reviewed. This is the same integrity model as stig-scan:
an approval always refers to specific bytes a human actually read.

Status is split on purpose:

* ``review_status`` — whether a named person accepted the *draft wording*
  (unreviewed / approved / rejected).
* ``poam_status`` — the lifecycle of the item (draft / open / closed).

Approving a draft moves it from ``draft`` to ``open``. It does **not**
close the finding. Closing requires ``close`` with a name, a closure
kind, and a note. The authoring path never sets ``closed``.
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

DRAFT = "draft"
OPEN = "open"
CLOSED = "closed"

KIND_FINDING = "finding"
KIND_EVALUATION_GAP = "evaluation_gap"
KIND_MANUAL = "manual_inspection"

CLOSURE_REMEDIATED = "remediated"
CLOSURE_RISK_ACCEPTED = "risk_accepted"
CLOSURE_NOT_APPLICABLE = "not_applicable"
CLOSURE_KINDS = (CLOSURE_REMEDIATED, CLOSURE_RISK_ACCEPTED, CLOSURE_NOT_APPLICABLE)

SEVERITIES = ("high", "medium", "low")
REVIEW_STATES = (UNREVIEWED, APPROVED, REJECTED)
POAM_STATES = (DRAFT, OPEN, CLOSED)
KINDS = (KIND_FINDING, KIND_EVALUATION_GAP, KIND_MANUAL)


class PackError(RuntimeError):
    pass


@dataclass
class PoamEntry:
    stig_id: str
    group_id: str = ""
    severity: str = "medium"
    title: str = ""
    kind: str = KIND_FINDING
    weakness: str = ""
    description: str = ""
    recommendation: str = ""
    impact: str = ""
    resources: str = "TBD — a person must estimate"
    scheduled_completion: str = ""
    milestones: list[str] = field(default_factory=list)
    finding_status: str = "fail"
    scan_detail: str = ""
    actual: str = ""
    expected: str = ""
    comparator: str = ""
    command: str = ""
    trusted: bool = True
    triage: str = ""
    caution: str = ""
    source_pack: str = ""
    authored_by: str = "unknown"
    authored_at: str = ""
    author_confidence: str = "medium"
    author_note: str = ""
    review_status: str = UNREVIEWED
    reviewed_by: str | None = None
    reviewed_at: str | None = None
    review_note: str = ""
    approved_digest: str | None = None
    poam_status: str = DRAFT
    closure_kind: str = ""
    closed_by: str | None = None
    closed_at: str | None = None
    closure_note: str = ""

    def digest(self) -> str:
        """Hash over exactly the fields that determine the wording a person reviews."""
        payload = json.dumps(
            {
                "stig_id": self.stig_id,
                "kind": self.kind,
                "weakness": self.weakness,
                "description": self.description,
                "recommendation": self.recommendation,
                "impact": self.impact,
                "resources": self.resources,
                "scheduled_completion": self.scheduled_completion,
                "milestones": list(self.milestones),
                "finding_status": self.finding_status,
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

    def approve(self, by: str, at: str, note: str = "") -> None:
        by = (by or "").strip()
        if not by:
            raise PackError(f"{self.stig_id}: approval requires a person's name")
        if self.poam_status == CLOSED:
            raise PackError(
                f"{self.stig_id}: already closed; reopen it before changing the wording"
            )
        if not self.description.strip():
            raise PackError(f"{self.stig_id}: refusing to approve an empty description")
        self.review_status = APPROVED
        self.reviewed_by = by
        self.reviewed_at = at
        self.review_note = note
        self.approved_digest = self.digest()
        if self.poam_status == DRAFT:
            self.poam_status = OPEN

    def reject(self, by: str, at: str, note: str = "") -> None:
        by = (by or "").strip()
        if not by:
            raise PackError(f"{self.stig_id}: rejection requires a person's name")
        if self.poam_status == CLOSED:
            raise PackError(f"{self.stig_id}: already closed")
        self.review_status = REJECTED
        self.reviewed_by = by
        self.reviewed_at = at
        self.review_note = note
        self.approved_digest = None
        self.poam_status = DRAFT

    def close(self, by: str, at: str, kind: str, note: str) -> None:
        """Mark the item complete. Never called from the authoring path."""
        by = (by or "").strip()
        if not by:
            raise PackError(f"{self.stig_id}: closing requires a person's name")
        if kind not in CLOSURE_KINDS:
            raise PackError(
                f"{self.stig_id}: closure kind must be one of {', '.join(CLOSURE_KINDS)}"
            )
        if not (note or "").strip():
            raise PackError(
                f"{self.stig_id}: closing requires a note from the person who is accountable"
            )
        if self.review_status != APPROVED:
            raise PackError(
                f"{self.stig_id}: approve the draft before closing it"
            )
        if self.is_drifted():
            raise PackError(
                f"{self.stig_id}: wording drifted after approval; re-review before closing"
            )
        self.poam_status = CLOSED
        self.closure_kind = kind
        self.closed_by = by
        self.closed_at = at
        self.closure_note = note.strip()

    def reopen(self, by: str, at: str, note: str = "") -> None:
        by = (by or "").strip()
        if not by:
            raise PackError(f"{self.stig_id}: reopen requires a person's name")
        if self.poam_status != CLOSED:
            raise PackError(f"{self.stig_id}: not closed")
        self.poam_status = OPEN
        self.closure_kind = ""
        self.closed_by = None
        self.closed_at = None
        self.closure_note = ""
        self.review_note = note
        self.reviewed_by = by
        self.reviewed_at = at

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "PoamEntry":
        known = {f for f in cls.__dataclass_fields__}
        unknown = set(d) - known
        if unknown:
            raise PackError(
                f"{d.get('stig_id', '?')}: unknown field(s): {', '.join(sorted(unknown))}"
            )
        return cls(**{k: v for k, v in d.items() if k in known})


@dataclass
class PoamPack:
    pack_id: str
    stig_title: str = ""
    stig_version: str = ""
    source_scan: str = ""
    created: str = ""
    notes: str = ""
    pack_format: int = PACK_FORMAT
    platform: str = ""
    entries: list[PoamEntry] = field(default_factory=list)

    @classmethod
    def load(cls, path: str | Path) -> "PoamPack":
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
        entries = [PoamEntry.from_dict(e) for e in raw.get("entries", [])]
        seen: set[str] = set()
        for e in entries:
            if e.stig_id in seen:
                raise PackError(f"{path}: duplicate stig_id {e.stig_id}")
            seen.add(e.stig_id)
            if e.severity not in SEVERITIES:
                raise PackError(f"{e.stig_id}: unknown severity {e.severity!r}")
            if e.review_status not in REVIEW_STATES:
                raise PackError(f"{e.stig_id}: unknown review_status {e.review_status!r}")
            if e.poam_status not in POAM_STATES:
                raise PackError(f"{e.stig_id}: unknown poam_status {e.poam_status!r}")
            if e.kind not in KINDS:
                raise PackError(f"{e.stig_id}: unknown kind {e.kind!r}")
            if e.poam_status == CLOSED and e.closure_kind not in CLOSURE_KINDS:
                raise PackError(f"{e.stig_id}: closed entry is missing a valid closure kind")
        return cls(
            pack_id=raw.get("pack_id", path.stem),
            stig_title=raw.get("stig_title", ""),
            stig_version=raw.get("stig_version", ""),
            source_scan=raw.get("source_scan", ""),
            created=raw.get("created", ""),
            notes=raw.get("notes", ""),
            platform=raw.get("platform", ""),
            entries=entries,
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
            "entries": [asdict(e) for e in self.entries],
        }
        path.write_text(json.dumps(body, indent=2) + "\n", encoding="utf-8")

    def get(self, stig_id: str) -> PoamEntry | None:
        for e in self.entries:
            if e.stig_id == stig_id:
                return e
        return None

    def summary(self) -> dict[str, int]:
        s = {
            "total": len(self.entries),
            "findings": 0,
            "evaluation_gaps": 0,
            "manual": 0,
            "draft": 0,
            "open": 0,
            "closed": 0,
            "unreviewed": 0,
            "approved": 0,
            "rejected": 0,
            "drifted": 0,
            "untrusted": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }
        for e in self.entries:
            if e.kind == KIND_FINDING:
                s["findings"] += 1
            elif e.kind == KIND_EVALUATION_GAP:
                s["evaluation_gaps"] += 1
            elif e.kind == KIND_MANUAL:
                s["manual"] += 1
            s[e.poam_status] = s.get(e.poam_status, 0) + 1
            s[e.review_status] = s.get(e.review_status, 0) + 1
            if e.is_drifted():
                s["drifted"] += 1
            if not e.trusted:
                s["untrusted"] += 1
            if e.severity in s:
                s[e.severity] += 1
        return s
