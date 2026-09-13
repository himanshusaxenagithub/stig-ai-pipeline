"""Turn scan results into POA&M drafts. Deterministic; no model required.

The wording is a first draft a person can accept or rewrite. Filed
stig-explain annotations are attached when present so the weakness
statement uses the same plain English as the checklist. Nothing here
sets ``poam_status`` to closed, and a result that already *passed* is
never turned into a finding.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Any, Iterable

from .load import load_explanations, load_scan
from .poam import (
    DRAFT,
    KIND_EVALUATION_GAP,
    KIND_FINDING,
    KIND_MANUAL,
    UNREVIEWED,
    PoamEntry,
    PoamPack,
)

AUTHOR = "rule-based-assessor/1.0"

# Statuses that can become a draft. Pass never does. Skipped is a coverage
# gap, not a finding — it is summarised on the pack, not listed as a POA&M.
DEFAULT_STATUSES = frozenset({"fail"})
GAP_STATUSES = frozenset({"error", "manual"})

_IMPACT = {
    "high": (
        "CAT I — DISA's highest severity. The scan found a control whose "
        "failure most readily enables compromise."
    ),
    "medium": (
        "CAT II — a significant hardening control is not met. Address after "
        "any CAT I items, unless a documented local risk decision says otherwise."
    ),
    "low": (
        "CAT III — a recommended hardening control is not met. Record it and "
        "schedule it; do not treat it as the same urgency as CAT I."
    ),
}

_RESOURCES = "TBD — a person must estimate staff time, tools, and any outage"


def _today() -> str:
    return date.today().isoformat()


def draft_from_scan(
    scan: dict[str, Any],
    *,
    explanations: dict[str, dict[str, Any]] | None = None,
    include: Iterable[str] | None = None,
    pack_id: str | None = None,
    created: str | None = None,
    source_scan: str = "",
) -> PoamPack:
    """Build an unreviewed POA&M pack from a stig-scan report dict."""
    explanations = explanations or {}
    wanted = set(include) if include is not None else set(DEFAULT_STATUSES)
    unknown = wanted - ({"fail", "error", "manual", "skipped", "pass"})
    if unknown:
        raise ValueError(f"unknown status filter: {', '.join(sorted(unknown))}")
    if "pass" in wanted:
        # A pass is evidence the control is met. Drafting a POA&M for it
        # would invent a finding. The filter is accepted only so the CLI
        # can refuse it with a clear error rather than silently no-op.
        raise ValueError("refusing to draft POA&M entries for results that passed")

    results = scan.get("results") or []
    entries: list[PoamEntry] = []
    for raw in results:
        if not isinstance(raw, dict):
            continue
        status = (raw.get("status") or "").lower()
        if status not in wanted:
            continue
        entries.append(_entry_from_result(raw, explanations, created or _today(),
                                          scan.get("pack_id", "")))

    notes = (
        "Drafts only. Nothing is closed. A named person must approve each "
        "entry before it is an open POA&M item, and must close it explicitly. "
        "Passing results were not drafted."
    )
    platform = ""
    options = scan.get("options") or {}
    if isinstance(options, dict):
        platform = str(options.get("platform") or "")

    return PoamPack(
        pack_id=pack_id or (scan.get("pack_id") or "poam") + "-poam",
        stig_title=scan.get("stig_title") or "",
        stig_version=scan.get("stig_version") or "",
        source_scan=source_scan or scan.get("pack_id") or "",
        created=created or _today(),
        notes=notes,
        platform=platform,
        entries=entries,
    )


def draft_from_path(
    scan_path: str | Path,
    *,
    checklist: str | Path | None = None,
    annotations: str | Path | None = None,
    include: Iterable[str] | None = None,
    pack_id: str | None = None,
) -> PoamPack:
    scan = load_scan(scan_path)
    explanations = load_explanations(checklist, annotations)
    return draft_from_scan(
        scan,
        explanations=explanations,
        include=include,
        pack_id=pack_id,
        source_scan=str(scan_path),
    )


def _entry_from_result(
    raw: dict[str, Any],
    explanations: dict[str, dict[str, Any]],
    authored_at: str,
    source_pack: str,
) -> PoamEntry:
    sid = raw.get("stig_id") or ""
    status = (raw.get("status") or "").lower()
    title = raw.get("title") or sid
    expl = explanations.get(sid) or {}
    summary = (expl.get("summary") or "").strip()
    caution = (expl.get("caution") or "").strip()
    triage = (expl.get("triage") or "").strip()
    fix_text = (expl.get("fix_text") or "").strip()
    trusted = bool(raw.get("trusted", True))

    if status == "fail":
        kind = KIND_FINDING
        weakness = title
        description = _finding_description(raw, summary)
        recommendation = _finding_recommendation(fix_text, caution)
        confidence = "high" if summary else "medium"
        note = "plain-English summary taken from filed explanations" if summary else (
            "no filed explanation; wording is taken from the scan result only"
        )
    elif status == "error":
        kind = KIND_EVALUATION_GAP
        weakness = f"Evaluation gap — {title}"
        description = (
            f"The check for {sid} could not produce a compliance result: "
            f"{raw.get('detail') or 'no detail'}. This is not a finding. "
            "It is a gap in evidence and must not be counted as pass or fail."
        )
        recommendation = (
            "Repair the check, run it with the required privilege, or record "
            "a manual inspection. Then re-scan. Do not close this as remediated "
            "until a later scan (or a person) actually evaluates the rule."
        )
        confidence = "high"
        note = "error result — drafted as an evaluation gap, not a finding"
    else:
        kind = KIND_MANUAL
        weakness = f"Manual inspection required — {title}"
        description = (
            f"{sid} requires a person to inspect a GUI, interview, or document. "
            f"The scanner did not evaluate it. {raw.get('detail') or ''}"
        ).strip()
        recommendation = (
            "Complete the inspection described in the STIG check text and "
            "record the outcome. The scanner cannot close this for you."
        )
        confidence = "high"
        note = "manual result — drafted as an inspection item, not a machine finding"

    if not trusted:
        note = (note + "; UNTRUSTED — the underlying check was not human-approved").strip("; ")

    return PoamEntry(
        stig_id=sid,
        group_id=raw.get("group_id") or "",
        severity=raw.get("severity") or "medium",
        title=title,
        kind=kind,
        weakness=weakness,
        description=description,
        recommendation=recommendation,
        impact=_IMPACT.get(raw.get("severity") or "medium", _IMPACT["medium"]),
        resources=_RESOURCES,
        scheduled_completion="",
        milestones=[],
        finding_status=status,
        scan_detail=raw.get("detail") or "",
        actual=raw.get("actual") or "",
        expected=raw.get("expected") or "",
        comparator=raw.get("comparator") or "",
        command=raw.get("command") or "",
        trusted=trusted,
        triage=triage,
        caution=caution,
        source_pack=source_pack,
        authored_by=AUTHOR,
        authored_at=authored_at,
        author_confidence=confidence,
        author_note=note,
        review_status=UNREVIEWED,
        poam_status=DRAFT,
    )


def _finding_description(raw: dict[str, Any], summary: str) -> str:
    sid = raw.get("stig_id") or ""
    title = raw.get("title") or sid
    parts = [
        f"The scan found that {sid} is not met: {title.rstrip('.')}."
    ]
    if summary:
        parts.append(summary)
    detail = (raw.get("detail") or "").strip()
    if detail:
        parts.append(f"Scanner detail: {detail}")
    actual = (raw.get("actual") or "").strip()
    expected = (raw.get("expected") or "").strip()
    comparator = (raw.get("comparator") or "").strip()
    if expected or actual:
        bits = []
        if comparator and expected:
            bits.append(f"expected ({comparator}) {expected!r}")
        elif expected:
            bits.append(f"expected {expected!r}")
        if actual:
            bits.append(f"observed {actual!r}")
        parts.append("Measured result: " + "; ".join(bits) + ".")
    parts.append(
        "This entry is a draft. It is not closed, and it is not a decision "
        "to remediate, accept the risk, or mark the rule not applicable."
    )
    return " ".join(parts)


def _finding_recommendation(fix_text: str, caution: str) -> str:
    if fix_text:
        first = fix_text.strip().split("\n\n", 1)[0].strip()
        if len(first) > 600:
            first = first[:597].rstrip() + "…"
        rec = (
            "Start from the STIG fix text (first paragraph of the filed rule): "
            + first
        )
    else:
        rec = (
            "Read the official STIG fix text for this rule. Decide whether to "
            "remediate, accept the residual risk, or mark the rule not "
            "applicable. The assessor will not make that decision."
        )
    if caution:
        rec += f" Caution from the filed explanation: {caution}"
    return rec
