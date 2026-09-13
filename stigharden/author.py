"""Author unreviewed remediation drafts from a scan report."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from typing import Any

from stigassess.load import load_explanations, load_scan

from .pack import (
    MODE_MANUAL,
    MODE_SCRIPT,
    MODE_UNSUPPORTED,
    NEVER_APPLIED,
    UNREVIEWED,
    Remediation,
    RemediationPack,
)
from .safety import audit, high_risk
from .shapes import invert

AUTHOR = "rule-based-hardener/1.0"


def _today() -> str:
    return date.today().isoformat()


def _language_for(platform: str) -> str:
    return "powershell" if platform == "windows" else "shell"


def _platform_of(scan: dict[str, Any], fallback: str = "") -> str:
    options = scan.get("options") or {}
    if isinstance(options, dict) and options.get("platform"):
        return str(options["platform"])
    host = scan.get("host") or {}
    system = str(host.get("system") or "").lower()
    if "darwin" in system or "macos" in system:
        return "macos"
    if "windows" in system:
        return "windows"
    if "linux" in system:
        return "linux"
    return fallback or "macos"


def load_check_index(pack_path: str | Path | None) -> dict[str, dict[str, Any]]:
    if not pack_path:
        return {}
    raw = json.loads(Path(pack_path).read_text(encoding="utf-8"))
    out = {}
    for c in raw.get("checks") or []:
        if isinstance(c, dict) and c.get("stig_id"):
            out[c["stig_id"]] = c
    return out


def author_from_scan(
    scan: dict[str, Any],
    *,
    explanations: dict[str, dict[str, Any]] | None = None,
    checks: dict[str, dict[str, Any]] | None = None,
    platform: str | None = None,
    pack_id: str | None = None,
    created: str | None = None,
    source_scan: str = "",
) -> RemediationPack:
    explanations = explanations or {}
    checks = checks or {}
    plat = platform or _platform_of(scan)
    rows: list[Remediation] = []
    for raw in scan.get("results") or []:
        if not isinstance(raw, dict):
            continue
        if (raw.get("status") or "").lower() != "fail":
            continue
        rows.append(_from_result(raw, explanations, checks, plat, created or _today()))

    return RemediationPack(
        pack_id=pack_id or (scan.get("pack_id") or "harden") + "-harden",
        stig_title=scan.get("stig_title") or "",
        stig_version=scan.get("stig_version") or "",
        source_scan=source_scan or scan.get("pack_id") or "",
        created=created or _today(),
        notes=(
            "Drafts only. Nothing has been applied. A named person must "
            "approve each script; apply defaults to dry-run and is refused "
            "in CI."
        ),
        platform=plat,
        remediations=rows,
    )


def author_from_path(
    scan_path: str | Path,
    *,
    checklist: str | Path | None = None,
    annotations: str | Path | None = None,
    checkpack: str | Path | None = None,
    platform: str | None = None,
    pack_id: str | None = None,
) -> RemediationPack:
    scan = load_scan(scan_path)
    return author_from_scan(
        scan,
        explanations=load_explanations(checklist, annotations),
        checks=load_check_index(checkpack),
        platform=platform,
        pack_id=pack_id,
        source_scan=str(scan_path),
    )


def _from_result(
    raw: dict[str, Any],
    explanations: dict[str, dict[str, Any]],
    checks: dict[str, dict[str, Any]],
    platform: str,
    authored_at: str,
) -> Remediation:
    sid = raw.get("stig_id") or ""
    expl = explanations.get(sid) or {}
    chk = checks.get(sid) or {}
    command = raw.get("command") or chk.get("command") or ""
    expected = raw.get("expected") or chk.get("expected") or ""
    comparator = raw.get("comparator") or chk.get("comparator") or ""
    source = chk.get("expected_source") or ""
    title = raw.get("title") or expl.get("title") or sid
    fix_text = expl.get("fix_text") or ""
    caution = expl.get("caution") or ""

    hit = invert(
        platform=platform,
        command=command,
        comparator=comparator,
        expected=expected,
        expected_source=source,
        fix_text=fix_text,
        title=title,
    )

    rec = Remediation(
        stig_id=sid,
        group_id=raw.get("group_id") or chk.get("group_id") or "",
        severity=raw.get("severity") or "medium",
        title=title,
        platform=platform,
        language=_language_for(platform),
        check_command=command,
        expected=expected,
        comparator=comparator,
        actual=raw.get("actual") or "",
        finding_status="fail",
        authored_by=AUTHOR,
        authored_at=authored_at,
        review_status=UNREVIEWED,
        apply_status=NEVER_APPLIED,
    )

    if hit is None:
        rec.mode = MODE_MANUAL if (fix_text or command) else MODE_UNSUPPORTED
        rec.language = "none"
        rec.script = ""
        rec.rationale = _manual_rationale(fix_text, caution, title)
        rec.author_confidence = "low"
        rec.author_note = (
            "no invertible check shape (registry / sysctl / defaults / "
            "auditpol / quoted fix-text command) — needs a person"
        )
        rec.shape = "none"
        return rec

    problems = audit(hit.script)
    if problems:
        rec.mode = MODE_MANUAL
        rec.language = "none"
        rec.script = ""
        rec.rationale = (
            _manual_rationale(fix_text, caution, title)
            + " A candidate script was refused by the remediation safety gate: "
            + "; ".join(problems)
        )
        rec.author_confidence = "low"
        rec.author_note = "safety gate refused the inverted script"
        rec.shape = hit.shape
        return rec

    if hit.high_risk or high_risk(hit.script):
        rec.mode = MODE_MANUAL
        rec.language = "none"
        rec.script = ""
        rec.rationale = (
            "This change is high-impact (SIP, FileVault, a full policy "
            "template, or firmware). Suggested command, for a person to "
            f"consider and run themselves if they accept the risk:\n\n{hit.script}"
        )
        rec.author_confidence = "low"
        rec.author_note = "high-risk form kept manual; apply will not run it"
        rec.shape = hit.shape
        rec.requires_root = True
        return rec

    rec.mode = MODE_SCRIPT
    rec.language = hit.language
    rec.script = hit.script
    rec.shape = hit.shape
    rec.requires_root = hit.requires_root
    rec.author_confidence = hit.confidence
    rec.author_note = hit.note
    rec.rationale = _script_rationale(title, expected, caution)
    return rec


def _script_rationale(title: str, expected: str, caution: str) -> str:
    bits = [
        f"Draft fix for a failed check: {title.rstrip('.')}.",
        "The script writes the value the check expected"
        + (f" ({expected})" if expected else "")
        + ". It has not been applied.",
    ]
    if caution:
        bits.append(f"Filed caution: {caution}")
    bits.append(
        "A named person must read the script, approve it, and only then "
        "choose to apply. Dry-run is the default."
    )
    return " ".join(bits)


def _manual_rationale(fix_text: str, caution: str, title: str) -> str:
    bits = [
        f"No safe invertible script was authored for: {title.rstrip('.')}.",
        "Use the official STIG fix text and decide whether to change the "
        "system, accept the risk, or mark the rule not applicable.",
    ]
    if fix_text:
        first = fix_text.strip().split("\n\n", 1)[0].strip()
        if len(first) > 500:
            first = first[:497].rstrip() + "…"
        bits.append("Fix text (first paragraph): " + first)
    if caution:
        bits.append("Filed caution: " + caution)
    return " ".join(bits)
