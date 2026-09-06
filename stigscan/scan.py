"""Scan orchestration: decide, for every check, what may be executed and why.

Most of this module is refusal logic, and that is intentional. The value of
an automated compliance scan lies less in running checks than in being
precise about which checks did *not* run, so that nobody mistakes silence
for compliance. Every check that is skipped is reported with the reason.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any

from .evaluate import evaluate, EvalError, PASS, FAIL, ERROR, MANUAL, SKIPPED
from .pack import CheckPack, Check, APPROVED, REJECTED, MODE_SHELL, MODE_MANUAL
from .runner import host_facts
from .safety import audit

SEVERITY_LABEL = {"high": "CAT I", "medium": "CAT II", "low": "CAT III"}


@dataclass
class Result:
    stig_id: str
    group_id: str
    severity: str
    title: str
    status: str
    detail: str = ""
    command: str = ""
    expected: str = ""
    comparator: str = ""
    actual: str = ""
    stderr: str = ""
    returncode: int | None = None
    trusted: bool = True      # False when an unreviewed check was force-run
    review_status: str = ""
    source: str = ""          # live | fixture | none


@dataclass
class ScanReport:
    pack_id: str
    stig_title: str
    stig_version: str
    started: str
    finished: str = ""
    host: dict[str, str] = field(default_factory=dict)
    options: dict[str, Any] = field(default_factory=dict)
    results: list[Result] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        c = {PASS: 0, FAIL: 0, ERROR: 0, MANUAL: 0, SKIPPED: 0}
        for r in self.results:
            c[r.status] = c.get(r.status, 0) + 1
        return c

    def cat1_failures(self) -> list[Result]:
        return [r for r in self.results if r.status == FAIL and r.severity == "high"]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["counts"] = self.counts()
        return d


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _skip(chk: Check, detail: str) -> Result:
    return Result(
        stig_id=chk.stig_id, group_id=chk.group_id, severity=chk.severity,
        title=chk.title, status=SKIPPED, detail=detail,
        review_status=chk.review_status, source="none",
    )


def run_scan(pack: CheckPack, runner, *, include_unreviewed: bool = False,
             only_ids: set[str] | None = None,
             severities: set[str] | None = None) -> ScanReport:
    facts = host_facts()
    is_root = facts.get("euid") == "0"

    report = ScanReport(
        pack_id=pack.pack_id,
        stig_title=pack.stig_title,
        stig_version=pack.stig_version,
        started=_now(),
        host=facts,
        options={
            "platform": pack.platform,
            "include_unreviewed": include_unreviewed,
            "only_ids": sorted(only_ids) if only_ids else None,
            "severities": sorted(severities) if severities else None,
            "runner": type(runner).__name__,
        },
    )

    for chk in pack.checks:
        if only_ids and chk.stig_id not in only_ids:
            continue
        if severities and chk.severity not in severities:
            continue

        if chk.mode == MODE_MANUAL:
            report.results.append(Result(
                stig_id=chk.stig_id, group_id=chk.group_id, severity=chk.severity,
                title=chk.title, status=MANUAL,
                detail="requires human inspection; see manual_instruction in the pack",
                review_status=chk.review_status, source="none",
            ))
            continue

        if chk.mode != MODE_SHELL:
            report.results.append(_skip(chk, f"not automatable ({chk.author_note or chk.mode})"))
            continue

        if chk.is_drifted():
            report.results.append(_skip(
                chk, "APPROVAL DRIFTED — content changed after approval; re-review required"))
            continue

        if chk.review_status == REJECTED:
            report.results.append(_skip(chk, f"rejected in review: {chk.review_note or 'no note'}"))
            continue

        trusted = chk.review_status == APPROVED
        if not trusted and not include_unreviewed:
            report.results.append(_skip(
                chk, "unreviewed — approve it, or re-run with --include-unreviewed"))
            continue

        # The safety gate is enforced here, not only inside ShellRunner, so
        # that a check judged unsafe is never reported as a compliance result
        # no matter which runner produced its output.
        problems = audit(chk.command, pack.platform)
        if problems:
            report.results.append(Result(
                stig_id=chk.stig_id, group_id=chk.group_id, severity=chk.severity,
                title=chk.title, status=ERROR, command=chk.command,
                detail="blocked by safety gate: " + "; ".join(problems),
                trusted=trusted, review_status=chk.review_status, source="none",
            ))
            continue

        if chk.requires_root and not is_root:
            report.results.append(_skip(
                chk, "requires root; re-run the scan with sudo to evaluate this check"))
            continue

        run = runner.run(chk.stig_id, chk.command)
        base = dict(
            stig_id=chk.stig_id, group_id=chk.group_id, severity=chk.severity,
            title=chk.title, command=chk.command, expected=chk.expected,
            comparator=chk.comparator, actual=run.stdout.strip(),
            stderr=run.stderr.strip()[:500], returncode=run.returncode,
            trusted=trusted, review_status=chk.review_status, source=run.source,
        )

        if run.error:
            report.results.append(Result(status=ERROR, detail=run.error, **base))
            continue

        try:
            verdict, detail = evaluate(run.stdout, chk.comparator, chk.expected)
        except EvalError as e:
            report.results.append(Result(status=ERROR, detail=str(e), **base))
            continue

        report.results.append(Result(status=verdict, detail=detail, **base))

    report.finished = _now()
    return report
