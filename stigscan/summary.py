"""Plain-language scan summary: remaining risk among what we could check.

A pass rate is not a security score. CAT I failures are treated as
Critical regardless of how many other rules passed. When nothing was
evaluated, we refuse to assign a risk level. Coverage is always stated
separately so silence is not mistaken for compliance.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

from .evaluate import ERROR, FAIL, MANUAL, PASS, SKIPPED

RISK_CRITICAL = "critical"
RISK_HIGH = "high"
RISK_MODERATE = "moderate"
RISK_LOW = "low"
RISK_INCOMPLETE = "incomplete"

RISK_LABEL = {
    RISK_CRITICAL: "Critical",
    RISK_HIGH: "High",
    RISK_MODERATE: "Moderate",
    RISK_LOW: "Low",
    RISK_INCOMPLETE: "Incomplete",
}

_CAT = {"high": "CAT I", "medium": "CAT II", "low": "CAT III"}


@dataclass
class ScanSummary:
    """Honest remaining-risk story for the UI, Markdown, and PDF."""

    risk: str
    risk_label: str
    headline: str
    meaning: str
    next_step: str
    coverage_line: str
    judged_line: str
    evaluated: int
    not_evaluated: int
    total: int
    coverage_pct: float
    fail_rate_pct: float | None
    counts: dict[str, int] = field(default_factory=dict)
    fails_by_severity: dict[str, int] = field(default_factory=dict)
    untrusted: int = 0
    serious_fails: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def summarize_report(report) -> ScanSummary:
    """Build a summary from a ScanReport (or any object with .results / .counts())."""
    counts = report.counts()
    fails_by_severity = {"high": 0, "medium": 0, "low": 0}
    serious: list[dict] = []
    untrusted = 0
    for r in report.results:
        if r.status == FAIL:
            if r.severity in fails_by_severity:
                fails_by_severity[r.severity] += 1
            if r.severity == "high":
                serious.append({"stig_id": r.stig_id, "title": r.title, "cat": "CAT I"})
        if not getattr(r, "trusted", True) and r.status in (PASS, FAIL):
            untrusted += 1
    return summarize(
        counts=counts,
        total=len(report.results),
        fails_by_severity=fails_by_severity,
        untrusted=untrusted,
        serious_fails=serious,
    )


def summarize(*, counts: dict[str, int], total: int,
              fails_by_severity: dict[str, int] | None = None,
              untrusted: int = 0,
              serious_fails: list[dict] | None = None) -> ScanSummary:
    """Decide remaining risk from outcome counts and fail-by-severity."""
    c = {
        PASS: int(counts.get(PASS, 0) or 0),
        FAIL: int(counts.get(FAIL, 0) or 0),
        ERROR: int(counts.get(ERROR, 0) or 0),
        MANUAL: int(counts.get(MANUAL, 0) or 0),
        SKIPPED: int(counts.get(SKIPPED, 0) or 0),
    }
    evaluated = c[PASS] + c[FAIL]
    if total <= 0:
        total = sum(c.values())
    not_evaluated = max(0, total - evaluated)
    coverage_pct = (evaluated / total * 100) if total else 0.0
    fail_rate = (c[FAIL] / evaluated * 100) if evaluated else None
    by_sev = {"high": 0, "medium": 0, "low": 0}
    src = fails_by_severity or {}
    for key in by_sev:
        by_sev[key] = int(src.get(key, 0) or 0)
    # If the caller only gave a fail total, keep the leftover uncategorised
    # out of the CAT buckets rather than inventing a severity.
    cat1, cat2, cat3 = by_sev["high"], by_sev["medium"], by_sev["low"]

    risk = _risk(evaluated, c[FAIL], fail_rate, cat1, cat2, cat3)
    coverage_line = (
        f"{evaluated} of {total} rules ({coverage_pct:.1f}%) were actually evaluated "
        "on this host. The remaining results produced no compliance evidence "
        "and must not be counted as either compliant or non-compliant."
    )
    if evaluated:
        judged_line = (
            f"{c[FAIL]} of {evaluated} checks we could judge still fail "
            f"({fail_rate:.1f}%)."
            if c[FAIL] else
            f"All {evaluated} checks we could judge met the requirement."
        )
    else:
        judged_line = "No rule produced a pass or fail, so remaining risk cannot be judged."

    headline, meaning, next_step = _copy(
        risk, evaluated, not_evaluated, total, coverage_pct,
        c[PASS], c[FAIL], fail_rate, cat1, cat2, cat3,
    )
    return ScanSummary(
        risk=risk,
        risk_label=RISK_LABEL[risk],
        headline=headline,
        meaning=meaning,
        next_step=next_step,
        coverage_line=coverage_line,
        judged_line=judged_line,
        evaluated=evaluated,
        not_evaluated=not_evaluated,
        total=total,
        coverage_pct=round(coverage_pct, 1),
        fail_rate_pct=None if fail_rate is None else round(fail_rate, 1),
        counts=c,
        fails_by_severity=by_sev,
        untrusted=untrusted,
        serious_fails=list(serious_fails or []),
    )


def text_bar(value: int, maximum: int, width: int = 22) -> str:
    """ASCII bar safe for Helvetica / latin-1 PDFs."""
    value = max(0, int(value or 0))
    maximum = max(0, int(maximum or 0))
    if maximum <= 0 or value <= 0:
        filled = 0
    else:
        filled = round(width * value / maximum)
        filled = max(1, min(width, filled))
    return "[" + "#" * filled + "." * (width - filled) + "]"


def breakdown_rows(summary: ScanSummary) -> list[tuple[str, str, str]]:
    """Rows for the visual-friendly breakdown: (label, bar, caption)."""
    c = summary.counts
    mix_max = max(c.get(PASS, 0), c.get(FAIL, 0), c.get(ERROR, 0),
                  c.get(MANUAL, 0) + c.get(SKIPPED, 0), 1)
    not_run = c.get(MANUAL, 0) + c.get(SKIPPED, 0)
    rows = [
        ("Met the requirement", text_bar(c.get(PASS, 0), mix_max), str(c.get(PASS, 0))),
        ("Did not", text_bar(c.get(FAIL, 0), mix_max), str(c.get(FAIL, 0))),
        ("Could not be judged", text_bar(c.get(ERROR, 0), mix_max), str(c.get(ERROR, 0))),
        ("Not run", text_bar(not_run, mix_max), str(not_run)),
    ]
    return rows


def severity_rows(summary: ScanSummary) -> list[tuple[str, str, str]]:
    """Fail-by-severity bars: (label, bar, caption)."""
    by = summary.fails_by_severity
    peak = max(by.get("high", 0), by.get("medium", 0), by.get("low", 0), 1)
    return [
        ("CAT I (most serious)", text_bar(by.get("high", 0), peak), str(by.get("high", 0))),
        ("CAT II", text_bar(by.get("medium", 0), peak), str(by.get("medium", 0))),
        ("CAT III", text_bar(by.get("low", 0), peak), str(by.get("low", 0))),
    ]


def coverage_rows(summary: ScanSummary) -> list[tuple[str, str, str]]:
    peak = max(summary.evaluated, summary.not_evaluated, 1)
    return [
        ("Evaluated", text_bar(summary.evaluated, peak),
         f"{summary.evaluated} of {summary.total} ({summary.coverage_pct:.1f}%)"),
        ("Not evaluated", text_bar(summary.not_evaluated, peak),
         str(summary.not_evaluated)),
    ]


def _risk(evaluated: int, fails: int, fail_rate: float | None,
          cat1: int, cat2: int, cat3: int) -> str:
    if evaluated <= 0:
        return RISK_INCOMPLETE
    if cat1 > 0:
        return RISK_CRITICAL
    rate = fail_rate or 0.0
    if cat2 >= 3 or rate >= 50:
        return RISK_HIGH
    if cat2 >= 1 or cat3 >= 3 or rate >= 15:
        return RISK_MODERATE
    return RISK_LOW


def _copy(risk: str, evaluated: int, not_evaluated: int, total: int,
          coverage_pct: float, passed: int, fails: int,
          fail_rate: float | None, cat1: int, cat2: int, cat3: int):
    gap = (
        f"We only evaluated {evaluated} of {total} rules ({coverage_pct:.1f}%). "
        f"The other {not_evaluated} produced no yes-or-no evidence and must not "
        "be counted as compliant."
        if not_evaluated else
        "Every rule in this pack produced a yes-or-no answer."
    )
    if risk == RISK_INCOMPLETE:
        return (
            "We could not judge this computer.",
            "None of the STIG rules produced a pass or fail. Skipped, manual, "
            "and error results are not evidence that the machine is secure or "
            "insecure. Approve read-only checks under your name and scan again.",
            "Open Checks, read each command, approve it under your own name, "
            "then run the scan.",
        )
    if risk == RISK_CRITICAL:
        n = f"{cat1} CAT I finding" + ("" if cat1 == 1 else "s")
        return (
            f"Critical remaining risk — {n} among the rules we could check.",
            f"Among the {evaluated} rules we could judge, {fails} did not meet "
            f"the requirement ({(fail_rate or 0):.1f}%), including {n}. "
            "CAT I is DISA's highest severity: these are the settings most "
            f"likely to be exploited. {gap} This is remaining risk among what "
            "we checked, not a percentage of how secure the laptop is.",
            "Start with the CAT I failures in the list below, then work "
            "through the other failing rules toward STIG compliance.",
        )
    if risk == RISK_HIGH:
        extra = (f" including {cat2} important (CAT II) setting"
                 + ("" if cat2 == 1 else "s") + ".") if cat2 else "."
        return (
            f"High remaining risk among what we checked — "
            f"{fails} of {evaluated} still fail.",
            f"{fails} of {evaluated} checks we could judge still fail "
            f"({(fail_rate or 0):.1f}%){extra} {gap} "
            "That is not a score of how secure the machine is overall.",
            "Work through the failing rules below, highest severity first, "
            "and fix toward STIG compliance.",
        )
    if risk == RISK_MODERATE:
        return (
            f"Moderate remaining risk — {fails} of {evaluated} checks "
            "we ran still fail.",
            f"Among the {evaluated} rules we could judge, {fails} did not meet "
            f"the requirement ({(fail_rate or 0):.1f}%). "
            f"{_sev_clause(cat1, cat2, cat3)} {gap}",
            "Review the failing rules below and fix the highest-severity "
            "ones first.",
        )
    # Low
    if fails == 0:
        if not_evaluated:
            return (
                f"No failures among the {evaluated} rules we could check.",
                f"Every rule that produced a yes-or-no answer met the "
                f"requirement ({passed} pass). That is not a clean bill of "
                f"health: {not_evaluated} of {total} rules "
                f"({100 - coverage_pct:.1f}%) were not evaluated, so they "
                "must not be counted as compliant.",
                "Approve more checks and scan again to close the coverage gap.",
            )
        return (
            "No failures on the rules we checked — and we checked every rule "
            "in this pack.",
            f"All {evaluated} rules met the requirement. Keep the approved "
            "checks and re-scan after any system change.",
            "Download the report and keep it with the approved check pack.",
        )
    return (
        f"Low remaining risk among what we checked — {fails} lower-severity "
        f"check{'s' if fails != 1 else ''} failed.",
        f"Among the {evaluated} rules we could judge, {fails} did not meet "
        f"the requirement, and none were CAT I or a large CAT II group. {gap}",
        "The remaining failures are lower severity. Fix them when you can "
        "and re-scan.",
    )


def _sev_clause(cat1: int, cat2: int, cat3: int) -> str:
    parts = []
    if cat1:
        parts.append(f"{cat1} CAT I")
    if cat2:
        parts.append(f"{cat2} CAT II")
    if cat3:
        parts.append(f"{cat3} CAT III")
    if not parts:
        return ""
    return "Fails by severity: " + ", ".join(parts) + "."
