"""Apply path: dry-run by default, refused in CI, never unreviewed.

``apply`` is the only command that might change a system. It still
defaults to printing what would run. ``--apply-for-real`` requires a
named person, ``--i-have-reviewed``, an approved (not drifted) script,
a clean safety gate, and a non-CI environment. Tests and GitHub Actions
never need a live host.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from typing import Callable

from .pack import APPROVED, MODE_SCRIPT, Remediation, RemediationPack
from .safety import audit


class ApplyError(RuntimeError):
    pass


def in_ci(env: dict[str, str] | None = None) -> bool:
    env = env if env is not None else os.environ
    for key in ("CI", "GITHUB_ACTIONS", "GITLAB_CI", "BUILD_ID"):
        if env.get(key, "").strip().lower() in {"1", "true", "yes"}:
            return True
    return False


Runner = Callable[[str, str], tuple[int, str, str]]


def _default_runner(language: str, script: str) -> tuple[int, str, str]:
    if language == "powershell":
        cmd = ["pwsh", "-NoProfile", "-NonInteractive", "-Command", script]
    else:
        cmd = ["/bin/sh", "-c", script]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.returncode, proc.stdout, proc.stderr


@dataclass
class ApplyResult:
    stig_id: str
    dry_run: bool
    ok: bool
    detail: str
    returncode: int | None = None
    stdout: str = ""
    stderr: str = ""


@dataclass
class ApplyReport:
    applied: list[ApplyResult] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return all(r.ok for r in self.applied)


def apply_ids(
    pack: RemediationPack,
    ids: list[str],
    *,
    by: str,
    at: str,
    i_have_reviewed: bool,
    apply_for_real: bool = False,
    runner: Runner | None = None,
    env: dict[str, str] | None = None,
) -> ApplyReport:
    by = (by or "").strip()
    if not by:
        raise ApplyError("apply requires a person's name (--by)")
    if not i_have_reviewed:
        raise ApplyError("refusing to apply without --i-have-reviewed")
    if apply_for_real and in_ci(env):
        raise ApplyError(
            "refusing --apply-for-real in CI; draft, show, or dry-run instead"
        )

    report = ApplyReport()
    run = runner or _default_runner
    for sid in ids:
        rec = pack.get(sid)
        if rec is None:
            raise ApplyError(f"{sid} is not in this pack")
        report.applied.append(
            _one(rec, by=by, at=at, apply_for_real=apply_for_real, run=run)
        )
    return report


def _one(
    rec: Remediation,
    *,
    by: str,
    at: str,
    apply_for_real: bool,
    run: Runner,
) -> ApplyResult:
    if rec.mode != MODE_SCRIPT or not rec.script.strip():
        raise ApplyError(
            f"{rec.stig_id}: no executable script (mode is {rec.mode!r})"
        )
    if rec.review_status != APPROVED:
        raise ApplyError(f"{rec.stig_id}: not approved — show the script and approve it first")
    if rec.is_drifted():
        raise ApplyError(f"{rec.stig_id}: script drifted after approval; re-review")
    problems = audit(rec.script)
    if problems:
        raise ApplyError(f"{rec.stig_id}: blocked by safety gate: {'; '.join(problems)}")

    if not apply_for_real:
        rec.mark_apply(by, at, "dry_run", "dry-run only; nothing was executed")
        return ApplyResult(
            stig_id=rec.stig_id,
            dry_run=True,
            ok=True,
            detail="dry-run — script not executed",
        )

    code, out, err = run(rec.language, rec.script)
    ok = code == 0
    rec.mark_apply(
        by, at, "applied",
        f"exit {code}" + ("" if ok else f": {err.strip()[:200]}"),
    )
    return ApplyResult(
        stig_id=rec.stig_id,
        dry_run=False,
        ok=ok,
        detail=f"executed; exit {code}",
        returncode=code,
        stdout=out,
        stderr=err,
    )


__all__ = [
    "ApplyError",
    "ApplyReport",
    "ApplyResult",
    "apply_ids",
    "in_ci",
]
