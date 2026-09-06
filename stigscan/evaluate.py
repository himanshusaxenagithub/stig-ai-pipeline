"""Turn raw command output into a compliance verdict.

Verdicts are deliberately coarse. A check either demonstrates compliance,
demonstrates non-compliance, or fails to demonstrate anything — and the
third case is reported as ERROR rather than being folded into "fail".
Silently reporting an unrunnable check as a finding is how automated
compliance tooling loses an auditor's trust.
"""

from __future__ import annotations

import re

PASS = "pass"
FAIL = "fail"
ERROR = "error"
MANUAL = "manual"
SKIPPED = "skipped"


class EvalError(ValueError):
    pass


def _as_int(text: str) -> int:
    try:
        return int(text.strip())
    except (TypeError, ValueError) as e:
        raise EvalError(f"expected an integer, got {text.strip()!r}") from e


def evaluate(stdout: str, comparator: str, expected: str) -> tuple[str, str]:
    """Return (verdict, human-readable explanation)."""
    actual = (stdout or "").strip()
    want = (expected or "").strip()

    if comparator == "equals":
        ok = actual == want
        return (PASS if ok else FAIL, f"got {actual!r}, expected {want!r}")

    if comparator == "not_equals":
        # "Anything but X" is only evidence if there *was* an answer. Empty
        # output means the command produced nothing to judge, not compliance.
        if not actual:
            return (ERROR, f"no output to evaluate (expected anything but {want!r})")
        ok = actual != want
        return (PASS if ok else FAIL, f"got {actual!r}, expected anything but {want!r}")

    if comparator == "contains":
        ok = want in actual
        return (PASS if ok else FAIL, f"{'found' if ok else 'did not find'} {want!r} in output")

    if comparator == "regex":
        try:
            ok = re.search(want, actual, re.M) is not None
        except re.error as e:
            raise EvalError(f"bad regex {want!r}: {e}") from e
        return (PASS if ok else FAIL, f"pattern {want!r} {'matched' if ok else 'did not match'}")

    if comparator in ("int_eq", "int_ge", "int_le"):
        a, w = _as_int(actual), _as_int(want)
        ok = {"int_eq": a == w, "int_ge": a >= w, "int_le": a <= w}[comparator]
        sym = {"int_eq": "==", "int_ge": ">=", "int_le": "<="}[comparator]
        return (PASS if ok else FAIL, f"{a} {sym} {w} is {ok}")

    if comparator == "nonempty":
        ok = bool(actual)
        return (PASS if ok else FAIL, "output was non-empty" if ok else "output was empty")

    if comparator == "empty":
        ok = not actual
        return (PASS if ok else FAIL, "output was empty" if ok else f"output was {actual!r}")

    raise EvalError(f"unknown comparator {comparator!r}")
