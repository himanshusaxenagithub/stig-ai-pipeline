"""Invert known check shapes into remediation drafts.

DISA's check text (and the stig-scan extractor) already encode a small
set of regular shapes: a registry Get, a sysctl query, a defaults read,
an auditpol /get. Where the expected value is unambiguous, the inverse
is a single write. Everything else stays manual or unsupported rather
than guessed.

Fix text from a stig-prep checklist is preferred when it already
contains one of those same mutating forms — that is DISA's own command,
not an invention.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .safety import audit, high_risk

_GET_ITEM = re.compile(
    r"Get-ItemProperty\s+-Path\s+'([^']+)'\s+-Name\s+'([^']+)'",
    re.I,
)
_AUDITPOL_GET = re.compile(
    r"auditpol\s+/get\s+/subcategory:\"([^\"]+)\"",
    re.I,
)
_SYSCTL = re.compile(
    r"(?:^|[;&\n])\s*(?:sudo\s+)?(?:/(?:usr/)?s?bin/)?sysctl\s+([\w.-]+)\s*$",
    re.I | re.M,
)
_DEFAULTS_READ = re.compile(
    r"(?:/(?:usr/)?bin/)?defaults\s+read\s+(\S+)\s+(\S+)",
    re.I,
)
_SYSTEMCTL_IS = re.compile(
    r"(?:^|[;&\n])\s*(?:sudo\s+)?systemctl\s+is-(enabled|active)\s+(\S+)",
    re.I | re.M,
)
_LAUNCHCTL_PRINT = re.compile(
    r"launchctl\s+print\s+(system|gui/\$UID)/([\w.-]+)",
    re.I,
)

_FIX_DEFAULTS_WRITE = re.compile(
    r"(?:/(?:usr/)?bin/)?defaults\s+write\s+\S+\s+\S+[^\n]*",
    re.I,
)
_FIX_SET_ITEM = re.compile(
    r"Set-ItemProperty\s+-Path\s+'[^']+'\s+-Name\s+'[^']+'[^\n]*",
    re.I,
)
_FIX_SYSCTL_W = re.compile(
    r"(?:sudo\s+)?sysctl\s+-w\s+[\w.-]+=\S+",
    re.I,
)
_SET_TO = re.compile(r'set to ["\']?([^"\']+)["\']?', re.I)
_QUOTED_NUM = re.compile(r'"(\d+)"')


@dataclass
class ShapeHit:
    script: str
    language: str
    shape: str
    confidence: str
    note: str
    requires_root: bool = False
    high_risk: bool = False


def invert(
    *,
    platform: str,
    command: str,
    comparator: str,
    expected: str,
    expected_source: str = "",
    fix_text: str = "",
    title: str = "",
) -> ShapeHit | None:
    """Return a draft script, or None if no known shape matched."""
    from_fix = _from_fix_text(fix_text, platform)
    if from_fix:
        return from_fix

    platform = (platform or "").lower()
    if platform == "windows":
        return _windows(command, comparator, expected, expected_source)
    if platform == "linux":
        return _linux(command, comparator, expected, expected_source, title)
    return _macos(command, comparator, expected, expected_source, title)


def _from_fix_text(fix_text: str, platform: str) -> ShapeHit | None:
    if not (fix_text or "").strip():
        return None
    language = "powershell" if platform == "windows" else "shell"
    for label, rx in (
        ("fix-text-defaults-write", _FIX_DEFAULTS_WRITE),
        ("fix-text-set-itemproperty", _FIX_SET_ITEM),
        ("fix-text-sysctl-w", _FIX_SYSCTL_W),
    ):
        m = rx.search(fix_text)
        if not m:
            continue
        script = m.group(0).strip()
        if audit(script):
            continue
        risk = bool(high_risk(script))
        return ShapeHit(
            script=script,
            language="powershell" if "Set-ItemProperty" in script else language,
            shape=label,
            confidence="medium",
            note="command taken from the STIG fix text; confirm it is the whole fix",
            requires_root=True,
            high_risk=risk,
        )
    return None


def _windows(command, comparator, expected, source) -> ShapeHit | None:
    m = _GET_ITEM.search(command or "")
    if m and comparator in {"equals", "int_eq", "int_ge", "int_le"} and expected:
        path, name = m.group(1), m.group(2)
        if re.fullmatch(r"-?\d+", expected):
            typ, val = "DWord", expected
        else:
            typ, val = "String", expected.replace("'", "''")
            val = f"'{val}'"
        conf = "high" if comparator == "equals" else "medium"
        note = "inverted from Get-ItemProperty"
        if comparator in {"int_ge", "int_le"}:
            note += f" ({comparator} {expected} — written as that bound; confirm the STIG accepts a range)"
        script = (
            f"if (-not (Test-Path -Path '{path}')) {{ "
            f"New-Item -Path '{path}' -Force | Out-Null }}\n"
            f"Set-ItemProperty -Path '{path}' -Name '{name}' -Type {typ} -Value {val}"
        )
        return ShapeHit(script, "powershell", "windows-registry", conf, note, True)

    m = _AUDITPOL_GET.search(command or "")
    if m:
        sub = m.group(1)
        src = f"{source} {expected}"
        success = "enable" if re.search(r"success", src, re.I) else ""
        failure = "enable" if re.search(r"failure", src, re.I) else ""
        if not success and not failure:
            return None
        parts = [f'auditpol /set /subcategory:"{sub}"']
        if success:
            parts.append(f"/success:{success}")
        if failure:
            parts.append(f"/failure:{failure}")
        return ShapeHit(
            " ".join(parts),
            "powershell",
            "windows-auditpol",
            "medium",
            "inverted from auditpol /get; confirm Success/Failure against the STIG text",
            True,
        )
    return None


def _linux(command, comparator, expected, source, title) -> ShapeHit | None:
    m = _SYSCTL.search(command or "")
    if m:
        key = m.group(1)
        val = _expected_value(key, expected, source)
        if val is None:
            return None
        script = (
            f"sysctl -w {key}={val}\n"
            f"# persist after review, for example in /etc/sysctl.d/99-stig.conf — "
            f"this comment is not an edit"
        )
        return ShapeHit(
            script, "shell", "linux-sysctl", "medium",
            "inverted from sysctl query; persistence is left for a person",
            True,
        )

    m = _SYSTEMCTL_IS.search(command or "")
    if m:
        verb, unit = m.group(1), m.group(2)
        want_on = _wants_enabled(expected, source, title)
        if want_on is None:
            return None
        if want_on:
            action = "enable --now" if verb == "active" else "enable"
        else:
            action = "mask --now"
        return ShapeHit(
            f"systemctl {action} {unit}",
            "shell",
            "linux-systemctl",
            "low",
            "inverted from systemctl is-enabled/is-active; confirm the unit name",
            True,
        )
    return None


def _macos(command, comparator, expected, source, title) -> ShapeHit | None:
    m = _DEFAULTS_READ.search(command or "")
    if m and expected:
        domain, key = m.group(1), m.group(2)
        flag, val = _defaults_type(expected)
        script = f"/usr/bin/defaults write {domain} {key} {flag} {val}"
        return ShapeHit(
            script, "shell", "macos-defaults", "medium",
            "inverted from defaults read; confirm the type flag",
            True,
        )

    m = _LAUNCHCTL_PRINT.search(command or "")
    if m:
        domain, label = m.group(1), m.group(2)
        if not _wants_disabled(expected, source, title):
            return None
        target = f"{domain}/{label}"
        script = f"/bin/launchctl bootout {target}"
        return ShapeHit(
            script, "shell", "macos-launchctl", "low",
            "inverted from launchctl print; bootout stops a loaded service — confirm the label",
            True,
        )
    return None


def _expected_value(key: str, expected: str, source: str) -> str | None:
    m = _SET_TO.search(source or "")
    if m:
        return m.group(1).strip()
    m = _QUOTED_NUM.search(source or "")
    if m:
        return m.group(1)
    # stig-scan linux regex: r"(?im)^\s*key\s*[=:]?\s*VALUE\b"
    m = re.search(r"\\s\*([0-9A-Za-z._-]+)\\b\s*$", expected or "")
    if m:
        return m.group(1)
    m = re.search(rf"{re.escape(key)}\s*[=:]?\s*(\S+)", expected or "")
    if m:
        return m.group(1).strip("\\b")
    if re.fullmatch(r"-?\d+", (expected or "").strip()):
        return expected.strip()
    return None


def _defaults_type(expected: str) -> tuple[str, str]:
    if expected.lower() in {"true", "yes"}:
        return "-bool", "true"
    if expected.lower() in {"false", "no"}:
        return "-bool", "false"
    if re.fullmatch(r"-?\d+", expected):
        return "-int", expected
    return "-string", expected


def _wants_enabled(expected: str, source: str, title: str) -> bool | None:
    blob = f"{expected} {source} {title}".lower()
    if re.search(r"\b(disabled|inactive|masked|not enabled)\b", blob):
        return False
    if re.search(r"\b(enabled|active)\b", blob):
        return True
    if expected.strip() in {"1", "enabled", "active"}:
        return True
    if expected.strip() in {"0", "disabled", "inactive", "masked"}:
        return False
    return None


def _wants_disabled(expected: str, source: str, title: str) -> bool:
    blob = f"{expected} {source} {title}".lower()
    return bool(re.search(r"\b(disable|disabled|unload|must not be)\b", blob))
