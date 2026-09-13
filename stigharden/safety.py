"""Safety gate for *remediation* scripts.

Scan checks must only read state. Remediation scripts are expected to
change configuration — that is the point — but they must not become a
channel for destruction, network fetches, or a hidden interpreter.

Two independent rules:

1. No forbidden construct (destructive filesystem verbs, network
   clients, reboot/halt, nested ``python -c`` / ``Invoke-Expression``).
2. High-risk forms (SIP, FileVault, ``secedit /configure``, firmware)
   are not silently treated as ordinary scripts. The authoring step
   downgrades those to ``manual`` so ``apply`` cannot run them.
"""

from __future__ import annotations

import re

FORBIDDEN = [
    (r"\b(rm|rmdir|unlink|del|erase)\s+(-[a-zA-Z]*r|/s)\b", "recursive delete"),
    (r"\b(rm|rmdir)\s+-rf\b", "recursive force delete"),
    (r"\b(mkfs|mkfs\.\w+)\b", "formats a filesystem"),
    (r"(?<![-\w])dd\s", "raw disk write utility"),
    (r"\b(Format-Volume|format)\s", "formats a volume"),
    (r"\b(curl|wget|nc|netcat|ftp|scp|sftp|Invoke-WebRequest|Invoke-RestMethod|Start-BitsTransfer)\b",
     "network client"),
    (r"\b(shutdown|reboot|halt|poweroff|Restart-Computer|Stop-Computer)\b",
     "reboots or halts the system"),
    (r"\b(python|python3|perl|ruby|node|bash|zsh|sh)\s+-c\b", "nested interpreter invocation"),
    (r"\b(Invoke-Expression|iex)\b", "dynamic evaluation"),
    (r"\beval\b", "dynamic evaluation"),
    (r"\$\(\s*curl", "command substitution around a network client"),
    (r"\b(userdel|passwd\s+-d)\b", "destroys an account or its password"),
]

# These may appear as *suggestions* in a manual draft. They must not be
# mode=script, because applying them on the wrong host is hard to undo.
HIGH_RISK = [
    (r"\bcsrutil\s+(enable|disable|clear|authenticated-root)\b", "changes SIP state"),
    (r"\bfdesetup\s+(enable|disable|remove|changerecovery)\b", "changes FileVault state"),
    (r"\bspctl\s+--master-(enable|disable)\b", "changes Gatekeeper master state"),
    (r"\bsecedit\s+/configure\b", "applies a full security-policy template"),
    (r"\bprofiles\s+install\b", "installs a configuration profile"),
    (r"\bnvram\s+-[dc]\b", "modifies firmware variables"),
    (r"\bmanage-bde\s+-(on|off)\b", "changes BitLocker power state"),
]


class UnsafeRemediation(ValueError):
    """Raised when a remediation script fails the safety gate."""


def audit(script: str) -> list[str]:
    """Return reasons the script is unsafe to even *draft* as executable."""
    problems: list[str] = []
    text = script or ""
    for pattern, reason in FORBIDDEN:
        if re.search(pattern, text, re.I):
            problems.append(f"forbidden construct ({reason}): /{pattern}/")
    return problems


def high_risk(script: str) -> list[str]:
    """Return reasons the script should stay manual, not apply-able."""
    hits: list[str] = []
    text = script or ""
    for pattern, reason in HIGH_RISK:
        if re.search(pattern, text, re.I):
            hits.append(f"high-risk ({reason})")
    return hits


def assert_safe(script: str) -> None:
    problems = audit(script)
    if problems:
        raise UnsafeRemediation("; ".join(problems))
