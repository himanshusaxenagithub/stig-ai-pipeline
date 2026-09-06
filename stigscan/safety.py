"""Static safety gate for check commands.

A STIG *check* should only ever read state. Nothing in this pipeline has any
business changing a system's configuration — that is module 4's job, behind
its own review gates. This module enforces that as a precondition of
execution rather than as a convention.

Two independent rules must both pass:

1. Every absolute executable path named in the command must be on the
   allowlist, and every bare command word must be on the small builtin
   allowlist. Unknown binaries are refused rather than assumed harmless.
2. No forbidden construct may appear: mutating subcommands of otherwise
   read-only tools (``defaults write``, ``csrutil disable``), file
   redirection, network clients, privilege escalation, or destructive verbs.

The gate is deliberately conservative. A false refusal costs a human one
review; a false permit runs unvetted code as an administrator.
"""

from __future__ import annotations

import re

from . import platforms

# Constructs forbidden on every platform. Profiles add their own list of
# mutating forms of otherwise read-only tools.
FORBIDDEN_COMMON = [
    (r"\b(rm|rmdir|unlink|mv|cp|chmod|chown|mkfs)\b", "destructive or mutating filesystem verb"),
    (r"(?<![-\w])dd\s", "raw disk write utility"),
    (r"\b(curl|wget|nc|netcat|ftp|scp|sftp)\b", "network client"),
    # `ssh -G` / `ssh -Q` dump configuration without connecting; any other
    # invocation opens a network session and is refused.
    (r"\bssh\b(?!d)(?!\s+-[GQ]\b)", "ssh invoked in a form that may open a connection"),
    # Anchored so that a path such as /etc/pam.d/su is not mistaken for the
    # su *command*.
    (r"(?<![\w/.-])(sudo|su|doas)\s", "privilege escalation inside the command"),
    (r"\b(kill|killall|pkill|shutdown|reboot|halt)\b", "terminates processes or the system"),
    (r"\b(python|python3|perl|ruby|node|bash|zsh|sh)\s+-c\b", "nested interpreter invocation"),
    (r"\beval\b", "dynamic evaluation"),
    (r"(?<![0-9<>])>(?!=)", "output redirection to a file"),
    (r"\|\s*(tee|dd)\b", "writes output to a file"),
    (r"\$\(\s*curl", "command substitution around a network client"),
    (r"`.*curl.*`", "command substitution around a network client"),
    (r"\bcrontab\b", "modifies scheduled jobs"),
]

# Kept for backward compatibility: the macOS lists under their old names.
ALLOWED_BINARIES = platforms.macos.ALLOWED_BINARIES
ALLOWED_BAREWORDS = platforms.macos.ALLOWED_BAREWORDS
FORBIDDEN = FORBIDDEN_COMMON + platforms.macos.FORBIDDEN

# Heredoc bodies are data (JXA source), not shell — exempt from word scanning
# but still scanned for forbidden constructs.
_HEREDOC = re.compile(r"<<-?\s*'?\"?(\w+)'?\"?\s*\n(.*?)\n\1", re.S)


class UnsafeCommand(ValueError):
    """Raised when a check command fails the static safety gate."""


def _strip_heredocs(command: str) -> str:
    return _HEREDOC.sub(lambda m: "\n", command)


def _strip_quoted(text: str) -> str:
    """Remove quoted literals so that data never trips the word scanner."""
    text = re.sub(r"'[^']*'", "''", text)
    text = re.sub(r'"(?:\\.|[^"\\])*"', '""', text)
    return text


def audit(command: str, platform: str | None = None) -> list[str]:
    """Return a list of reasons the command is unsafe. Empty list == safe.

    *platform* selects the profile (default: macOS, the reference platform).
    """
    prof = platforms.get(platform)
    problems: list[str] = []
    shell_part = _strip_heredocs(command)
    scannable = _strip_quoted(shell_part)

    for pattern, reason in FORBIDDEN_COMMON + list(prof.FORBIDDEN):
        if re.search(pattern, scannable):
            problems.append(f"forbidden construct ({reason}): /{pattern}/")

    for path in set(prof.ABS_PATH.findall(scannable)):
        if path not in prof.ALLOWED_BINARIES:
            problems.append(f"executable not on allowlist: {path}")

    # Bare command words: first token of the whole command and of each
    # pipeline / logical segment.
    for segment in re.split(r"\|\||&&|[|;\n]", scannable):
        segment = segment.strip()
        if not segment:
            continue
        token = segment.split()[0]
        token = token.lstrip("(){}$")
        if not token or token.startswith(("/", "-", "#", '"', "'", "[")):
            continue
        if "=" in token.split()[0]:      # variable assignment
            continue
        if token in prof.ALLOWED_BAREWORDS:
            continue
        if re.fullmatch(r"[\w.-]+", token):
            problems.append(f"unrecognised command word: {token}")

    return problems


def assert_safe(command: str, platform: str | None = None) -> None:
    problems = audit(command, platform)
    if problems:
        raise UnsafeCommand("; ".join(problems))
