"""macOS profile — the reference platform (validated on Apple macOS 26 V1R3)."""

from __future__ import annotations

import re

NAME = "macos"
SUPPORTED = True          # scanning implemented and tested on this platform
EXTRACTOR = True          # DISA check text can be reduced to commands
SHELL_CANDIDATES = ("/bin/zsh", "/bin/bash", "/bin/sh")

ALLOWED_BINARIES = {
    # read-only macOS state inspection
    "/usr/bin/osascript", "/usr/bin/csrutil", "/usr/sbin/fdesetup",
    "/usr/sbin/sshd", "/bin/launchctl", "/usr/bin/pwpolicy",
    "/usr/bin/defaults", "/usr/bin/security", "/usr/sbin/system_profiler",
    "/usr/sbin/spctl", "/usr/bin/spctl", "/usr/bin/dscl", "/usr/bin/sw_vers",
    "/usr/bin/profiles", "/usr/sbin/systemsetup", "/usr/bin/plutil",
    "/usr/bin/log", "/usr/sbin/nvram", "/usr/bin/mdutil", "/usr/bin/xmllint",
    "/usr/libexec/PlistBuddy", "/usr/bin/socketfilterfw",
    "/usr/libexec/ApplicationFirewall/socketfilterfw",
    # generic text/shell utilities
    "/usr/bin/grep", "/usr/bin/egrep", "/usr/bin/awk", "/usr/bin/sed",
    "/usr/bin/wc", "/usr/bin/cut", "/usr/bin/sort", "/usr/bin/uniq",
    "/usr/bin/head", "/usr/bin/tail", "/usr/bin/tr", "/usr/bin/expr",
    "/bin/echo", "/bin/cat", "/bin/date", "/bin/ls", "/usr/bin/stat",
    "/usr/bin/basename", "/usr/bin/dirname", "/usr/bin/printf", "/usr/bin/find",
    "/usr/bin/xargs", "/usr/bin/pgrep", "/usr/bin/id", "/usr/bin/whoami",
    "/usr/bin/fdesetup", "/usr/sbin/cupsctl", "/usr/libexec/mdmclient",
    "/usr/bin/ssh", "/usr/bin/last", "/usr/bin/uname", "/usr/bin/file",
}

ALLOWED_BAREWORDS = {
    "echo", "test", "if", "then", "else", "elif", "fi", "for", "do", "done",
    "while", "case", "esac", "in", "return", "break", "continue", "local",
    "true", "false", "function", "grep", "awk", "sed", "wc", "cut", "sort",
    "uniq", "head", "tail", "tr", "expr", "cat", "date", "printf", "read",
    "security", "defaults", "launchctl", "sshd", "csrutil", "fdesetup",
    "pwpolicy", "osascript", "spctl", "dscl", "sw_vers", "system_profiler",
    "xmllint", "plutil", "profiles", "socketfilterfw", "systemsetup",
}

# Platform-specific mutating forms of otherwise read-only tools. The generic
# list (destructive verbs, redirection, network, privilege escalation) lives
# in safety.py and applies everywhere.
FORBIDDEN = [
    (r"\bdefaults\s+(write|delete|import|rename)\b", "mutates a preference domain"),
    (r"\bcsrutil\s+(disable|enable|clear|authenticated-root)\b", "changes SIP state"),
    (r"\bfdesetup\s+(disable|enable|remove|changerecovery|add)\b", "changes FileVault state"),
    (r"\bspctl\s+--(master-disable|master-enable|add|remove|disable|enable)\b", "changes Gatekeeper state"),
    (r"\bsecurity\s+authorizationdb\s+write\b", "modifies the authorization database"),
    (r"\blaunchctl\s+(load|unload|bootstrap|bootout|enable|disable|kickstart|remove|setenv)\b", "changes service state"),
    (r"\bsystemsetup\s+-set", "changes system settings"),
    (r"\bpwpolicy\s+(-set|-clear)", "changes password policy"),
    (r"\bprofiles\s+(install|remove|renew)\b", "installs or removes configuration profiles"),
    (r"\bnvram\s+-[dc]\b", "modifies firmware variables"),
    (r"\b(chflags|diskutil)\b", "mutating filesystem verb"),
    (r"\bpmset\b\s+-a", "changes power management settings"),
]

ABS_PATH = re.compile(
    r"(?<![\w./])(/(?:usr/bin|usr/sbin|usr/libexec|bin|sbin|opt/homebrew/bin|opt/local/bin)/[\w.-]+)")

# Words in check text that mean "a human does this in a window", not a command.
GUI_HINT = re.compile(
    r"\b(click|System Settings|System Preferences|menu bar|top left corner|"
    r"interview the|ask the|verify with the (?:SA|ISSO)|documented with the ISSO)\b", re.I)


def clean_command(body: str) -> str:
    """macOS check text is already a shell snippet; nothing to strip."""
    return body.strip("\n").strip()
