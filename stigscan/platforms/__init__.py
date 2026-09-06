"""Platform profiles for stig-scan.

The scanner core — packs, review, approval digests, the safety gate, the
runner and the report — is platform-neutral. What differs between operating
systems is small and explicit, and lives here, one module per platform:

* which binaries a *check* may execute (read-only state inspection only),
* which bare command words are permitted,
* which constructs are forbidden because they mutate state,
* which shell runs the command,
* how DISA writes check text for that platform, so the extractor can recover
  the command and the acceptance sentence,
* whether scanning on that platform is supported in this release.

A pack records the platform it was authored for. A scan refuses to run a
pack on a different platform than the one it declares.
"""

from __future__ import annotations

import platform as _platform

from . import macos, linux, windows

PROFILES = {
    macos.NAME: macos,
    linux.NAME: linux,
    windows.NAME: windows,
}
DEFAULT = macos.NAME
NAMES = tuple(PROFILES)


def get(name: str | None):
    """Return the profile module for *name* (case-insensitive)."""
    if not name:
        return PROFILES[DEFAULT]
    key = name.strip().lower()
    if key not in PROFILES:
        raise KeyError(f"unknown platform {name!r}; expected one of {', '.join(NAMES)}")
    return PROFILES[key]


def detect() -> str:
    """Best-effort name of the platform this process is running on."""
    system = _platform.system()
    if system == "Darwin":
        return macos.NAME
    if system == "Linux":
        return linux.NAME
    if system == "Windows":
        return windows.NAME
    return DEFAULT
