"""Command execution, with a recorded-fixture mode for reproducibility.

Two runners share one interface:

``ShellRunner``   executes a check on the live system, after the static
                  safety gate has cleared it.
``FixtureRunner`` replays previously recorded output. Fixtures make a scan
                  reproducible on any machine — including CI on a platform
                  that cannot run the commands at all — and turn a real scan
                  into a durable evidence artifact rather than a claim about
                  something that happened once on somebody's laptop.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .safety import assert_safe, UnsafeCommand
from . import platforms

DEFAULT_TIMEOUT = 30


@dataclass
class RunResult:
    stdout: str
    stderr: str
    returncode: int
    source: str          # "live" | "fixture"
    error: str = ""      # populated when the command could not be run at all


def _pick_shell(platform: str | None = None) -> str:
    prof = platforms.get(platform)
    for candidate in prof.SHELL_CANDIDATES:
        if Path(candidate).exists():
            return candidate
        found = shutil.which(candidate)
        if found:
            return found
    return shutil.which("sh") or "/bin/sh"


class ShellRunner:
    """Runs checks against the live system."""

    def __init__(self, timeout: int = DEFAULT_TIMEOUT, shell: str | None = None,
                 record_dir: str | Path | None = None, platform: str | None = None):
        self.timeout = timeout
        self.platform = platforms.get(platform).NAME
        self.shell = shell or _pick_shell(self.platform)
        self.record_dir = Path(record_dir) if record_dir else None
        if self.record_dir:
            self.record_dir.mkdir(parents=True, exist_ok=True)

    def run(self, stig_id: str, command: str) -> RunResult:
        try:
            assert_safe(command, self.platform)
        except UnsafeCommand as e:
            return RunResult("", "", -1, "live", error=f"blocked by safety gate: {e}")

        try:
            prof = platforms.get(self.platform)
            argv = [self.shell, *getattr(prof, "SHELL_ARGS", ("-c",)), command]
            proc = subprocess.run(
                argv,
                capture_output=True, text=True, timeout=self.timeout,
                env={**os.environ, "LC_ALL": "C"},
            )
            result = RunResult(proc.stdout, proc.stderr, proc.returncode, "live")
        except subprocess.TimeoutExpired:
            result = RunResult("", "", -1, "live",
                               error=f"timed out after {self.timeout}s")
        except OSError as e:
            result = RunResult("", "", -1, "live", error=f"could not execute: {e}")

        if self.record_dir:
            (self.record_dir / f"{stig_id}.json").write_text(
                json.dumps({
                    "stig_id": stig_id,
                    "command": command,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "returncode": result.returncode,
                    "error": result.error,
                }, indent=2) + "\n",
                encoding="utf-8",
            )
        return result


class FixtureRunner:
    """Replays recorded output instead of touching the system."""

    def __init__(self, fixture_dir: str | Path):
        self.fixture_dir = Path(fixture_dir)
        if not self.fixture_dir.is_dir():
            raise FileNotFoundError(f"fixture directory not found: {self.fixture_dir}")

    def run(self, stig_id: str, command: str) -> RunResult:
        path = self.fixture_dir / f"{stig_id}.json"
        if not path.exists():
            return RunResult("", "", -1, "fixture",
                             error=f"no recorded fixture for {stig_id}")
        data = json.loads(path.read_text(encoding="utf-8"))
        return RunResult(
            data.get("stdout", ""), data.get("stderr", ""),
            data.get("returncode", 0), "fixture", data.get("error", ""),
        )


def host_facts() -> dict[str, str]:
    """Environment metadata recorded alongside every scan report."""
    facts = {
        "hostname": platform.node(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "euid": str(os.geteuid()) if hasattr(os, "geteuid") else "n/a",
    }
    if platform.system() == "Darwin":
        try:
            out = subprocess.run(["/usr/bin/sw_vers", "-productVersion"],
                                 capture_output=True, text=True, timeout=10)
            facts["macos_version"] = out.stdout.strip()
        except (OSError, subprocess.SubprocessError):
            facts["macos_version"] = "unknown"
    return facts
