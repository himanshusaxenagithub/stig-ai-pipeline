"""Source-checkout launchers, including first-run Python bootstrap."""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class TestStartScripts(unittest.TestCase):
    def test_start_command_runs_in_app_mode(self):
        text = (ROOT / "Start.command").read_text(encoding="utf-8")
        self.assertIn("run.py --app", text)
        self.assertNotIn("export PYTHONPATH", text, "run.py sets sys.path itself")
        self.assertIn("ensure-python.sh", text)
        self.assertIn("selection.json", text)

    def test_start_bat_defers_to_the_hidden_helper_when_present(self):
        text = (ROOT / "Start.bat").read_text(encoding="utf-8")
        self.assertIn("run-hidden.vbs", text)
        self.assertIn("run.py --app", text)

    def test_hidden_helper_can_bootstrap_python(self):
        text = (ROOT / "run-hidden.vbs").read_text(encoding="utf-8")
        self.assertIn("run.py", text)
        self.assertNotIn("-m stigui", text,
                         "the embeddable Python's ._pth ignores PYTHONPATH and the cwd; -m stigui fails there")
        self.assertIn("ensure-python.ps1", text)
        self.assertIn("python.org", text)
        self.assertIn("selection.json", text)
        self.assertRegex(text, r"sh\.Run\s+py\s+&.*,\s*0,\s*False")

    def test_hidden_helper_dims_every_option_explicit_variable(self):
        """WSH with Option Explicit raises 800A01F4 on the first
        assignment to an undeclared name — that is the dialog a
        Windows user saw after downloading the website zip."""
        text = (ROOT / "run-hidden.vbs").read_text(encoding="utf-8")
        self.assertIn("Option Explicit", text)
        declared = set()
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.lower().startswith("dim "):
                declared.update(n.strip() for n in stripped[4:].split(",") if n.strip())
        funcs = set(re.findall(r"(?im)^\s*Function\s+(\w+)", text))
        assigned = set(re.findall(r"(?m)^\s*(?:Set\s+)?([A-Za-z]\w*)\s*=", text))
        undeclared = assigned - declared - funcs
        self.assertFalse(
            undeclared,
            f"Option Explicit but not Dim'd (WSH 800A01F4): {sorted(undeclared)}")
        self.assertIn("args", declared)

    def test_windows_bootstrap_pins_official_embed_build(self):
        text = (ROOT / "scripts" / "ensure-python.ps1").read_text(encoding="utf-8")
        self.assertIn("python.org/ftp/python/3.12.7/python-3.12.7-embed-amd64.zip", text)
        self.assertIn("0d57bb6cb078b74d23dbfe91f77d6780d45bed328911609f1f7ee2ba1606bf44", text)
        self.assertIn("Get-FileHash", text)

    def test_named_aliases_point_at_the_real_launchers(self):
        bat = (ROOT / "STIG Checker.bat").read_text(encoding="utf-8")
        mac = (ROOT / "STIG Checker.command").read_text(encoding="utf-8")
        self.assertIn("Start.bat", bat)
        self.assertIn("Start.command", mac)

    def test_command_files_are_executable_in_git(self):
        """GitHub's Download ZIP keeps git's file modes. A .command committed
        as 100644 arrives non-executable, and macOS then refuses it with
        "you do not have appropriate access privileges" -- which breaks the
        README's own Mac quick start. Both the working copy and the index
        must say 755."""
        import os, shutil, subprocess
        names = ["Start.command", "STIG Checker.command", "Build.command",
                 "scripts/ensure-python.sh"]
        for name in names:
            self.assertTrue(os.access(ROOT / name, os.X_OK), f"{name} is not executable")
        git = shutil.which("git")
        if git and (ROOT / ".git").exists():
            out = subprocess.run([git, "ls-files", "-s", *names], cwd=ROOT,
                                 capture_output=True, text=True).stdout
            for line in out.splitlines():
                mode, _, _, name = line.split(maxsplit=3)
                self.assertEqual(mode, "100755", f"{name} is committed as {mode}")

    def test_run_py_works_under_an_interpreter_that_ignores_the_environment(self):
        """python.org's embeddable build (what ensure-python.ps1 fetches)
        ships a ._pth file: PYTHONPATH is ignored and the current folder is
        not put on sys.path. `python -I` reproduces exactly that, so this is
        the Windows no-Python-installed path, run here."""
        import os, subprocess, sys
        env = dict(os.environ, PYTHONPATH="/nonexistent")
        out = subprocess.run([sys.executable, "-I", str(ROOT / "run.py"), "--help"],
                             cwd="/", env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(out.returncode, 0, out.stderr[-400:])
        self.assertIn("--app", out.stdout)
        self.assertIn("--selection", out.stdout)
        # and the old way really does fail there, which is why run.py exists
        bad = subprocess.run([sys.executable, "-I", "-m", "stigui", "--help"],
                             cwd=str(ROOT), env=env, capture_output=True, text=True, timeout=60)
        self.assertNotEqual(bad.returncode, 0)
        self.assertIn("No module named stigui", bad.stderr)

    def test_start_command_checks_the_python_it_finds(self):
        """`command -v python3` succeeding is not enough: a Mac without the
        Xcode Command Line Tools has a /usr/bin/python3 stub that opens an
        installer when run, and an old Python 3.8 parses none of this code."""
        text = (ROOT / "Start.command").read_text(encoding="utf-8")
        self.assertIn("xcode-select -p", text)
        self.assertIn("sys.version_info >= (3, 9)", text)
        # a downloaded private copy is preferred over hunting the PATH again
        self.assertLess(text.index('bundled="$HOME/Library'), text.index("for c in python3"))


if __name__ == "__main__":
    unittest.main()
