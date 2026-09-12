"""The source-checkout launchers: Start.command (macOS) and Start.bat plus
its hidden helper run-hidden.vbs (Windows). These are for someone who
already has Python and downloaded the plain source ZIP rather than a
release build from packaging/build_portable.py — a different, lighter
path than the bundled STIG Checker.app/.bat in dist/, so they are checked
straight into the repository rather than generated.
"""

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class TestStartScripts(unittest.TestCase):
    def test_start_command_runs_in_app_mode(self):
        text = (ROOT / "Start.command").read_text(encoding="utf-8")
        self.assertIn("stigui --app", text,
                      "without --app there is no Quit button, no single-instance reuse")
        self.assertIn("python.org", text)

    def test_start_bat_defers_to_the_hidden_helper_when_present(self):
        text = (ROOT / "Start.bat").read_text(encoding="utf-8")
        self.assertIn("run-hidden.vbs", text)
        self.assertIn("stigui --app", text, "the direct fallback must also use app mode")

    def test_hidden_helper_runs_in_app_mode_with_no_window(self):
        text = (ROOT / "run-hidden.vbs").read_text(encoding="utf-8")
        self.assertIn("stigui --app", text)
        self.assertIn("Add python.exe to PATH", text)
        # sh.Run(..., 0, False): window style 0 = hidden — this is what
        # keeps a black console from ever flashing on screen.
        self.assertRegex(text, r"sh\.Run\s+py\s+&.*,\s*0,\s*False")

    def test_both_platforms_check_for_python_before_anything_else(self):
        mac = (ROOT / "Start.command").read_text(encoding="utf-8")
        win = (ROOT / "run-hidden.vbs").read_text(encoding="utf-8")
        self.assertIn("Python 3 is not installed", mac)
        self.assertIn("needs Python 3.9", win)

    def test_named_aliases_point_at_the_real_launchers(self):
        bat = (ROOT / "STIG Checker.bat").read_text(encoding="utf-8")
        mac = (ROOT / "STIG Checker.command").read_text(encoding="utf-8")
        self.assertIn("Start.bat", bat)
        self.assertIn("Start.command", mac)
        self.assertTrue((ROOT / "Double-click this.txt").is_file())


if __name__ == "__main__":
    unittest.main()
