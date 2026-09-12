"""Source-checkout launchers, including first-run Python bootstrap."""

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class TestStartScripts(unittest.TestCase):
    def test_start_command_runs_in_app_mode(self):
        text = (ROOT / "Start.command").read_text(encoding="utf-8")
        self.assertIn("stigui --app", text)
        self.assertIn("ensure-python.sh", text)

    def test_start_bat_defers_to_the_hidden_helper_when_present(self):
        text = (ROOT / "Start.bat").read_text(encoding="utf-8")
        self.assertIn("run-hidden.vbs", text)
        self.assertIn("stigui --app", text)

    def test_hidden_helper_can_bootstrap_python(self):
        text = (ROOT / "run-hidden.vbs").read_text(encoding="utf-8")
        self.assertIn("stigui --app", text)
        self.assertIn("ensure-python.ps1", text)
        self.assertIn("python.org", text)
        self.assertRegex(text, r"sh\.Run\s+py\s+&.*,\s*0,\s*False")

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


if __name__ == "__main__":
    unittest.main()
