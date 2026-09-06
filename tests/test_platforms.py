"""Platform profiles: the safety gate, the extractor and the pack all carry
the platform explicitly, and the defaults keep the macOS behaviour intact."""

import json
import tempfile
import unittest
from pathlib import Path

from stigscan import platforms
from stigscan.evaluate import evaluate, ERROR, PASS, FAIL
from stigscan.extract import build_pack, candidate_from_rule
from stigscan.pack import CheckPack, MODE_SHELL, MODE_UNSUPPORTED
from stigscan.safety import audit


class ProfileRegistry(unittest.TestCase):
    def test_names_and_default(self):
        self.assertEqual(platforms.NAMES, ("macos", "linux", "windows"))
        self.assertIs(platforms.get(None), platforms.macos)
        self.assertIs(platforms.get("Linux"), platforms.linux)

    def test_unknown_platform_is_an_error(self):
        with self.assertRaises(KeyError):
            platforms.get("solaris")

    def test_support_flags(self):
        self.assertTrue(platforms.macos.SUPPORTED and platforms.macos.EXTRACTOR)
        self.assertTrue(platforms.linux.SUPPORTED and platforms.linux.EXTRACTOR)
        self.assertFalse(platforms.windows.SUPPORTED)
        self.assertFalse(platforms.windows.EXTRACTOR)


class LinuxSafetyGate(unittest.TestCase):
    def test_read_only_queries_pass(self):
        for cmd in (
            "systemctl is-active auditd.service",
            "sysctl kernel.randomize_va_space",
            "dpkg -l | grep rsyslog",
            "grep -i '^PASS_MAX_DAYS' /etc/login.defs",
            "/usr/bin/stat -c '%a %U' /etc/shadow",
            "auditctl -l | grep -w faillock",
            "ufw status",
        ):
            self.assertEqual(audit(cmd, "linux"), [], cmd)

    def test_mutating_forms_are_refused(self):
        for cmd in (
            "systemctl enable auditd",
            "sysctl -w kernel.randomize_va_space=2",
            "ufw enable",
            "auditctl -w /etc/passwd -p wa",
            "apt-get install -y auditd",
            "chage -M 60 alice",
            "usermod -L alice",
            "iptables -A INPUT -j DROP",
            "update-grub",
            "grep x /etc/foo > /tmp/out",
        ):
            self.assertTrue(audit(cmd, "linux"), f"should be refused: {cmd}")

    def test_macos_gate_is_unchanged_by_default(self):
        self.assertEqual(audit("/usr/bin/csrutil status | /usr/bin/grep -c enabled"), [])
        self.assertTrue(audit("systemctl is-active auditd"))   # not a macOS binary

    def test_linux_binary_is_refused_on_macos_profile(self):
        self.assertTrue(audit("/usr/bin/systemctl is-active auditd", "macos"))


class LinuxExtractor(unittest.TestCase):
    RULE = {
        "stig_id": "UBTU-24-TEST01", "severity": "medium", "title": "t",
        "check_text": ("Verify the log service is enabled with the following command:\n\n"
                       "$ systemctl is-enabled rsyslog\nenabled\n\n"
                       'If the command above returns "disabled", this is a finding.'),
    }

    def test_prompt_line_becomes_the_command(self):
        c = candidate_from_rule(self.RULE, "2026-09-06", "linux")
        self.assertEqual(c.mode, MODE_SHELL)
        self.assertEqual(c.command, "systemctl is-enabled rsyslog")
        self.assertEqual((c.comparator, c.expected), ("not_equals", "disabled"))
        self.assertEqual(c.author_confidence, "high")

    def test_sudo_is_declared_not_embedded(self):
        rule = dict(self.RULE, check_text=(
            "Verify with the following command:\n\n$ sudo grep -w foo /etc/bar.conf\nfoo = 1\n\n"
            'If "foo" is not set to "1", this is a finding.'))
        c = candidate_from_rule(rule, "d", "linux")
        self.assertEqual(c.command, "grep -w foo /etc/bar.conf")
        self.assertTrue(c.requires_root)
        self.assertEqual(c.comparator, "regex")
        self.assertIn("foo", c.expected)

    def test_package_installed_means_output_must_be_empty(self):
        rule = dict(self.RULE, check_text=(
            "Check with the following command:\n\n$ dnf list --installed | grep vsftpd\n\n"
            'If the "vsftpd" package is installed, this is a finding.'))
        c = candidate_from_rule(rule, "d", "linux")
        self.assertEqual(c.comparator, "empty")

    def test_example_match_builds_anchored_regex(self):
        rule = dict(self.RULE, check_text=(
            "Verify with the following command:\n\n$ grep pam_faillock /etc/pam.d/common-auth\n"
            "auth required pam_faillock.so preauth\n\n"
            "If the command does not return a line that matches the example or the line is commented out, this is a finding."))
        c = candidate_from_rule(rule, "d", "linux")
        self.assertEqual(c.comparator, "regex")
        self.assertEqual(evaluate("auth required pam_faillock.so preauth", "regex", c.expected)[0], PASS)
        self.assertEqual(evaluate("#auth required pam_faillock.so preauth", "regex", c.expected)[0], FAIL)

    def test_unmapped_sentence_stays_unsupported(self):
        rule = dict(self.RULE, check_text=(
            "$ some-command\n\nIf there is no evidence of appropriate action, this is a finding."))
        c = candidate_from_rule(rule, "d", "linux")
        self.assertEqual(c.mode, MODE_UNSUPPORTED)


class WindowsProfile(unittest.TestCase):
    def test_author_marks_everything_unsupported(self):
        rule = {"stig_id": "WN11-TEST", "severity": "high", "title": "t",
                "check_text": "Run \"gpedit.msc\". If the value is not 1, this is a finding."}
        c = candidate_from_rule(rule, "d", "windows")
        self.assertEqual(c.mode, MODE_UNSUPPORTED)
        self.assertIn("no extractor", c.author_note)

    def test_mutating_cmdlets_are_refused(self):
        self.assertTrue(audit("Set-ItemProperty -Path HKLM:\\x -Name y -Value 1", "windows"))
        self.assertEqual(audit("Get-ItemProperty -Path HKLM:\\x | Select-Object y", "windows"), [])


class PackCarriesPlatform(unittest.TestCase):
    def test_round_trip_and_default(self):
        pack = build_pack({"title": "t", "version": "1", "release_info": "Release: 1", "rules": []},
                          "p", "2026-09-06", platform="linux")
        self.assertEqual(pack.platform, "linux")
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "p.json"
            pack.save(path)
            self.assertEqual(CheckPack.load(path).platform, "linux")
            raw = json.loads(path.read_text()); raw.pop("platform")
            path.write_text(json.dumps(raw))
            self.assertEqual(CheckPack.load(path).platform, "macos")   # legacy packs


class NotEqualsNeedsOutput(unittest.TestCase):
    def test_empty_output_is_error_not_pass(self):
        self.assertEqual(evaluate("", "not_equals", "disabled")[0], ERROR)
        self.assertEqual(evaluate("enabled", "not_equals", "disabled")[0], PASS)


if __name__ == "__main__":
    unittest.main()
