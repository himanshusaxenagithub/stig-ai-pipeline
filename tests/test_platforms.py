"""Platform profiles: the safety gate, the extractor and the pack all carry
the platform explicitly, and the defaults keep the macOS behaviour intact."""

import json
import tempfile
import unittest
from pathlib import Path

from stigscan import platforms
from stigscan.evaluate import evaluate, ERROR, PASS, FAIL
from stigscan.extract import build_pack, candidate_from_rule
from stigscan.pack import CheckPack, MODE_SHELL, MODE_UNSUPPORTED, MODE_MANUAL
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
        self.assertTrue(platforms.windows.SUPPORTED and platforms.windows.EXTRACTOR)


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
    def _c(self, text, **kw):
        rule = {"stig_id": "WN11-TEST", "severity": "high", "title": "t", "check_text": text}
        rule.update(kw)
        return candidate_from_rule(rule, "2026-09-09", "windows")

    def test_registry_value_becomes_get_itemproperty(self):
        c = self._c("If the following registry value does not exist or is not configured as specified, this is a finding:\n\n"
                    "Registry Hive: HKEY_LOCAL_MACHINE\nRegistry Path: \\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters\\\n\n"
                    "Value Name: DisableIPSourceRouting\n\nType: REG_DWORD\nValue: 0x00000002 (2)")
        self.assertEqual(c.mode, MODE_SHELL)
        self.assertIn("Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip6\\Parameters'", c.command)
        self.assertIn("-Name 'DisableIPSourceRouting'", c.command)
        self.assertEqual((c.comparator, c.expected), ("equals", "2"))
        self.assertEqual(c.author_confidence, "high")
        self.assertEqual(audit(c.command, "windows"), [])

    def test_registry_string_value(self):
        c = self._c("Registry Hive: HKEY_LOCAL_MACHINE\nRegistry Path: \\SOFTWARE\\Policies\\X\\\nValue Name: Banner\nType: REG_SZ\nValue: \"Authorized use only\"")
        self.assertEqual((c.comparator, c.expected), ("equals", "Authorized use only"))

    def test_registry_or_less_becomes_range(self):
        c = self._c("Registry Hive: HKEY_LOCAL_MACHINE\nRegistry Path: \\SOFTWARE\\X\\\nValue Name: CachedLogonsCount\nType: REG_SZ\nValue: 4 (or less)")
        self.assertEqual(c.comparator, "int_le")
        self.assertEqual(c.expected, "4")
        self.assertEqual(c.author_confidence, "medium")

    def test_auditpol_line_becomes_subcategory_check(self):
        c = self._c('Use the "AuditPol" tool to review the current Audit Policy configuration:\n'
                    'Enter "AuditPol /get /category:*"\n\nIf the system does not audit the following, this is a finding.\n\n'
                    "Account Logon >> Credential Validation - Success")
        self.assertEqual(c.mode, MODE_SHELL)
        self.assertIn('auditpol /get /subcategory:"Credential Validation"', c.command)
        self.assertEqual(c.comparator, "regex")
        self.assertEqual(evaluate("Machine,System,Credential Validation,{guid},Success and Failure,", "regex", c.expected)[0], PASS)
        self.assertEqual(evaluate("Machine,System,Credential Validation,{guid},No Auditing,", "regex", c.expected)[0], FAIL)
        self.assertEqual(audit(c.command, "windows"), [])

    def test_secedit_fallback_is_used(self):
        c = self._c('Run "gpedit.msc". Navigate to ... Password Policy.\n'
                    'If the value for "Store passwords using reversible encryption" is not set to "Disabled", this is a finding.\n'
                    "For server core installations, run the following command:\n"
                    "Secedit /Export /Areas SecurityPolicy /CFG C:\\Path\\FileName.Txt\n"
                    'If "ClearTextPassword" equals "1" in the file, this is a finding.')
        self.assertEqual(c.mode, MODE_SHELL)
        self.assertIn("secedit /export /areas SecurityPolicy", c.command)
        self.assertIn("'^ClearTextPassword\\s*='", c.command)
        self.assertEqual((c.comparator, c.expected), ("not_equals", "1"))
        self.assertEqual(audit(c.command, "windows"), [])   # Remove-Item $f -Force is the one permitted form

    def test_gpedit_without_secedit_is_manual(self):
        c = self._c('Run "gpedit.msc". Navigate to Local Computer Policy >> ... \nIf the value is not set to "Enabled", this is a finding.\n'
                    "Verify in Computer Management that no standard user accounts are members.")
        self.assertEqual(c.mode, MODE_MANUAL)

    def test_quoted_cmdlet_with_any_output_sentence(self):
        c = self._c('Open PowerShell.\nEnter "Get-LocalGroupMember -Group Administrators"\n'
                    "If any results are returned, this is a finding.")
        self.assertEqual(c.command, "Get-LocalGroupMember -Group Administrators")
        self.assertEqual(c.comparator, "empty")

    def test_mutating_cmdlets_are_refused(self):
        self.assertTrue(audit("Set-ItemProperty -Path HKLM:\\x -Name y -Value 1", "windows"))
        self.assertTrue(audit("Remove-Item C:\\Windows\\System32\\x", "windows"))
        self.assertTrue(audit("auditpol /set /subcategory:x /success:enable", "windows"))
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
