"""Tests for stig-scan (module 2).

The behaviour worth protecting here is refusal: the scanner must not execute
unapproved checks, must not honour an approval whose content changed, and
must not report an unsafe or unrunnable check as a compliance verdict.
"""

import json
import tempfile
import unittest
from pathlib import Path

from stigscan.pack import Check, CheckPack, PackError, APPROVED, UNREVIEWED
from stigscan.safety import audit, assert_safe, UnsafeCommand
from stigscan.evaluate import evaluate, EvalError, PASS, FAIL
from stigscan.extract import build_pack, candidate_from_rule
from stigscan.runner import FixtureRunner
from stigscan.scan import run_scan
from stigscan.report import to_markdown, to_json

FIXTURES = Path(__file__).parent / "fixtures" / "macos26-unmanaged-synthetic"


def _check(**kw):
    base = dict(stig_id="TEST-0001", mode="shell",
                command="/bin/echo 1", comparator="equals", expected="1")
    base.update(kw)
    return Check(**base)


class TestSafetyGate(unittest.TestCase):
    def test_read_only_command_passes(self):
        self.assertEqual(audit("/usr/bin/csrutil status | /usr/bin/grep -c enabled"), [])

    def test_mutating_defaults_write_is_refused(self):
        self.assertTrue(audit("/usr/bin/defaults write com.apple.x Y -bool true"))

    def test_sip_disable_is_refused(self):
        self.assertTrue(audit("/usr/bin/csrutil disable"))

    def test_file_redirection_is_refused(self):
        self.assertTrue(audit("/usr/bin/csrutil status > /tmp/x"))

    def test_stderr_redirection_is_allowed(self):
        self.assertEqual(audit("/bin/launchctl print system/com.apple.tftpd 2>/dev/null"), [])

    def test_network_client_is_refused(self):
        self.assertTrue(audit("/usr/bin/curl https://example.com"))

    def test_unknown_binary_is_refused(self):
        self.assertTrue(audit("/usr/bin/totally-made-up --status"))

    def test_jxa_heredoc_body_is_treated_as_data(self):
        cmd = ("/usr/bin/osascript -l JavaScript << EOS\n"
               "$.NSUserDefaults.alloc.initWithSuiteName('com.apple.MCX')"
               ".objectForKey('x').js\nEOS")
        self.assertEqual(audit(cmd), [])

    def test_su_in_a_file_path_is_not_privilege_escalation(self):
        self.assertEqual(audit("/usr/bin/grep -Ec 'pam_rootok' /etc/pam.d/su"), [])

    def test_ssh_config_dump_allowed_but_connection_refused(self):
        self.assertEqual(audit("/usr/bin/ssh -G ."), [])
        self.assertTrue(audit("/usr/bin/ssh user@host"))

    def test_assert_safe_raises(self):
        with self.assertRaises(UnsafeCommand):
            assert_safe("/bin/rm -rf /")


class TestEvaluate(unittest.TestCase):
    def test_equals(self):
        self.assertEqual(evaluate("1\n", "equals", "1")[0], PASS)
        self.assertEqual(evaluate("0", "equals", "1")[0], FAIL)

    def test_not_equals(self):
        self.assertEqual(evaluate("2", "not_equals", "1")[0], PASS)

    def test_empty_output_fails_a_true_expectation(self):
        self.assertEqual(evaluate("", "equals", "true")[0], FAIL)

    def test_int_comparators(self):
        self.assertEqual(evaluate("900", "int_ge", "900")[0], PASS)
        self.assertEqual(evaluate("899", "int_ge", "900")[0], FAIL)

    def test_regex(self):
        self.assertEqual(evaluate("FileVault is On.", "regex", r"is On")[0], PASS)

    def test_non_numeric_input_to_int_comparator_is_an_error(self):
        with self.assertRaises(EvalError):
            evaluate("banana", "int_ge", "1")

    def test_unknown_comparator_is_an_error(self):
        with self.assertRaises(EvalError):
            evaluate("1", "sort-of-equals", "1")


class TestPackFreeze(unittest.TestCase):
    def test_new_check_is_unreviewed_and_not_runnable(self):
        c = _check()
        self.assertEqual(c.review_status, UNREVIEWED)
        self.assertFalse(c.is_runnable())

    def test_approval_makes_it_runnable(self):
        c = _check()
        c.approve("H. Saxena", "2026-08-20T00:00:00Z")
        self.assertEqual(c.review_status, APPROVED)
        self.assertTrue(c.is_runnable())

    def test_editing_after_approval_causes_drift_and_blocks_execution(self):
        c = _check()
        c.approve("H. Saxena", "2026-08-20T00:00:00Z")
        c.command = "/bin/echo 2"          # tampered after review
        self.assertTrue(c.is_drifted())
        self.assertFalse(c.is_runnable())

    def test_changing_expected_value_also_causes_drift(self):
        c = _check()
        c.approve("H. Saxena", "2026-08-20T00:00:00Z")
        c.expected = "99"
        self.assertTrue(c.is_drifted())

    def test_empty_command_cannot_be_approved(self):
        with self.assertRaises(PackError):
            _check(command="  ").approve("H", "t")

    def test_manual_check_cannot_be_approved(self):
        with self.assertRaises(PackError):
            _check(mode="manual", command="").approve("H", "t")

    def test_roundtrip_preserves_approval(self):
        c = _check()
        c.approve("H. Saxena", "2026-08-20T00:00:00Z")
        pack = CheckPack(pack_id="t", checks=[c])
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "pack.json"
            pack.save(p)
            again = CheckPack.load(p)
        self.assertTrue(again.checks[0].is_runnable())
        self.assertFalse(again.checks[0].is_drifted())

    def test_duplicate_ids_are_rejected_on_load(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "pack.json"
            p.write_text(json.dumps({"pack_format": 1, "pack_id": "t", "checks": [
                {"stig_id": "A"}, {"stig_id": "A"}]}))
            with self.assertRaises(PackError):
                CheckPack.load(p)

    def test_unknown_comparator_is_rejected_on_load(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "pack.json"
            p.write_text(json.dumps({"pack_format": 1, "pack_id": "t", "checks": [
                {"stig_id": "A", "comparator": "vibes"}]}))
            with self.assertRaises(PackError):
                CheckPack.load(p)

    def test_future_pack_format_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "pack.json"
            p.write_text(json.dumps({"pack_format": 99, "pack_id": "t", "checks": []}))
            with self.assertRaises(PackError):
                CheckPack.load(p)


class TestExtractor(unittest.TestCase):
    RULE = {
        "stig_id": "APPL-26-005001", "group_id": "V-277165", "severity": "high",
        "title": "SIP must be enabled.",
        "check_text": ("Verify the macOS system is configured to enable SIP with the "
                       "following command:\n\n"
                       "/usr/bin/csrutil status | /usr/bin/grep -c 'System Integrity "
                       "Protection status: enabled.'\n\n"
                       'If the result is not "1", this is a finding.'),
    }

    def test_extracts_command_and_expected_value(self):
        c = candidate_from_rule(self.RULE, "2026-08-20")
        self.assertEqual(c.mode, "shell")
        self.assertEqual(c.expected, "1")
        self.assertEqual(c.comparator, "equals")
        self.assertIn("csrutil status", c.command)
        self.assertNotIn("this is a finding", c.command)

    def test_candidates_are_never_born_approved(self):
        self.assertEqual(candidate_from_rule(self.RULE, "2026-08-20").review_status, UNREVIEWED)

    def test_positive_phrasing_inverts_the_comparator(self):
        rule = dict(self.RULE, check_text=(
            "Verify with the following command:\n\n/bin/echo x\n\n"
            'If the result is "0", this is a finding.'))
        self.assertEqual(candidate_from_rule(rule, "d").comparator, "not_equals")

    def test_rule_without_acceptance_sentence_is_unsupported(self):
        rule = dict(self.RULE, check_text="Ask the ISSO whether this is documented.")
        c = candidate_from_rule(rule, "d")
        self.assertIn(c.mode, ("unsupported", "manual"))
        self.assertFalse(c.is_runnable())

    def test_embedded_sudo_becomes_a_declared_requirement(self):
        rule = dict(self.RULE, check_text=(
            "Verify with the following command:\n\n"
            "sudo /usr/bin/grep -c x /etc/pam.d/su\n\n"
            'If the result is not "1", this is a finding.'))
        c = candidate_from_rule(rule, "d")
        self.assertTrue(c.requires_root)
        self.assertNotIn("sudo", c.command)

    def test_sudo_as_another_user_is_left_for_human_review(self):
        rule = dict(self.RULE, check_text=(
            "Verify with the following command:\n\n"
            "/usr/bin/sudo -u bob /usr/bin/ssh -G .\n\n"
            'If the result is not "1", this is a finding.'))
        c = candidate_from_rule(rule, "d")
        self.assertIn("sudo -u bob", c.command)
        self.assertEqual(c.author_confidence, "low")


class TestScanOrchestration(unittest.TestCase):
    def setUp(self):
        self.runner = FixtureRunner(FIXTURES)

    def _pack(self, checks):
        return CheckPack(pack_id="t", checks=checks)

    def test_unreviewed_checks_do_not_execute_by_default(self):
        pack = self._pack([_check(stig_id="APPL-26-005001",
                                  command="/usr/bin/csrutil status", expected="1")])
        rep = run_scan(pack, self.runner)
        self.assertEqual(rep.results[0].status, "skipped")
        self.assertIn("unreviewed", rep.results[0].detail)

    def test_approved_check_executes(self):
        c = _check(stig_id="APPL-26-005001", command="/usr/bin/csrutil status", expected="1")
        c.approve("tester", "t")
        rep = run_scan(self._pack([c]), self.runner)
        self.assertEqual(rep.results[0].status, PASS)
        self.assertTrue(rep.results[0].trusted)

    def test_drifted_approval_is_refused_at_scan_time(self):
        c = _check(stig_id="APPL-26-005001", command="/usr/bin/csrutil status", expected="1")
        c.approve("tester", "t")
        c.expected = "0"                     # edited after approval
        rep = run_scan(self._pack([c]), self.runner)
        self.assertEqual(rep.results[0].status, "skipped")
        self.assertIn("DRIFTED", rep.results[0].detail)

    def test_forced_unreviewed_results_are_marked_untrusted(self):
        pack = self._pack([_check(stig_id="APPL-26-005001",
                                  command="/usr/bin/csrutil status", expected="1")])
        rep = run_scan(pack, self.runner, include_unreviewed=True)
        self.assertEqual(rep.results[0].status, PASS)
        self.assertFalse(rep.results[0].trusted)

    def test_unsafe_command_is_an_error_not_a_verdict(self):
        c = _check(stig_id="APPL-26-005001", command="/usr/bin/defaults write a b")
        c.approve("tester", "t")
        rep = run_scan(self._pack([c]), self.runner)
        self.assertEqual(rep.results[0].status, "error")
        self.assertIn("safety gate", rep.results[0].detail)

    def test_missing_fixture_is_an_error_not_a_pass(self):
        c = _check(stig_id="APPL-26-NOPE", command="/bin/echo 1")
        c.approve("tester", "t")
        rep = run_scan(self._pack([c]), self.runner)
        self.assertEqual(rep.results[0].status, "error")

    def test_rejected_check_never_runs(self):
        c = _check(stig_id="APPL-26-005001", command="/usr/bin/csrutil status")
        c.reject("tester", "t", "wrong rule")
        rep = run_scan(self._pack([c]), self.runner)
        self.assertEqual(rep.results[0].status, "skipped")

    def test_severity_filter(self):
        a = _check(stig_id="APPL-26-005001", severity="high",
                   command="/usr/bin/csrutil status", expected="1")
        b = _check(stig_id="APPL-26-002001", severity="medium",
                   command="/usr/bin/csrutil status", expected="PASS")
        for c in (a, b):
            c.approve("tester", "t")
        rep = run_scan(self._pack([a, b]), self.runner, severities={"high"})
        self.assertEqual(len(rep.results), 1)


class TestReport(unittest.TestCase):
    def _report(self, include_unreviewed=True):
        with open(Path(__file__).parent.parent / "checkpacks" / "macos-26-v1r3.json") as f:
            pack = CheckPack.load(Path(f.name))
        return run_scan(pack, FixtureRunner(FIXTURES),
                        include_unreviewed=include_unreviewed, severities={"high"})

    def test_markdown_warns_when_results_are_untrusted(self):
        md = to_markdown(self._report(True))
        self.assertIn("untrusted", md.lower())

    def test_markdown_states_evaluated_coverage(self):
        self.assertIn("were actually evaluated", to_markdown(self._report(True)))

    def test_json_is_machine_readable_and_carries_counts(self):
        data = json.loads(to_json(self._report(True)))
        self.assertIn("counts", data)
        self.assertEqual(sum(data["counts"].values()), len(data["results"]))

    def test_nothing_runs_when_nothing_is_approved(self):
        rep = self._report(include_unreviewed=False)
        self.assertEqual(rep.counts()["pass"], 0)
        self.assertEqual(rep.counts()["fail"], 0)


class TestRealPackIntegrity(unittest.TestCase):
    """The shipped macOS pack must not contain approvals or unsafe commands."""

    def setUp(self):
        self.pack = CheckPack.load(
            Path(__file__).parent.parent / "checkpacks" / "macos-26-v1r3.json")

    def test_ships_entirely_unreviewed(self):
        self.assertTrue(all(c.review_status == UNREVIEWED for c in self.pack.checks))

    def test_no_approved_check_is_unsafe(self):
        for c in self.pack.checks:
            if c.review_status == APPROVED:
                self.assertEqual(audit(c.command), [], f"{c.stig_id} approved but unsafe")

    def test_every_shell_check_has_an_expected_value_and_provenance(self):
        for c in self.pack.checks:
            if c.mode == "shell":
                self.assertTrue(c.expected_source, f"{c.stig_id} lacks provenance")
                self.assertTrue(c.command.strip(), f"{c.stig_id} has an empty command")

    def test_no_command_contains_the_verdict_sentence(self):
        for c in self.pack.checks:
            self.assertNotIn("this is a finding", c.command.lower())


if __name__ == "__main__":
    unittest.main()
