"""Plain-language remaining-risk summary: honest, coverage-first, no fake score."""

import unittest

from stigscan.evaluate import FAIL, MANUAL, PASS, SKIPPED
from stigscan.pdf import to_pdf
from stigscan.report import to_json, to_markdown
from stigscan.scan import Result, ScanReport
from stigscan.summary import (
    RISK_CRITICAL, RISK_HIGH, RISK_INCOMPLETE, RISK_LOW, RISK_MODERATE,
    breakdown_rows, summarize, summarize_report, text_bar,
)


def _counts(p=0, f=0, e=0, m=0, s=0):
    return {"pass": p, "fail": f, "error": e, "manual": m, "skipped": s}


def _report(results):
    return ScanReport(
        pack_id="test-pack",
        stig_title="Test STIG",
        stig_version="V1R1",
        started="2026-09-13T00:00:00Z",
        finished="2026-09-13T00:00:01Z",
        host={"hostname": "box", "system": "Linux"},
        options={"runner": "FixtureRunner"},
        results=results,
    )


class TestRiskLevels(unittest.TestCase):
    def test_cat1_fail_is_critical_even_when_most_rules_pass(self):
        story = summarize(counts=_counts(p=100, f=1), total=120,
                          fails_by_severity={"high": 1})
        self.assertEqual(story.risk, RISK_CRITICAL)
        self.assertIn("CAT I", story.headline)
        self.assertNotIn("percent secure", story.meaning.lower())
        self.assertIn("not a percentage of how secure", story.meaning.lower())

    def test_three_cat2_fails_are_high(self):
        story = summarize(counts=_counts(p=20, f=3), total=40,
                          fails_by_severity={"medium": 3})
        self.assertEqual(story.risk, RISK_HIGH)

    def test_half_failing_is_high_even_if_only_cat3(self):
        story = summarize(counts=_counts(p=5, f=5), total=10,
                          fails_by_severity={"low": 5})
        self.assertEqual(story.risk, RISK_HIGH)

    def test_one_cat2_fail_is_moderate(self):
        story = summarize(counts=_counts(p=40, f=1), total=50,
                          fails_by_severity={"medium": 1})
        self.assertEqual(story.risk, RISK_MODERATE)

    def test_one_or_two_cat3_fails_are_low(self):
        story = summarize(counts=_counts(p=40, f=2), total=50,
                          fails_by_severity={"low": 2})
        self.assertEqual(story.risk, RISK_LOW)
        self.assertIn("lower-severity", story.headline)

    def test_no_fails_with_a_coverage_gap_is_low_not_secure(self):
        story = summarize(counts=_counts(p=19, f=0, e=5, s=40), total=64)
        self.assertEqual(story.risk, RISK_LOW)
        self.assertIn("No failures among", story.headline)
        self.assertIn("not a clean bill of health", story.meaning)
        self.assertIn("were not evaluated", story.meaning)

    def test_full_coverage_and_no_fails_says_we_checked_every_rule(self):
        story = summarize(counts=_counts(p=10, f=0), total=10)
        self.assertEqual(story.risk, RISK_LOW)
        self.assertIn("checked every rule", story.headline)
        self.assertNotIn("not a clean bill", story.meaning)

    def test_nothing_evaluated_is_incomplete(self):
        story = summarize(counts=_counts(s=40, m=10, e=5), total=55)
        self.assertEqual(story.risk, RISK_INCOMPLETE)
        self.assertEqual(story.evaluated, 0)
        self.assertIn("could not judge", story.headline.lower())
        self.assertIn("cannot be judged", story.judged_line.lower())

    def test_empty_report_is_incomplete(self):
        story = summarize(counts=_counts(), total=0)
        self.assertEqual(story.risk, RISK_INCOMPLETE)

    def test_coverage_and_fail_rate_are_among_what_we_could_check(self):
        story = summarize(counts=_counts(p=19, f=90, e=5, s=40), total=154,
                          fails_by_severity={"high": 3, "medium": 80, "low": 7})
        self.assertEqual(story.evaluated, 109)
        self.assertEqual(story.not_evaluated, 45)
        self.assertEqual(story.coverage_pct, 70.8)
        self.assertEqual(story.fail_rate_pct, 82.6)
        self.assertEqual(story.risk, RISK_CRITICAL)
        self.assertIn("90 of 109", story.judged_line)
        self.assertIn("were actually evaluated", story.coverage_line)


class TestReportSurfaces(unittest.TestCase):
    def _mixed(self):
        return _report([
            Result(stig_id="APPL-26-000001", group_id="V-1", severity="high",
                   title="SIP must be enabled", status=PASS, detail="matched"),
            Result(stig_id="APPL-26-000002", group_id="V-2", severity="high",
                   title="FileVault must be on", status=FAIL, detail="expected 1"),
            Result(stig_id="APPL-26-000003", group_id="V-3", severity="medium",
                   title="A GUI check", status=SKIPPED, detail="unreviewed"),
            Result(stig_id="APPL-26-000004", group_id="V-4", severity="low",
                   title="Interview", status=MANUAL, detail="needs a person"),
        ])

    def test_summarize_report_lists_cat1_failures(self):
        story = summarize_report(self._mixed())
        self.assertEqual(story.risk, RISK_CRITICAL)
        self.assertEqual(len(story.serious_fails), 1)
        self.assertEqual(story.serious_fails[0]["stig_id"], "APPL-26-000002")

    def test_markdown_keeps_coverage_and_adds_the_plain_story(self):
        md = to_markdown(self._mixed())
        self.assertIn("were actually evaluated", md)
        self.assertIn("What this means", md)
        self.assertIn("Critical remaining risk", md)
        self.assertIn("#####", md)
        self.assertNotIn("% secure", md)

    def test_json_carries_the_summary(self):
        data = __import__("json").loads(to_json(self._mixed()))
        self.assertEqual(data["summary"]["risk"], RISK_CRITICAL)
        self.assertIn("headline", data["summary"])

    def test_pdf_still_leads_with_coverage_and_adds_bars(self):
        text = to_pdf(self._mixed()).decode("latin-1", "replace")
        self.assertIn("were actually evaluated", text)
        self.assertIn("Coverage", text)
        self.assertIn("What this means", text)
        self.assertIn("How the numbers break down", text)
        self.assertIn("[", text)
        self.assertIn("#", text)

    def test_ascii_bar_is_fixed_width_and_shows_a_sliver_for_nonzero(self):
        self.assertEqual(len(text_bar(0, 10, 10)), 12)  # [ + 10 + ]
        self.assertEqual(text_bar(0, 10, 8), "[" + "." * 8 + "]")
        self.assertIn("#", text_bar(1, 100, 8))
        rows = breakdown_rows(summarize(counts=_counts(p=19, f=90, e=5, s=40), total=154))
        self.assertEqual(len(rows), 4)
        self.assertEqual(rows[1][2], "90")


if __name__ == "__main__":
    unittest.main()
