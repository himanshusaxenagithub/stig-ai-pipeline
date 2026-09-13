"""PDF reports: coverage first, no extra dependency, valid PDF header."""

import unittest

from stigscan.evaluate import PASS, FAIL, SKIPPED
from stigscan.pdf import to_pdf
from stigscan.scan import Result, ScanReport


def _report(untrusted=False):
    return ScanReport(
        pack_id="test-pack",
        stig_title="Test STIG",
        stig_version="V1R1",
        started="2026-09-13T00:00:00Z",
        finished="2026-09-13T00:00:01Z",
        host={"hostname": "box", "system": "Darwin", "macos_version": "26.0"},
        options={"runner": "FixtureRunner"},
        results=[
            Result(stig_id="APPL-26-000001", group_id="V-1", severity="high",
                   title="SIP must be enabled", status=PASS, detail="matched",
                   trusted=not untrusted),
            Result(stig_id="APPL-26-000002", group_id="V-2", severity="medium",
                   title="A GUI check", status=SKIPPED,
                   detail="unreviewed — approve it"),
            Result(stig_id="APPL-26-000003", group_id="V-3", severity="high",
                   title="Something failed", status=FAIL, detail="expected 1"),
        ],
    )


class TestPdfReport(unittest.TestCase):
    def test_is_a_pdf(self):
        pdf = to_pdf(_report())
        self.assertTrue(pdf.startswith(b"%PDF-1.4"))
        self.assertIn(b"%%EOF", pdf)
        self.assertIn(b"xref", pdf)

    def test_leads_with_coverage(self):
        text = to_pdf(_report()).decode("latin-1", "replace")
        self.assertIn("were actually evaluated", text)
        self.assertIn("Coverage", text)
        self.assertIn("APPL-26-000001", text)

    def test_warns_when_results_are_untrusted(self):
        text = to_pdf(_report(untrusted=True)).decode("latin-1", "replace")
        self.assertIn("WARNING", text)
        self.assertIn("unreviewed", text.lower())

    def test_escapes_parentheses_in_titles(self):
        r = _report()
        r.results[0].title = "Limit SSH (FIPS) ciphers"
        pdf = to_pdf(r)
        self.assertTrue(pdf.startswith(b"%PDF-1.4"))
        self.assertIn(b"FIPS", pdf)


if __name__ == "__main__":
    unittest.main()
