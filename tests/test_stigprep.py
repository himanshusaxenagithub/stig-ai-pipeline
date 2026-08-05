"""Tests for stig-prep. Run from the repo root:  python3 -m unittest discover tests"""

import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from stigprep.parser import parse_stig, _extract_discussion  # noqa: E402
from stigprep.render import to_markdown, to_json, to_csv  # noqa: E402
from stigprep import explain as explain_mod  # noqa: E402

SAMPLE = ROOT / "samples" / "sample_macos15_stig.xml"


class TestParser(unittest.TestCase):
    def test_parses_all_rules(self):
        b = parse_stig(SAMPLE)
        self.assertEqual(len(b.rules), 6)
        self.assertIn("macOS 15", b.title)

    def test_rule_fields(self):
        b = parse_stig(SAMPLE)
        by_id = {r.stig_id: r for r in b.rules}
        r = by_id["APPL-15-000022"]
        self.assertEqual(r.group_id, "V-268428")
        self.assertEqual(r.severity, "medium")
        self.assertEqual(r.cat, "CAT II")
        self.assertIn("three", r.title)
        self.assertIn("brute-force", r.discussion)
        self.assertIn("pwpolicy", r.check_text)
        self.assertIn("passwordpolicy", r.fix_text)
        self.assertEqual(r.ccis, ["CCI-000044", "CCI-002238"])

    def test_severity_sorting(self):
        b = parse_stig(SAMPLE)
        severities = [r.severity for r in b.rules]
        self.assertEqual(severities, sorted(
            severities, key=lambda s: {"high": 0, "medium": 1, "low": 2}[s]))

    def test_discussion_extraction_strips_pseudotags(self):
        raw = ("&lt;VulnDiscussion&gt;Real text here.&lt;/VulnDiscussion&gt;"
               "&lt;FalsePositives&gt;&lt;/FalsePositives&gt;")
        self.assertEqual(_extract_discussion(raw), "Real text here.")

    def test_zip_input(self):
        with tempfile.TemporaryDirectory() as td:
            zpath = Path(td) / "U_Sample_STIG.zip"
            with zipfile.ZipFile(zpath, "w") as z:
                z.write(SAMPLE, "U_Sample_STIG/U_Sample_Manual-xccdf.xml")
            b = parse_stig(zpath)
            self.assertEqual(len(b.rules), 6)


class TestRender(unittest.TestCase):
    def setUp(self):
        self.b = parse_stig(SAMPLE)

    def test_markdown(self):
        md = to_markdown(self.b)
        self.assertIn("# STIG Checklist", md)
        self.assertIn("APPL-15-000002", md)
        self.assertIn("CAT III", md)  # the low-severity sample rule
        self.assertIn("**Check:**", md)

    def test_json_roundtrip(self):
        data = json.loads(to_json(self.b))
        self.assertEqual(data["rule_count"], 6)
        self.assertEqual(len(data["rules"]), 6)

    def test_csv(self):
        lines = to_csv(self.b).strip().splitlines()
        self.assertEqual(len(lines), 7)  # header + 6 rules
        self.assertTrue(lines[0].startswith("stig_id,"))


class TestExplain(unittest.TestCase):
    def test_missing_api_key_raises(self):
        b = parse_stig(SAMPLE)
        with mock.patch.dict("os.environ", {"ANTHROPIC_API_KEY": ""}):
            with self.assertRaises(explain_mod.ExplainError):
                explain_mod.explain(b, SAMPLE)

    def test_annotation_and_cache(self):
        b = parse_stig(SAMPLE)

        def fake_api(rules_payload, model, api_key):
            return [{
                "stig_id": r["stig_id"],
                "summary": f"Explains {r['stig_id']}.",
                "triage": "quick-win",
                "automation": "automatable",
                "caution": "",
            } for r in rules_payload]

        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "sample.xml"
            src.write_bytes(SAMPLE.read_bytes())
            with mock.patch.dict("os.environ",
                                 {"ANTHROPIC_API_KEY": "sk-test"}), \
                 mock.patch.object(explain_mod, "_call_api",
                                   side_effect=fake_api) as api:
                n = explain_mod.explain(b, src, progress=False)
                self.assertEqual(n, 6)
                self.assertTrue(all(r.ai for r in b.rules))
                # Second run: everything served from cache, no API calls
                b2 = parse_stig(src)
                first_calls = api.call_count
                n2 = explain_mod.explain(b2, src, progress=False)
                self.assertEqual(n2, 0)
                self.assertEqual(api.call_count, first_calls)
                self.assertTrue(all(r.ai for r in b2.rules))

    def test_invalid_triage_normalized(self):
        b = parse_stig(SAMPLE)

        def fake_api(rules_payload, model, api_key):
            return [{"stig_id": r["stig_id"], "summary": "x",
                     "triage": "banana", "automation": "manual",
                     "caution": ""} for r in rules_payload]

        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "sample.xml"
            src.write_bytes(SAMPLE.read_bytes())
            with mock.patch.dict("os.environ",
                                 {"ANTHROPIC_API_KEY": "sk-test"}), \
                 mock.patch.object(explain_mod, "_call_api",
                                   side_effect=fake_api):
                explain_mod.explain(b, src, progress=False)
        self.assertTrue(all(r.ai["triage"] == "needs-judgment"
                            for r in b.rules))


if __name__ == "__main__":
    unittest.main()
