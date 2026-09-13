"""Tests for stig-assess (module 3).

The behaviour worth protecting here is refusal: drafts only, never an
auto-close, never a POA&M for a passing result, and never a closure
without a named person and a note.
"""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from stigassess.interpret import draft_from_path, draft_from_scan
from stigassess.load import LoadError, load_explanations, load_scan
from stigassess.poam import (
    APPROVED,
    CLOSED,
    CLOSURE_REMEDIATED,
    CLOSURE_RISK_ACCEPTED,
    DRAFT,
    KIND_EVALUATION_GAP,
    KIND_FINDING,
    KIND_MANUAL,
    OPEN,
    UNREVIEWED,
    PackError,
    PoamEntry,
    PoamPack,
)
from stigassess.render import to_csv, to_json, to_markdown
import stigassess.__main__ as assess_main

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).parent / "fixtures" / "assess"
SCAN = FIXTURES / "scan_mixed.json"
CHECKLIST = FIXTURES / "checklist.json"
SKILL = ROOT / "skills" / "stig-assess" / "scripts" / "assess.py"


def _entry(**kw):
    base = dict(
        stig_id="TEST-0001",
        weakness="Test weakness",
        description="The scan found a failure.",
        recommendation="Read the STIG fix text.",
        finding_status="fail",
        kind=KIND_FINDING,
    )
    base.update(kw)
    return PoamEntry(**base)


class TestLoad(unittest.TestCase):
    def test_scan_fixture_has_the_shape_module_2_writes(self):
        scan = load_scan(SCAN)
        self.assertEqual(scan["pack_id"], "fixture-mixed")
        self.assertEqual(len(scan["results"]), 7)

    def test_missing_scan_is_a_load_error(self):
        with self.assertRaises(LoadError):
            load_scan(FIXTURES / "no-such.json")

    def test_non_object_scan_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "x.json"
            p.write_text("[]\n", encoding="utf-8")
            with self.assertRaises(LoadError):
                load_scan(p)

    def test_scan_without_results_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "x.json"
            p.write_text('{"pack_id": "x"}\n', encoding="utf-8")
            with self.assertRaises(LoadError):
                load_scan(p)

    def test_explanations_come_from_the_checklist_ai_block(self):
        expl = load_explanations(CHECKLIST)
        self.assertEqual(expl["APPL-26-005001"]["triage"], "risky-change")
        self.assertIn("csrutil enable", expl["APPL-26-005001"]["fix_text"])

    def test_annotation_cache_keys_are_split_on_model_prefix(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "cache.json"
            p.write_text(json.dumps({
                "claude:APPL-26-005001": {"summary": "from cache", "triage": "quick-win"},
            }), encoding="utf-8")
            expl = load_explanations(annotations=p)
        self.assertEqual(expl["APPL-26-005001"]["summary"], "from cache")

    def test_checklist_explanations_override_the_cache(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "cache.json"
            p.write_text(json.dumps({
                "x:APPL-26-005001": {"summary": "stale"},
            }), encoding="utf-8")
            expl = load_explanations(CHECKLIST, p)
        self.assertIn("System Integrity Protection", expl["APPL-26-005001"]["summary"])


class TestDraftFromScan(unittest.TestCase):
    def setUp(self):
        self.pack = draft_from_path(SCAN, checklist=CHECKLIST)

    def test_default_drafts_only_failures(self):
        ids = {e.stig_id for e in self.pack.entries}
        self.assertEqual(ids, {"APPL-26-005001", "APPL-26-002064", "APPL-26-002069"})
        self.assertTrue(all(e.kind == KIND_FINDING for e in self.pack.entries))

    def test_pass_is_never_drafted(self):
        self.assertIsNone(self.pack.get("APPL-26-000054"))

    def test_skipped_is_never_drafted_by_default(self):
        self.assertIsNone(self.pack.get("APPL-26-002038"))

    def test_every_draft_is_unreviewed_and_not_closed(self):
        for e in self.pack.entries:
            self.assertEqual(e.review_status, UNREVIEWED)
            self.assertEqual(e.poam_status, DRAFT)
            self.assertEqual(e.closure_kind, "")
            self.assertIsNone(e.closed_by)

    def test_filed_explanation_is_attached(self):
        sip = self.pack.get("APPL-26-005001")
        self.assertIn("System Integrity Protection", sip.description)
        self.assertEqual(sip.triage, "risky-change")
        self.assertIn("Recovery OS", sip.recommendation)
        self.assertIn("csrutil enable", sip.recommendation)

    def test_untrusted_failure_is_flagged_not_dropped(self):
        row = self.pack.get("APPL-26-002069")
        self.assertFalse(row.trusted)
        self.assertIn("UNTRUSTED", row.author_note)

    def test_gaps_are_opt_in_and_are_not_findings(self):
        pack = draft_from_path(SCAN, include=("fail", "error", "manual"))
        self.assertEqual(pack.get("APPL-26-002001").kind, KIND_EVALUATION_GAP)
        self.assertEqual(pack.get("APPL-26-000001").kind, KIND_MANUAL)
        self.assertIn("not a finding", pack.get("APPL-26-002001").description.lower())

    def test_refuses_to_draft_passes(self):
        with self.assertRaises(ValueError) as ctx:
            draft_from_path(SCAN, include=("pass",))
        self.assertIn("passed", str(ctx.exception))

    def test_unknown_status_filter_is_refused(self):
        with self.assertRaises(ValueError):
            draft_from_path(SCAN, include=("vibes",))

    def test_resources_and_schedule_stay_blank_for_a_person(self):
        for e in self.pack.entries:
            self.assertTrue(e.resources.startswith("TBD"))
            self.assertEqual(e.scheduled_completion, "")

    def test_cat1_impact_mentions_highest_severity(self):
        self.assertIn("highest severity", self.pack.get("APPL-26-005001").impact)

    def test_draft_from_scan_dict_does_not_need_a_file(self):
        scan = load_scan(SCAN)
        pack = draft_from_scan(scan, include={"fail"})
        self.assertEqual(len(pack.entries), 3)


class TestPoamFreeze(unittest.TestCase):
    def test_new_entry_is_not_closed(self):
        e = _entry()
        self.assertEqual(e.poam_status, DRAFT)
        self.assertEqual(e.review_status, UNREVIEWED)

    def test_approve_opens_and_freezes_wording(self):
        e = _entry()
        e.approve("H. Saxena", "2026-09-13T00:00:00Z")
        self.assertEqual(e.review_status, APPROVED)
        self.assertEqual(e.poam_status, OPEN)
        self.assertTrue(e.approved_digest.startswith("sha256:"))
        self.assertFalse(e.is_drifted())

    def test_approve_does_not_close(self):
        e = _entry()
        e.approve("H. Saxena", "t")
        self.assertNotEqual(e.poam_status, CLOSED)

    def test_editing_after_approval_causes_drift(self):
        e = _entry()
        e.approve("H. Saxena", "t")
        e.description = "rewritten after review"
        self.assertTrue(e.is_drifted())

    def test_empty_name_cannot_approve(self):
        with self.assertRaises(PackError):
            _entry().approve("  ", "t")

    def test_empty_description_cannot_be_approved(self):
        with self.assertRaises(PackError):
            _entry(description="  ").approve("H", "t")

    def test_close_requires_approval_name_kind_and_note(self):
        e = _entry()
        with self.assertRaises(PackError):
            e.close("H", "t", CLOSURE_REMEDIATED, "fixed")
        e.approve("H", "t")
        with self.assertRaises(PackError):
            e.close("H", "t", CLOSURE_REMEDIATED, "")
        with self.assertRaises(PackError):
            e.close("H", "t", "ship-it", "note")
        with self.assertRaises(PackError):
            e.close("", "t", CLOSURE_REMEDIATED, "note")
        e.close("H. Saxena", "t", CLOSURE_RISK_ACCEPTED, "accepted until next ATO")
        self.assertEqual(e.poam_status, CLOSED)
        self.assertEqual(e.closure_kind, CLOSURE_RISK_ACCEPTED)
        self.assertEqual(e.closed_by, "H. Saxena")

    def test_drifted_wording_cannot_be_closed(self):
        e = _entry()
        e.approve("H", "t")
        e.recommendation = "changed"
        with self.assertRaises(PackError) as ctx:
            e.close("H", "t", CLOSURE_REMEDIATED, "done")
        self.assertIn("drifted", str(ctx.exception).lower())

    def test_reopen_clears_closure_and_keeps_the_name(self):
        e = _entry()
        e.approve("H", "t")
        e.close("H", "t", CLOSURE_REMEDIATED, "fixed")
        e.reopen("H", "t2", "found again")
        self.assertEqual(e.poam_status, OPEN)
        self.assertEqual(e.closure_kind, "")
        self.assertIsNone(e.closed_by)

    def test_roundtrip_preserves_approval(self):
        e = _entry()
        e.approve("H. Saxena", "2026-09-13T00:00:00Z")
        pack = PoamPack(pack_id="t", entries=[e])
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "poam.json"
            pack.save(p)
            again = PoamPack.load(p)
        self.assertEqual(again.entries[0].review_status, APPROVED)
        self.assertFalse(again.entries[0].is_drifted())

    def test_duplicate_ids_are_rejected_on_load(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "poam.json"
            p.write_text(json.dumps({
                "pack_format": 1, "pack_id": "t",
                "entries": [{"stig_id": "A"}, {"stig_id": "A"}],
            }))
            with self.assertRaises(PackError):
                PoamPack.load(p)

    def test_future_pack_format_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "poam.json"
            p.write_text(json.dumps({"pack_format": 99, "pack_id": "t", "entries": []}))
            with self.assertRaises(PackError):
                PoamPack.load(p)

    def test_closed_row_without_a_kind_is_rejected_on_load(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "poam.json"
            p.write_text(json.dumps({
                "pack_format": 1, "pack_id": "t",
                "entries": [{
                    "stig_id": "A", "description": "x",
                    "poam_status": "closed", "review_status": "approved",
                    "closure_kind": "",
                }],
            }))
            with self.assertRaises(PackError):
                PoamPack.load(p)

    def test_unknown_field_is_rejected(self):
        with self.assertRaises(PackError):
            PoamEntry.from_dict({"stig_id": "A", "secret_flag": True})


class TestRender(unittest.TestCase):
    def setUp(self):
        self.pack = draft_from_path(SCAN, checklist=CHECKLIST)

    def test_markdown_says_nothing_is_closed(self):
        md = to_markdown(self.pack)
        self.assertIn("0 closed", md)
        self.assertIn("never marks an item complete", md)
        self.assertIn("APPL-26-005001", md)
        self.assertNotIn("APPL-26-000054", md)

    def test_markdown_warns_on_untrusted_drafts(self):
        self.assertIn("untrusted", to_markdown(self.pack).lower())

    def test_json_carries_summary_and_digests(self):
        data = json.loads(to_json(self.pack))
        self.assertEqual(data["summary"]["findings"], 3)
        self.assertEqual(data["summary"]["closed"], 0)
        self.assertTrue(data["entries"][0]["digest"].startswith("sha256:"))

    def test_csv_has_a_row_per_entry(self):
        lines = to_csv(self.pack).strip().splitlines()
        self.assertEqual(len(lines), 1 + len(self.pack.entries))
        self.assertTrue(lines[0].startswith("stig_id,"))


class TestCLI(unittest.TestCase):
    def _run(self, argv):
        buf = io.StringIO()
        err = io.StringIO()
        with redirect_stdout(buf), redirect_stderr(err):
            code = assess_main.main(argv)
        return code, buf.getvalue(), err.getvalue()

    def test_draft_review_approve_verify_render(self):
        with tempfile.TemporaryDirectory() as d:
            poam = Path(d) / "poam.json"
            code, out, err = self._run([
                "draft", str(SCAN), "-o", str(poam),
                "--checklist", str(CHECKLIST),
            ])
            self.assertEqual(code, 0, err)
            self.assertIn("UNREVIEWED", out)
            self.assertIn("Nothing is closed", out)

            code, out, _ = self._run(["review", str(poam), "--severity", "high", "--show"])
            self.assertEqual(code, 0)
            self.assertIn("APPL-26-005001", out)
            self.assertNotIn("APPL-26-002064", out)

            code, out, err = self._run([
                "approve", str(poam), "--by", "H. Saxena", "--id", "APPL-26-005001",
            ])
            self.assertEqual(code, 0, err)
            self.assertIn("not closed", out.lower())

            loaded = PoamPack.load(poam)
            self.assertEqual(loaded.get("APPL-26-005001").poam_status, OPEN)
            self.assertEqual(loaded.get("APPL-26-002064").poam_status, DRAFT)

            code, out, err = self._run(["verify", str(poam)])
            self.assertEqual(code, 0, err)
            self.assertIn("Verify OK", out)

            dest = Path(d) / "out"
            code, out, err = self._run(["render", str(poam), "-o", str(dest)])
            self.assertEqual(code, 0, err)
            self.assertTrue((dest / "fixture-mixed-poam.md").exists())
            self.assertTrue((dest / "fixture-mixed-poam.csv").exists())

    def test_draft_refuses_pass_on_the_cli(self):
        with tempfile.TemporaryDirectory() as d:
            code, _, err = self._run([
                "draft", str(SCAN), "-o", str(Path(d) / "x.json"),
                "--include", "pass",
            ])
        self.assertEqual(code, 1)
        self.assertIn("passed", err)

    def test_close_without_approval_fails(self):
        with tempfile.TemporaryDirectory() as d:
            poam = Path(d) / "poam.json"
            self.assertEqual(self._run([
                "draft", str(SCAN), "-o", str(poam),
            ])[0], 0)
            code, _, err = self._run([
                "close", str(poam), "--by", "H", "--id", "APPL-26-005001",
                "--kind", "remediated", "--note", "fixed",
            ])
        self.assertEqual(code, 1)
        self.assertIn("approve", err.lower())

    def test_unknown_id_is_an_error(self):
        with tempfile.TemporaryDirectory() as d:
            poam = Path(d) / "poam.json"
            self._run(["draft", str(SCAN), "-o", str(poam)])
            code, _, err = self._run([
                "approve", str(poam), "--by", "H", "--id", "NO-SUCH",
            ])
        self.assertEqual(code, 1)
        self.assertIn("NO-SUCH", err)

    def test_close_then_reopen(self):
        with tempfile.TemporaryDirectory() as d:
            poam = Path(d) / "poam.json"
            self._run(["draft", str(SCAN), "-o", str(poam)])
            self._run(["approve", str(poam), "--by", "H", "--id", "APPL-26-005001"])
            code, out, err = self._run([
                "close", str(poam), "--by", "H", "--id", "APPL-26-005001",
                "--kind", "remediated", "--note", "re-scan pass after SIP enabled",
            ])
            self.assertEqual(code, 0, err)
            self.assertEqual(PoamPack.load(poam).get("APPL-26-005001").poam_status, CLOSED)
            code, _, err = self._run([
                "reopen", str(poam), "--by", "H", "--id", "APPL-26-005001",
            ])
            self.assertEqual(code, 0, err)
            self.assertEqual(PoamPack.load(poam).get("APPL-26-005001").poam_status, OPEN)

    def test_verify_fails_on_drift(self):
        with tempfile.TemporaryDirectory() as d:
            poam = Path(d) / "poam.json"
            self._run(["draft", str(SCAN), "-o", str(poam)])
            self._run(["approve", str(poam), "--by", "H", "--id", "APPL-26-005001"])
            pack = PoamPack.load(poam)
            pack.get("APPL-26-005001").description = "tampered"
            pack.save(poam)
            code, _, err = self._run(["verify", str(poam)])
        self.assertEqual(code, 2)
        self.assertIn("VERIFY FAILED", err)

    def test_reject_returns_item_to_draft(self):
        with tempfile.TemporaryDirectory() as d:
            poam = Path(d) / "poam.json"
            self._run(["draft", str(SCAN), "-o", str(poam)])
            self._run(["approve", str(poam), "--by", "H", "--id", "APPL-26-005001"])
            code, _, err = self._run([
                "reject", str(poam), "--by", "H", "--id", "APPL-26-005001",
                "--note", "wrong rule",
            ])
            self.assertEqual(code, 0, err)
            e = PoamPack.load(poam).get("APPL-26-005001")
            self.assertEqual(e.review_status, "rejected")
            self.assertEqual(e.poam_status, DRAFT)


class TestSkillHelper(unittest.TestCase):
    def _script(self, argv, cwd=None):
        import subprocess
        proc = subprocess.run(
            [sys.executable, str(SKILL), *argv],
            cwd=cwd, capture_output=True, text=True,
        )
        return proc.returncode, proc.stdout, proc.stderr

    def _poam(self, folder: Path) -> Path:
        dest = folder / "poam.json"
        draft_from_path(SCAN, checklist=CHECKLIST).save(dest)
        return dest

    def test_next_prints_unapproved_items(self):
        with tempfile.TemporaryDirectory() as d:
            poam = self._poam(Path(d))
            code, out, err = self._script(["next", str(poam), "--limit", "2"])
        self.assertEqual(code, 0, err)
        batch = json.loads(out)
        self.assertEqual(len(batch), 2)
        self.assertIn("stig_id", batch[0])
        self.assertIn("command", batch[0])

    def test_merge_rejects_a_closure_attempt(self):
        with tempfile.TemporaryDirectory() as d:
            poam = self._poam(Path(d))
            batch = Path(d) / "batch.json"
            batch.write_text(json.dumps([{
                "stig_id": "APPL-26-005001",
                "description": "SIP is off.",
                "recommendation": "Enable it in Recovery.",
                "resources": "TBD",
                "scheduled_completion": "",
                "poam_status": "closed",
                "closure_kind": "remediated",
            }]), encoding="utf-8")
            code, _, err = self._script(["merge", str(poam), str(batch)])
        self.assertEqual(code, 2)
        self.assertIn("rejected", err)
        self.assertIn("closure", err)

    def test_merge_rejects_invented_commands(self):
        with tempfile.TemporaryDirectory() as d:
            poam = self._poam(Path(d))
            batch = Path(d) / "batch.json"
            batch.write_text(json.dumps([{
                "stig_id": "APPL-26-005001",
                "description": "failed",
                "recommendation": "run defaults write com.apple.MCX DestroyFVKeyOnStandby -bool true",
                "resources": "TBD",
                "scheduled_completion": "",
            }]), encoding="utf-8")
            code, _, err = self._script(["merge", str(poam), str(batch)])
        self.assertEqual(code, 2)
        self.assertIn("command-like", err)

    def test_merge_accepts_a_clean_batch_and_resets_review(self):
        with tempfile.TemporaryDirectory() as d:
            poam = self._poam(Path(d))
            pack = PoamPack.load(poam)
            pack.get("APPL-26-005001").approve("H", "t")
            pack.save(poam)
            batch = Path(d) / "batch.json"
            batch.write_text(json.dumps([{
                "stig_id": "APPL-26-005001",
                "description": "SIP is reported off. This draft is not a closure.",
                "recommendation": "Use /usr/bin/csrutil status to confirm, then decide.",
                "resources": "TBD — a person must estimate",
                "scheduled_completion": "",
            }]), encoding="utf-8")
            code, out, err = self._script(
                ["merge", str(poam), str(batch), "--model", "test-model"])
            self.assertEqual(code, 0, err)
            self.assertIn("merged 1", out)
            again = PoamPack.load(poam)
            e = again.get("APPL-26-005001")
            self.assertEqual(e.review_status, UNREVIEWED)
            self.assertEqual(e.poam_status, DRAFT)
            self.assertIn("not a closure", e.description)
            self.assertEqual(e.authored_by, "test-model")

    def test_status_reports_closed_count(self):
        with tempfile.TemporaryDirectory() as d:
            poam = self._poam(Path(d))
            code, out, err = self._script(["status", str(poam)])
        self.assertEqual(code, 0, err)
        self.assertIn("0 closed", out)

    def test_skill_text_forbids_silent_closure(self):
        text = (ROOT / "skills" / "stig-assess" / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("never marks a finding complete", text.lower())
        self.assertIn("Never run `close` yourself", text)
        self.assertIn("Never run `approve` yourself", text)


class TestSkillPresence(unittest.TestCase):
    def test_skill_layout_mirrors_explain(self):
        skill = ROOT / "skills" / "stig-assess"
        self.assertTrue((skill / "SKILL.md").is_file())
        self.assertTrue((skill / "scripts" / "assess.py").is_file())
        header = (skill / "SKILL.md").read_text(encoding="utf-8").split("---", 2)[1]
        self.assertIn("name: stig-assess", header)


if __name__ == "__main__":
    unittest.main()
