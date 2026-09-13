"""Configured scanner packages: filter, stay unreviewed, keep launchers."""

import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from stigscan.pack import Check, CheckPack, PackError, UNREVIEWED
from stigscan.selection import (
    SelectionError, apply_selection, load_selection, make_selection, write_selection,
)

ROOT = Path(__file__).resolve().parents[1]


def _pack(*ids):
    checks = [
        Check(stig_id=sid, title=sid, mode="shell",
              command="/bin/echo 1", comparator="equals", expected="1",
              review_status=UNREVIEWED)
        for sid in ids
    ]
    return CheckPack(pack_id="demo-pack", platform="macos",
                     stig_title="Demo", checks=checks)


class TestPackSubset(unittest.TestCase):
    def test_keeps_only_the_named_rules_in_that_order(self):
        got = _pack("A", "B", "C").subset(["C", "A"])
        self.assertEqual([c.stig_id for c in got.checks], ["C", "A"])
        self.assertTrue(got.pack_id.endswith("-selected"))

    def test_does_not_approve_anything(self):
        got = _pack("A", "B").subset(["A"])
        self.assertTrue(all(c.review_status == UNREVIEWED for c in got.checks))

    def test_refuses_an_empty_selection(self):
        with self.assertRaises(PackError):
            _pack("A").subset([])

    def test_refuses_an_id_that_is_not_in_the_pack(self):
        with self.assertRaises(PackError) as e:
            _pack("A").subset(["NOPE"])
        self.assertIn("NOPE", str(e.exception))


class TestSelection(unittest.TestCase):
    def test_round_trip(self):
        sel = make_selection(platform="macos", guide_key="macos-26",
                             source_pack="demo-pack", rule_ids=["A", "A", "B"])
        self.assertEqual(sel["rule_ids"], ["A", "B"])
        self.assertTrue(sel["unreviewed"])
        with TemporaryDirectory() as tmp:
            path = write_selection(Path(tmp) / "selection.json", sel)
            loaded = load_selection(path)
        self.assertEqual(loaded["rule_ids"], ["A", "B"])

    def test_apply_refuses_a_platform_mismatch(self):
        sel = make_selection(platform="windows", guide_key="windows-11",
                             source_pack="demo-pack", rule_ids=["A"])
        with self.assertRaises(SelectionError):
            apply_selection(_pack("A"), sel)

    def test_apply_filters_the_pack(self):
        sel = make_selection(platform="macos", guide_key="macos-26",
                             source_pack="demo-pack", rule_ids=["B"])
        got = apply_selection(_pack("A", "B"), sel)
        self.assertEqual([c.stig_id for c in got.checks], ["B"])


class TestBuildScanpack(unittest.TestCase):
    def test_writes_a_runnable_folder_with_the_selection(self):
        import sys
        sys.path.insert(0, str(ROOT / "packaging"))
        from build_scanpack import build_configured

        source = CheckPack.load(ROOT / "checkpacks" / "macos-26-v1r3.json")
        ids = [c.stig_id for c in source.checks if c.mode == "shell"][:3]
        with TemporaryDirectory() as tmp:
            dest = Path(tmp) / "STIG-Scanner-macOS"
            sel = build_configured(
                dest, platform="macos", pack=source, rule_ids=ids,
                guide_key="macos-26",
                annotation="U_Apple_macOS_26_V1R3_STIG_Manual-xccdf.ai-cache.json",
                root=ROOT,
            )
            self.assertTrue((dest / "selection.json").is_file())
            self.assertTrue((dest / "stigui" / "app.html").is_file())
            self.assertTrue((dest / "Start.command").is_file())
            loaded = json.loads((dest / "selection.json").read_text())
            self.assertEqual(loaded["rule_ids"], ids)
            pack = CheckPack.load(dest / sel["pack_path"])
            self.assertEqual([c.stig_id for c in pack.checks], ids)
            self.assertTrue(all(c.review_status == UNREVIEWED for c in pack.checks))
            self.assertFalse((dest / "checkpacks" / "rhel-9-v2r9.json").exists())
            self.assertIn("--selection", (dest / "Start.command").read_text())


if __name__ == "__main__":
    unittest.main()
