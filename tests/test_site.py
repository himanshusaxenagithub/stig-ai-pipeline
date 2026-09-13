"""The GitHub Pages export: catalogue, explanations, scanner payload."""

import json
import unittest
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import urlparse

from stigprep.catalog import DOWNLOAD_PAGE, scannable_guides

ROOT = Path(__file__).resolve().parents[1]


class TestSiteExport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import runpy
        cls.tmp = TemporaryDirectory()
        cls.out = Path(cls.tmp.name)
        # Load as a script so we do not import the PyPI ``packaging`` package.
        ns = runpy.run_path(str(ROOT / "packaging" / "build_site.py"))
        ns["export"](cls.out)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_catalog_names_the_desktop_guides_and_the_fallback_page(self):
        data = json.loads((self.out / "data" / "catalog.json").read_text())
        keys = {g["key"] for g in data["guides"]}
        self.assertIn("macos-26", keys)
        self.assertIn("windows-11", keys)
        self.assertEqual(data["download_page"], DOWNLOAD_PAGE)
        self.assertIn("dl.dod.cyber.mil", data["note"])
        mac = next(g for g in data["guides"] if g["key"] == "macos-26")
        self.assertEqual(mac["rules"], 160)
        self.assertEqual(mac["checkpack"], "macos-26-v1r3")
        self.assertTrue(mac["url"].startswith("https://dl.dod.cyber.mil/"))

    def test_guide_json_carries_filed_explanations(self):
        data = json.loads((self.out / "data" / "guides" / "macos-26.json").read_text())
        self.assertEqual(data["rules"], 160)
        self.assertEqual(data["annotated"], 160)
        first = data["items"][0]
        self.assertTrue(first["summary"])
        self.assertIn(first["triage"],
                      {"quick-win", "config-profile", "needs-judgment", "risky-change"})

    def test_windows_guide_matches_the_shipped_pack(self):
        data = json.loads((self.out / "data" / "guides" / "windows-11.json").read_text())
        self.assertEqual(data["rules"], 257)
        self.assertGreater(data["annotated"], 200)

    def test_scanner_src_zip_is_stored_and_has_the_launchers(self):
        archive = self.out / "packages" / "scanner-src.zip"
        self.assertTrue(archive.is_file())
        with zipfile.ZipFile(archive) as zf:
            names = set(zf.namelist())
            self.assertIn("stigui/app.html", names)
            self.assertIn("Start.command", names)
            self.assertIn("Start.bat", names)
            self.assertIn("stigscan/pdf.py", names)
            info = zf.getinfo("Start.command")
            self.assertEqual(info.compress_type, zipfile.ZIP_STORED)

    def test_official_urls_are_https(self):
        for g in scannable_guides():
            url = g.url(g.template.format(rel=g.release))
            self.assertEqual(urlparse(url).scheme, "https")


class TestWebsitePage(unittest.TestCase):
    def test_page_says_it_does_not_scan(self):
        html = (ROOT / "docs" / "index.html").read_text(encoding="utf-8")
        self.assertIn("does not scan your machine", html)
        self.assertIn("GitHub Pages", html)
        self.assertIn("himanshusaxenagithub.github.io/stig-ai-pipeline", html)

    def test_site_js_builds_a_selection_not_a_remote_scan(self):
        js = (ROOT / "docs" / "site.js").read_text(encoding="utf-8")
        self.assertIn("selection_format", js)
        self.assertIn("unreviewed", js)
        self.assertIn("pack.checks", js)
        self.assertNotIn("/api/scan", js)


if __name__ == "__main__":
    unittest.main()
