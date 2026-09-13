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
        self.assertTrue(data.get("payload", {}).get("sha256"))
        self.assertEqual(data["payload"]["file"], "packages/scanner-src.zip")
        archive = self.out / "packages" / "scanner-src.zip"
        import hashlib
        self.assertEqual(data["payload"]["sha256"],
                         hashlib.sha256(archive.read_bytes()).hexdigest())

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
            vbs = zf.read("run-hidden.vbs").decode("utf-8")
            self.assertRegex(vbs, r"(?i)Dim\b.*\bargs\b")

    def test_official_urls_are_https(self):
        for g in scannable_guides():
            url = g.url(g.template.format(rel=g.release))
            self.assertEqual(urlparse(url).scheme, "https")


class TestWebsitePage(unittest.TestCase):
    def test_page_says_it_does_not_scan(self):
        html = (ROOT / "docs" / "index.html").read_text(encoding="utf-8")
        self.assertIn("does not scan your machine", html)
        self.assertIn("GitHub Pages", html)
        self.assertIn("https://stig.hsaxena.com", html)

    def test_landing_explains_stigs_before_hosting_caveats(self):
        html = (ROOT / "docs" / "index.html").read_text(encoding="utf-8")
        self.assertIn("What is a STIG?", html)
        self.assertIn("Security Technical Implementation Guide", html)
        self.assertIn("What this tool does", html)
        self.assertIn('id="os-pick"', html)
        self.assertIn('data-os="macos"', html)
        self.assertIn('data-os="windows"', html)
        self.assertIn("img/stig-idea.svg", html)
        self.assertIn("img/process-flow.svg", html)
        self.assertTrue((ROOT / "docs" / "img" / "stig-idea.svg").is_file())
        self.assertTrue((ROOT / "docs" / "img" / "process-flow.svg").is_file())
        landing = html.split('id="s-landing"', 1)[1].split('id="s-rules"', 1)[0]
        self.assertIn("Technical notes", landing)
        self.assertLess(landing.find("<details"), landing.find("dl.dod.cyber.mil"))
        self.assertNotIn("<b>Local vs hosted.</b>", html)
        hero = landing.split('id="os-pick"', 1)[0]
        self.assertNotIn("dl.dod.cyber.mil", hero)
        self.assertNotIn("CORS", hero)
        self.assertNotIn("SHA-256", hero)

    def test_site_js_builds_a_selection_not_a_remote_scan(self):
        js = (ROOT / "docs" / "site.js").read_text(encoding="utf-8")
        self.assertIn("selection_format", js)
        self.assertIn("unreviewed", js)
        self.assertIn("pack.checks", js)
        self.assertNotIn("/api/scan", js)

    def test_site_js_does_not_dump_catalog_note_on_the_hero(self):
        js = (ROOT / "docs" / "site.js").read_text(encoding="utf-8")
        self.assertNotIn('$("#fetch-note").textContent = catalog.note', js)
        self.assertIn("tech-catalog-note", js)
        self.assertIn("Guides are ready", js)

    def test_rules_page_starts_with_no_stigs_selected(self):
        js = (ROOT / "docs" / "site.js").read_text(encoding="utf-8")
        self.assertIn("selected = new Set();", js)
        self.assertNotIn(
            "selected = new Set(guide.items.filter(r => r.mode === \"shell\")",
            js)
        self.assertIn('alert("Select at least one rule to put in the scanner.")', js)

    def test_scanner_src_fetch_is_cache_busted(self):
        js = (ROOT / "docs" / "site.js").read_text(encoding="utf-8")
        self.assertIn("payloadUrl(\"packages/scanner-src.zip\")", js)
        self.assertIn("catalog.payload", js)
        self.assertIn('cache: "no-store"', js)
        html = (ROOT / "docs" / "index.html").read_text(encoding="utf-8")
        self.assertIn("Delete the previous unzipped scanner folder", html)
        self.assertIn("site.js?v=", html)


if __name__ == "__main__":
    unittest.main()
