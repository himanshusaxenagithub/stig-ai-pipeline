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

    def test_winrm_service_explanation_does_not_invent_an_ao_exception(self):
        data = json.loads((self.out / "data" / "guides" / "windows-11.json").read_text())
        row = next(i for i in data["items"] if i["stig_id"] == "WN11-CC-000345")
        summary = row["summary"]
        self.assertIn("WinRM", summary)
        self.assertIn("Basic", summary)
        self.assertNotIn("Authorizing Official", summary)
        self.assertNotIn("exception", summary.lower())

    def test_scanner_src_zip_is_stored_and_has_the_launchers(self):
        archive = self.out / "packages" / "scanner-src.zip"
        self.assertTrue(archive.is_file())
        with zipfile.ZipFile(archive) as zf:
            names = set(zf.namelist())
            self.assertIn("stigui/app.html", names)
            self.assertIn("Start.command", names)
            self.assertIn("Start.bat", names)
            self.assertIn("stigscan/pdf.py", names)
            self.assertIn("stigassess/__main__.py", names)
            self.assertIn("stigharden/__main__.py", names)
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
        self.assertIn('href="demo.html"', html)
        self.assertIn("https://hsaxena.com", html)
        self.assertIn("Essays on my site", html)
        self.assertNotIn('href="articles/"', html)
        self.assertNotIn("Ten short essays", html)
        self.assertIn("Defense Information Systems Agency", html)
        self.assertNotIn("Pentagon publishes", html)
        self.assertNotIn("the Pentagon publishes", html.lower())

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
        import xml.etree.ElementTree as ET
        for name in ("stig-idea.svg", "process-flow.svg"):
            ET.parse(ROOT / "docs" / "img" / name)
        landing = html.split('id="s-landing"', 1)[1].split('id="s-rules"', 1)[0]
        self.assertIn("Technical notes", landing)
        self.assertLess(landing.find("<details"), landing.find("dl.dod.cyber.mil"))
        self.assertNotIn("<b>Local vs hosted.</b>", html)
        hero = landing.split('id="os-pick"', 1)[0]
        self.assertNotIn("dl.dod.cyber.mil", hero)
        self.assertNotIn("CORS", hero)
        self.assertNotIn("SHA-256", hero)
        self.assertNotIn("Pentagon", html)
        self.assertNotIn("Most people never", html)
        self.assertNotIn("1. Hundreds of settings", html)
        self.assertNotIn("How it works, start to finish", html)
        self.assertEqual(landing.count("img/stig-idea.svg"), 1)
        self.assertEqual(landing.count("Hundreds of settings"), 0)
        self.assertIn(
            "The US Department of Defense publishes free STIG checklists.", html)
        self.assertIn(
            "This site explains them and helps you check your PC.", html)
        self.assertNotIn("Pentagon", html)
        self.assertNotIn("Most people never apply them", html)
        self.assertNotIn("among the most thorough", html)

    def test_landing_has_a_beginner_demo(self):
        html = (ROOT / "docs" / "index.html").read_text(encoding="utf-8")
        landing = html.split('id="s-landing"', 1)[1].split('id="s-rules"', 1)[0]
        self.assertIn('id="demo"', landing)
        self.assertIn("Demo — try a simple first scan", landing)
        self.assertIn("Try a simple first scan", landing)
        self.assertIn("Department of Defense", landing)
        self.assertIn("configuration gaps", landing)
        self.assertIn("CAT I only", landing)
        self.assertIn("data-demo=\"cati\"", landing)
        self.assertIn('data-os="macos"', landing)
        self.assertIn('data-os="windows"', landing)
        demo = landing.split('id="demo"', 1)[1].split('id="os-pick"', 1)[0]
        self.assertIn("find", demo.lower())
        self.assertIn("PDF", demo)
        self.assertIn("fix", demo.lower())
        self.assertNotIn("Pentagon", demo)
        self.assertNotIn("most people never", demo.lower())
        self.assertNotIn("vulnerabilit", demo.lower())
        self.assertNotIn("exploit", demo.lower())
        self.assertNotIn("dl.dod.cyber.mil", demo)
        self.assertNotIn("CORS", demo)
        self.assertNotIn("may come later", html)
        self.assertIn("draft", demo.lower())
        self.assertIn("Select CAT I for demo", html)
        self.assertIn('id="sel-cati-demo"', html)
        self.assertIn('id="demo-rules-banner"', html)

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

    def test_demo_path_filters_cat_i_and_does_not_auto_download(self):
        js = (ROOT / "docs" / "site.js").read_text(encoding="utf-8")
        self.assertIn('dataset.demo === "cati"', js)
        self.assertIn('resetRuleFilters(demoMode)', js)
        self.assertIn('value = forDemo ? "high" : ""', js)
        self.assertIn("sel-cati-demo", js)
        self.assertIn('severity === "high"', js)
        choose = js.split("async function chooseOS", 1)[1].split(
            "function renderGuideMeta", 1)[0]
        self.assertNotIn("downloadScanner", choose)
        self.assertNotIn("go-build", choose)
        self.assertNotIn("a.download", choose)
        self.assertIn("selected = new Set();", choose)

    def test_scanner_src_fetch_is_cache_busted(self):
        js = (ROOT / "docs" / "site.js").read_text(encoding="utf-8")
        self.assertIn("payloadUrl(\"packages/scanner-src.zip\")", js)
        self.assertIn("catalog.payload", js)
        self.assertIn('cache: "no-store"', js)
        html = (ROOT / "docs" / "index.html").read_text(encoding="utf-8")
        self.assertIn("Delete the previous unzipped scanner folder", html)
        self.assertIn("site.js?v=", html)


def _visible_words(html: str) -> list[str]:
    import re
    text = re.sub(r"<script\b.*?</script>", " ", html, flags=re.S | re.I)
    text = re.sub(r"<style\b.*?</style>", " ", text, flags=re.S | re.I)
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"&[a-zA-Z]+;", " ", text)
    return re.findall(r"[A-Za-z0-9']+", text)


DEMO_SVGS = (
    "demo-pick-os.svg",
    "demo-select-cati.svg",
    "demo-download.svg",
    "demo-approve.svg",
    "demo-results.svg",
)


class TestDemoPage(unittest.TestCase):
    def test_demo_page_is_a_labeled_example_not_a_live_scan(self):
        html = (ROOT / "docs" / "demo.html").read_text(encoding="utf-8")
        self.assertIn("Example run", html)
        self.assertIn("Sample data", html)
        self.assertIn("does not scan", html.lower())
        self.assertIn("Cedar Ridge Family Clinic", html)
        self.assertIn("Jordan Hale", html)
        self.assertIn("remaining risk", html.lower())
        self.assertIn("CAT I", html)
        self.assertIn("Himanshu Saxena", html)
        self.assertIn("https://stig.hsaxena.com", html)
        self.assertIn("Defense Information Systems Agency", html)
        self.assertNotIn("Pentagon publishes", html)
        self.assertNotIn('href="articles/"', html)
        self.assertTrue((ROOT / "docs" / "pages.css").is_file())
        for name in DEMO_SVGS:
            self.assertIn(f"img/{name}", html)
            self.assertTrue((ROOT / "docs" / "img" / name).is_file())
        import xml.etree.ElementTree as ET
        for name in DEMO_SVGS:
            ET.parse(ROOT / "docs" / "img" / name)
        words = _visible_words(html)
        self.assertGreaterEqual(len(words), 400)
        self.assertNotIn("Planned later modules", html)
        self.assertNotIn("This first module only looks", html)
        self.assertIn("stig-assess", html)
        self.assertIn("stig-harden", html)
        self.assertIn("untrusted", html)
        self.assertIn("include-unreviewed", html)
        self.assertIn("dry-run", html)

    def test_product_site_does_not_host_the_essay_library(self):
        articles = ROOT / "docs" / "articles"
        self.assertFalse(articles.exists(), "essays belong on hsaxena.com, not this Pages site")
        html = (ROOT / "docs" / "index.html").read_text(encoding="utf-8")
        self.assertIn('href="https://hsaxena.com"', html)
        self.assertEqual(html.count("Ten short essays"), 0)
        self.assertEqual(html.count('href="articles/"'), 0)
        # no page on this site may link to a folder that does not exist
        for page in (ROOT / "docs").glob("*.html"):
            self.assertNotIn('href="articles/"', page.read_text(encoding="utf-8"), page.name)


class TestEvidenceAndTransparency(unittest.TestCase):
    def test_landing_has_a_subtle_reviewer_link(self):
        html = (ROOT / "docs" / "index.html").read_text(encoding="utf-8")
        self.assertIn("For reviewers / transparency", html)
        self.assertIn('href="evidence.html"', html)
        footer = html.split("<footer>", 1)[1]
        self.assertIn("For reviewers / transparency", footer)
        self.assertNotIn("EB-2", html)
        self.assertNotIn("NIW", html)
        self.assertNotIn("immigration", html.lower())
        self.assertNotIn("chatbot", html.lower())
        self.assertNotIn("chat bot", html.lower())

    def test_evidence_page_lists_checkable_facts(self):
        html = (ROOT / "docs" / "evidence.html").read_text(encoding="utf-8")
        self.assertTrue((ROOT / "docs" / "meta.css").is_file())
        self.assertIn('href="meta.css"', html)
        self.assertIn("Evidence", html)
        self.assertIn("2026-09-13", html)
        self.assertIn("MIT", html)
        self.assertIn("API key", html)
        self.assertIn("unreviewed", html)
        self.assertIn("approve", html.lower())
        self.assertIn("macOS", html)
        self.assertIn("Linux", html)
        self.assertIn("Windows", html)
        self.assertIn("https://stig.hsaxena.com", html)
        self.assertIn("https://github.com/himanshusaxenagithub/stig-ai-pipeline", html)
        self.assertIn("CAT I", html)
        self.assertIn("Select CAT I for demo", html)
        self.assertIn('href="index.html#demo"', html)
        self.assertIn('href="demo.html"', html)
        self.assertIn('href="https://hsaxena.com/writing"', html)  # essays live on the personal site
        self.assertIn('href="used.html"', html)
        self.assertIn("What we do not claim", html)
        self.assertIn("not", html.lower())
        self.assertIn("endorsed", html.lower())
        self.assertIn("stars", html.lower())
        self.assertIn("sample data", html.lower())
        self.assertIn("dry-run", html)
        self.assertIn("human-gated", html)
        self.assertIn("runs 306 tests", html)
        self.assertIn("1,440", html)
        self.assertIn("1,338", html)
        self.assertIn("include-unreviewed", html)
        self.assertIn("untrusted", html.lower())
        self.assertIn("stigprep", html)
        self.assertIn("stigassess", html)
        self.assertIn("stigharden", html)
        self.assertNotIn("Unapproved checks do not run. The program never approves a check for you.", html)
        self.assertNotIn("chatbot", html.lower())
        self.assertNotIn("EB-2", html)
        self.assertNotIn("NIW", html)
        self.assertNotIn("immigration", html.lower())
        self.assertNotIn("endorsed by the Department of Defense", html)
        self.assertNotIn("Pentagon publishes", html)

    def test_used_page_invites_notes_and_invents_none(self):
        html = (ROOT / "docs" / "used.html").read_text(encoding="utf-8")
        self.assertIn("Used this?", html)
        self.assertIn("mailto:1992.hsaxena@gmail.com", html)
        self.assertIn("1992.hsaxena@gmail.com", html)
        self.assertIn("issues/new?template=used-this.yml", html)
        self.assertIn("personal", html.lower())
        self.assertIn("No invented quotes", html)
        self.assertNotIn("chatbot", html.lower())
        self.assertNotIn("EB-2", html)
        self.assertNotIn("<blockquote", html)
        template = (ROOT / ".github" / "ISSUE_TEMPLATE" / "used-this.yml").read_text(
            encoding="utf-8")
        self.assertIn("Optional public note", template)
        self.assertIn("Prefer not to say", template)
        self.assertIn("personal data", template.lower())


CONTACT_PAGES = (
    "index.html",
    "demo.html",
    "evidence.html",
    "used.html",
    "reviews.html",
    "review-thanks.html",
)


class TestContactAndReviews(unittest.TestCase):
    def test_contact_email_is_on_related_docs_pages(self):
        for name in CONTACT_PAGES:
            html = (ROOT / "docs" / name).read_text(encoding="utf-8")
            self.assertIn("mailto:1992.hsaxena@gmail.com", html, name)
            self.assertIn("1992.hsaxena@gmail.com", html, name)
            self.assertIn("https://hsaxena.com", html, name)
            self.assertIn("https://hsaxena.com/writing", html, name)
            footer = html.split("<footer>", 1)[1]
            self.assertIn("Contact", footer, name)
            self.assertNotIn("co-authored-by", html.lower())
            self.assertNotIn("@stig.", html)

    def test_reviews_page_posts_to_formsubmit_and_hides_email(self):
        html = (ROOT / "docs" / "reviews.html").read_text(encoding="utf-8")
        self.assertIn("formsubmit.co/1992.hsaxena@gmail.com", html)
        self.assertIn('name="_subject"', html)
        self.assertIn("STIG site review submission", html)
        self.assertIn("review-thanks.html", html)
        self.assertIn('id="review-title"', html)
        self.assertIn('name="title"', html)
        self.assertIn('name="name"', html)
        self.assertIn('name="email"', html)
        self.assertIn('name="organization"', html)
        self.assertIn('name="review"', html)
        title_input = html.split('id="review-title"', 1)[1].split(">", 1)[0]
        self.assertIn("required", title_input)
        name_input = html.split('id="review-name"', 1)[1].split(">", 1)[0]
        self.assertIn("required", name_input)
        email_input = html.split('id="review-email"', 1)[1].split(">", 1)[0]
        self.assertIn("required", email_input)
        review_area = html.split('id="review-text"', 1)[1].split(">", 1)[0]
        self.assertIn("required", review_area)
        org_input = html.split('id="review-org"', 1)[1].split(">", 1)[0]
        self.assertNotIn("required", org_input)
        self.assertIn("required", html)
        self.assertIn(
            "Reviews appear only after manual approval. Email addresses are never published.",
            html)
        self.assertIn("The form emails the maintainer.", html)
        self.assertNotIn("docs/data/reviews.json", html)
        self.assertNotIn("data/reviews.json", html)
        self.assertNotIn("activation", html.lower())
        self.assertIn("used.html", html)
        self.assertNotIn("formspree", html.lower())
        self.assertNotIn("<blockquote", html)
        thanks = (ROOT / "docs" / "review-thanks.html").read_text(encoding="utf-8")
        self.assertIn(
            "Reviews appear only after manual approval. Email addresses are never published.",
            thanks)
        self.assertIn("approved by hand", thanks)
        self.assertIn("will not be published", thanks)
        self.assertNotIn("docs/data/reviews.json", thanks)
        self.assertNotIn("data/reviews.json", thanks)
        self.assertNotIn("activation email", thanks.lower())
        self.assertNotIn("form is not live", thanks.lower())
        self.assertIn("You do not need to activate anything", thanks)
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("Activate FormSubmit (first use, maintainer inbox only)", readme)
        self.assertIn("docs/data/reviews.json", readme)

    def test_approved_reviews_file_starts_empty_and_has_no_email(self):
        path = ROOT / "docs" / "data" / "reviews.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        reviews = data["reviews"] if isinstance(data, dict) else data
        self.assertEqual(reviews, [])
        self.assertNotIn("email", data if isinstance(data, dict) else {})
        for item in reviews:
            self.assertNotIn("email", item)
            self.assertFalse(any("@" in str(v) for v in item.values()))
        self.assertNotIn("@", path.read_text(encoding="utf-8"))
        js = (ROOT / "docs" / "site-chrome.js").read_text(encoding="utf-8")
        self.assertIn("data/reviews.json", js)
        self.assertIn('"email" in r', js)
        self.assertIn("No approved reviews yet", js)

    def test_approved_reviews_render_title_name_org_and_text(self):
        js = (ROOT / "docs" / "site-chrome.js").read_text(encoding="utf-8")
        fill = js.split("async function fillReviews", 1)[1]
        self.assertIn("review-title", fill)
        self.assertIn("escapeHtml(r.title)", fill)
        self.assertIn("escapeHtml(r.name)", fill)
        self.assertIn("r.organization", fill)
        self.assertIn("escapeHtml(r.text)", fill)
        self.assertIn("r.title && r.name && r.text", fill)
        self.assertIn('looksLikeEmail(r.title)', fill)
        sample = {
            "title": "Example headline",
            "name": "Example Name",
            "organization": "Example role",
            "text": "Fixture text for the public-render contract. Not a real review.",
        }
        self.assertNotIn("email", sample)
        self.assertTrue(sample["title"] and sample["name"] and sample["text"])
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn('"title": "Short headline from the form"', readme)
        self.assertIn("`title`, `name`, optional `organization`, and `text`", readme)

    def test_landing_links_reviews_and_keeps_used_this(self):
        html = (ROOT / "docs" / "index.html").read_text(encoding="utf-8")
        self.assertIn('href="reviews.html"', html)
        self.assertIn('href="used.html"', html)
        used = (ROOT / "docs" / "used.html").read_text(encoding="utf-8")
        self.assertIn("No invented quotes", used)
        self.assertIn("reviews.html", used)
        self.assertIn("mailto:1992.hsaxena@gmail.com", used)
        self.assertIn("issues/new?template=used-this.yml", used)


class TestGoatCounter(unittest.TestCase):
    def test_site_config_has_goatcounter_code(self):
        js = (ROOT / "docs" / "site-config.js").read_text(encoding="utf-8")
        self.assertIn('goatcounterCode: "stig-hsaxena"', js)
        self.assertNotIn("YOUR_GOATCOUNTER_CODE", js)
        self.assertIn("1992.hsaxena@gmail.com", js)
        self.assertNotIn("countapi", js.lower())

    def test_chrome_installs_goatcounter_and_fetches_public_totals(self):
        js = (ROOT / "docs" / "site-chrome.js").read_text(encoding="utf-8")
        self.assertIn("gc.zgo.at/count.js", js)
        self.assertIn("data-goatcounter", js)
        self.assertIn("goatcounter.com/count", js)
        self.assertIn("/counter/TOTAL.html", js)
        self.assertIn("gcvc-views", js)
        self.assertIn("parseGcvcViews", js)
        self.assertIn("/counter/TOTAL.json", js)
        self.assertIn("/reviews.html", js)
        self.assertIn("/demo.html", js)
        self.assertIn("n > 0", js)
        self.assertIn("YOUR_GOATCOUNTER_CODE", js)
        self.assertIn("resp.status === 404", js)
        order = js.split("async function publicGoatTotal", 1)[1]
        self.assertLess(order.find("totalFromTotalJson"), order.find("totalFromKnownPaths"))
        self.assertLess(order.find("totalFromKnownPaths"), order.find("totalFromWidgetHtml"))
        fill = js.split("async function fillSiteActivity", 1)[1]
        self.assertIn("got.n > 0", fill)
        self.assertIn("visitorsEl.textContent = formatCount(got.n)", fill)
        self.assertNotIn("countapi", js.lower())
        self.assertNotIn("api.countapi", js.lower())
        snippet = '<span id="gcvc-views">13</span>'
        import re
        match = re.search(r'id=["\']gcvc-views["\'][^>]*>([^<]*)', snippet)
        self.assertEqual(match.group(1).strip(), "13")

    def test_landing_shows_one_visitor_total(self):
        html = (ROOT / "docs" / "index.html").read_text(encoding="utf-8")
        landing = html.split('id="site-activity"', 1)[1].split('id="tech-notes"', 1)[0]
        self.assertIn('data-stat="visitors"', landing)
        self.assertIn("Site visitors", landing)
        self.assertIn("People who opened this site (GoatCounter).", landing)
        self.assertIn("not a count of people who downloaded or ran the scanner", landing)
        self.assertIn("https://stig-hsaxena.goatcounter.com", landing)
        self.assertNotIn("data-stat=\"opens\"", landing)
        self.assertNotIn("data-stat=\"users\"", landing)
        self.assertNotIn("same total, not a second metric", landing)
        self.assertNotIn("Opens / pageviews", landing)
        self.assertNotIn("Users / unique visitors", landing)
        self.assertNotIn("Visitors/Users", landing)

    def test_docs_pages_include_the_shared_goatcounter_config(self):
        for name in CONTACT_PAGES:
            html = (ROOT / "docs" / name).read_text(encoding="utf-8")
            self.assertIn("site-config.js", html, name)
            self.assertIn("site-chrome.js", html, name)

    def test_landing_has_honest_site_activity_section(self):
        html = (ROOT / "docs" / "index.html").read_text(encoding="utf-8")
        self.assertIn('id="site-activity"', html)
        self.assertIn("Site activity", html)
        self.assertIn("data-stat=\"visitors\"", html)
        self.assertIn("Site visitors", html)
        self.assertIn("Not Department of Defense adoption", html)
        self.assertIn("—", html)
        self.assertNotIn("countapi", html.lower())


class TestBrowserZip(unittest.TestCase):
    """docs/zip.js builds the download in the visitor's browser. Run it for
    real under Node and check the archive it makes with Python's zipfile."""

    def _zip_from_browser(self) -> bytes:
        import shutil, subprocess, tempfile
        node = shutil.which("node")
        if not node:
            self.skipTest("node is not installed here")
        script = (ROOT / "docs" / "zip.js").read_text(encoding="utf-8") + """
const files = {"STIG Checker.command": "#!/bin/bash\\necho hi\\n", "Start.bat": "@echo off\\n",
               "selection.json": "{}\\n"};
const blob = zipStore(files, "STIG-Scanner-macOS/");
blob.arrayBuffer().then(b => process.stdout.write(Buffer.from(b)));
"""
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as fh:
            fh.write(script)
        out = subprocess.run([node, fh.name], capture_output=True, check=True)
        return out.stdout

    def test_command_files_keep_their_execute_bit(self):
        import io, zipfile
        data = self._zip_from_browser()
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            by_name = {i.filename: i for i in zf.infolist()}
            cmd = by_name["STIG-Scanner-macOS/STIG Checker.command"]
            bat = by_name["STIG-Scanner-macOS/Start.bat"]
            # host OS byte 3 = Unix; without it unpackers ignore the mode and
            # macOS refuses to run the .command ("you do not have permission").
            self.assertEqual(cmd.create_system, 3)
            self.assertEqual((cmd.external_attr >> 16) & 0o777, 0o755)
            self.assertEqual((bat.external_attr >> 16) & 0o777, 0o644)
            self.assertEqual(zf.read(cmd).decode(), "#!/bin/bash\necho hi\n")
            self.assertIsNone(zf.testzip())


class TestShippedScope(unittest.TestCase):
    """Two scoped rule counts, four shipped modules, no invented WinRM exception."""

    def test_annotations_total_1440_across_seven_stigs(self):
        from stigprep.explain import _entries
        files = sorted((ROOT / "annotations").glob("*.ai-cache.json"))
        self.assertEqual(len(files), 7)
        total = 0
        for path in files:
            n = len(_entries(json.loads(path.read_text(encoding="utf-8"))))
            total += n
        self.assertEqual(total, 1440)

    def test_checkpacks_total_1338_across_five_platforms(self):
        from stigscan.pack import CheckPack
        files = sorted((ROOT / "checkpacks").glob("*.json"))
        self.assertEqual(len(files), 5)
        total = 0
        for path in files:
            total += len(CheckPack.load(path).checks)
        self.assertEqual(total, 1338)

    def test_readme_and_changelog_state_both_scoped_counts(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
        for text, name in ((readme, "README.md"), (changelog, "CHANGELOG.md")):
            self.assertIn("1,440", text, name)
            self.assertIn("1,338", text, name)
        self.assertIn("All four modules ship", readme)
        self.assertIn("stig-assess", readme)
        self.assertIn("stig-harden", readme)
        self.assertIn("--include-unreviewed", readme)
        self.assertIn("untrusted", readme)
        self.assertNotIn("Planned later modules", readme)
        self.assertIn("WN11-CC-000345", changelog)
        self.assertIn("BitLocker", changelog)

    def test_filed_winrm_annotation_matches_disa_not_an_invented_exception(self):
        from stigprep.explain import _entries
        path = ROOT / "annotations" / "U_MS_Windows_11_STIG_V2R9_Manual-xccdf.ai-cache.json"
        entries = _entries(json.loads(path.read_text(encoding="utf-8")))
        summary = entries["WN11-CC-000345"]["summary"]
        self.assertIn("WinRM", summary)
        self.assertIn("Basic authentication", summary)
        self.assertNotIn("Authorizing Official", summary)
        self.assertNotIn("exception", summary.lower())
        published = json.loads(
            (ROOT / "docs" / "data" / "guides" / "windows-11.json").read_text(encoding="utf-8"))
        row = next(i for i in published["items"] if i["stig_id"] == "WN11-CC-000345")
        self.assertEqual(row["summary"], summary)


if __name__ == "__main__":
    unittest.main()
