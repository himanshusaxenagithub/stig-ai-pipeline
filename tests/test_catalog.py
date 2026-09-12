"""The fetcher: what it will accept, what it refuses, and what it says when
the network will not let it through. No test here touches the network."""

import io
import unittest
import urllib.error
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from stigprep import catalog


def _zip_with(rules: int) -> bytes:
    body = "".join(f'<Rule id="SV-{i}" severity="high"></Rule>' for i in range(rules))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("U_Test_V1R1_Manual_STIG/U_Test_STIG_V1R1_Manual-xccdf.xml",
                    f"<Benchmark>{body}</Benchmark>")
    return buf.getvalue()


class TestCatalogue(unittest.TestCase):
    def test_every_entry_has_a_distinct_key_and_a_known_platform(self):
        keys = [g.key for g in catalog.CATALOG]
        self.assertEqual(len(keys), len(set(keys)))
        for g in catalog.CATALOG:
            self.assertIn(g.platform, {"macos", "windows", "linux", "database"})
            self.assertIn("{rel}", g.template)

    def test_the_validated_release_is_tried_first(self):
        g = catalog.BY_KEY["windows-11"]
        releases = [rel for rel, _ in g.candidates()]
        self.assertEqual(releases[0], g.release)
        self.assertGreater(max(releases), g.release)
        self.assertEqual(len(releases), len(set(releases)))

    def test_for_platform_filters(self):
        for g in catalog.for_platform("windows"):
            self.assertEqual(g.platform, "windows")


class TestFetchGuards(unittest.TestCase):
    def test_unknown_guide_lists_the_known_ones(self):
        with self.assertRaises(catalog.FetchError) as e:
            catalog.fetch("not-a-guide")
        self.assertIn("windows-11", str(e.exception))

    def test_accepts_a_package_with_the_expected_rule_count(self):
        data = _zip_with(257)
        with TemporaryDirectory() as tmp, \
             mock.patch.object(catalog, "_get", return_value=data):
            path = catalog.fetch("windows-11", tmp, progress=lambda *_: None)
            self.assertTrue(Path(path).is_file())
            self.assertEqual(Path(path).read_bytes(), data)

    def test_refuses_a_package_with_the_wrong_rule_count(self):
        with TemporaryDirectory() as tmp, \
             mock.patch.object(catalog, "_get", return_value=_zip_with(12)):
            with self.assertRaises(catalog.FetchError) as e:
                catalog.fetch("windows-11", tmp, progress=lambda *_: None)
        self.assertIn("Refusing", str(e.exception))

    def test_refuses_an_archive_with_no_xccdf(self):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("readme.txt", "nothing to see")
        with TemporaryDirectory() as tmp, \
             mock.patch.object(catalog, "_get", return_value=buf.getvalue()):
            with self.assertRaises(catalog.FetchError) as e:
                catalog.fetch("windows-11", tmp, progress=lambda *_: None)
        self.assertIn("no XCCDF", str(e.exception))

    def test_refuses_a_package_that_does_not_match_a_pinned_digest(self):
        pinned = catalog.Guide("t", "Test", "windows", "U_T_V1R{rel}_STIG.zip",
                               release=1, rules=3, sha256="0" * 64, lookahead=0)
        with TemporaryDirectory() as tmp, \
             mock.patch.dict(catalog.BY_KEY, {"t": pinned}), \
             mock.patch.object(catalog, "_get", return_value=_zip_with(3)):
            with self.assertRaises(catalog.FetchError) as e:
                catalog.fetch("t", tmp, progress=lambda *_: None)
        self.assertIn("digest", str(e.exception))

    def test_a_blocked_network_names_the_page_to_use_instead(self):
        err = urllib.error.URLError("Tunnel connection failed: 403 Forbidden")
        with TemporaryDirectory() as tmp, \
             mock.patch.object(catalog, "_get", side_effect=err):
            with self.assertRaises(catalog.FetchError) as e:
                catalog.fetch("windows-11", tmp, progress=lambda *_: None)
        message = str(e.exception)
        self.assertIn(catalog.DOWNLOAD_PAGE, message)
        self.assertIn("by hand", message)

    def test_a_withdrawn_release_falls_through_to_another(self):
        data = _zip_with(257)
        calls = {"n": 0}

        def flaky(url, timeout=60):
            calls["n"] += 1
            if calls["n"] < 3:
                raise urllib.error.HTTPError(url, 404, "Not Found", None, None)
            return data

        with TemporaryDirectory() as tmp, mock.patch.object(catalog, "_get", flaky):
            path = catalog.fetch("windows-11", tmp, progress=lambda *_: None)
            self.assertTrue(Path(path).is_file())
        self.assertEqual(calls["n"], 3)


if __name__ == "__main__":
    unittest.main()


class TestAudienceSplit(unittest.TestCase):
    """The page is for a MacBook or a Windows PC. Servers, Linux and
    databases belong to the command line, and the page must not be able to
    reach for them."""

    def test_only_desktop_machines_are_offered_in_the_page(self):
        offered = {g.key for g in catalog.desktop_guides()}
        self.assertEqual(offered, {"macos-26", "macos-15", "windows-11"})

    def test_servers_and_databases_are_command_line_only(self):
        cli = {g.key for g in catalog.cli_only_guides()}
        self.assertIn("windows-server-2019", cli)
        self.assertIn("rhel-9", cli)
        self.assertIn("ubuntu-24.04", cli)
        self.assertIn("sql-server-2022", cli)
        self.assertFalse(cli & {g.key for g in catalog.desktop_guides()})

    def test_every_guide_is_in_exactly_one_of_the_two(self):
        both = len(catalog.desktop_guides()) + len(catalog.cli_only_guides())
        self.assertEqual(both, len(catalog.CATALOG))

    def test_the_command_line_still_offers_all_of_them(self):
        for g in catalog.CATALOG:
            self.assertIn(g.key, catalog.BY_KEY)

    def test_the_recommendation_for_a_desktop_is_a_desktop_guide(self):
        offered = {g.key for g in catalog.desktop_guides()}
        self.assertIn(catalog.recommended("macos"), offered)
        self.assertIn(catalog.recommended("windows"), offered)
