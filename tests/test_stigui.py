"""stig-ui: the server refuses anything it should refuse, and the
explanation lookup finds a filed set whether it is handed the zip or the
XCCDF inside it."""

import json
import time
import unittest
import zipfile
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import mock

from stigprep.explain import _candidate_names, load_annotations
import stigui.__main__ as ui
from stigui.__main__ import ROOT, Handler, TOKEN, shipped_packs
from stigscan import platforms


class TestAnnotationLookup(unittest.TestCase):
    def test_zip_offers_its_xccdf_member_name(self):
        with TemporaryDirectory() as tmp:
            src = Path(tmp) / "U_MS_Windows_11_V2R9_STIG.zip"
            with zipfile.ZipFile(src, "w") as zf:
                zf.writestr("U_MS_Windows_11_V2R9_Manual_STIG/"
                            "U_MS_Windows_11_STIG_V2R9_Manual-xccdf.xml", "<x/>")
            names = _candidate_names(src)
        self.assertIn("U_MS_Windows_11_V2R9_STIG.ai-cache.json", names)
        self.assertIn("U_MS_Windows_11_STIG_V2R9_Manual-xccdf.ai-cache.json", names)

    def test_plain_xml_offers_its_own_name(self):
        names = _candidate_names(Path("U_RHEL_9_STIG_V2R9_Manual-xccdf.xml"))
        self.assertEqual(names, ["U_RHEL_9_STIG_V2R9_Manual-xccdf.ai-cache.json"])

    def test_unknown_name_falls_back_to_overlapping_set(self):
        repo = Path(__file__).resolve().parents[1] / "annotations"
        filed = sorted(repo.glob("*.ai-cache.json"))
        if not filed:
            self.skipTest("no filed annotation sets in this checkout")
        raw = json.loads(filed[0].read_text(encoding="utf-8"))
        ids = {k.split(":", 1)[1] if ":" in k else k for k in raw}
        found = load_annotations(Path("no-such-guide.zip"), ids)
        self.assertTrue(set(found) & ids)


class TestServerGuards(unittest.TestCase):
    def _authorised(self, host, token):
        h = Handler.__new__(Handler)
        h.headers = {"Host": host, "X-Stig-Token": token}
        return Handler._authorised(h, {})

    def test_rejects_a_wrong_token(self):
        self.assertFalse(self._authorised("127.0.0.1", "not-the-token"))

    def test_rejects_a_non_loopback_host_header(self):
        self.assertFalse(self._authorised("192.168.1.10", TOKEN))

    def test_accepts_loopback_with_the_token(self):
        self.assertTrue(self._authorised("127.0.0.1", TOKEN))
        self.assertTrue(self._authorised("localhost", TOKEN))


class TestShippedPacks(unittest.TestCase):
    def test_only_returns_packs_for_the_platform_asked_for(self):
        for name in platforms.NAMES:
            for pack in shipped_packs(name):
                data = json.loads(Path(pack["path"]).read_text(encoding="utf-8"))
                self.assertEqual(data.get("platform"), name)

    def test_every_shipped_pack_declares_a_platform(self):
        """A pack with no platform is silently invisible in the UI. That is
        how the macOS pack went missing from the Checks screen on a Mac."""
        packs = sorted((ROOT / "checkpacks").glob("*.json"))
        self.assertTrue(packs, "no check packs are shipped")
        for path in packs:
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertIn(data.get("platform"), platforms.NAMES,
                          f"{path.name} declares no usable platform")

    def test_both_desktop_platforms_have_a_pack(self):
        for name in ("macos", "windows"):
            self.assertTrue(shipped_packs(name),
                            f"nothing would appear in the Checks list on {name}")


class TestAppMode(unittest.TestCase):
    """The double-click program: files in the user's folder, one instance,
    a Quit that really stops it, and a marker that does not outlive it."""

    def _start(self, workdir, port):
        import threading
        done = {}
        def run():
            done["code"] = ui.main(["--app", "--no-browser", "--workdir", workdir,
                                    "--port", str(port), "--idle-minutes", "0"])
        th = threading.Thread(target=run, daemon=True)
        th.start()
        for _ in range(100):
            if (Path(workdir) / ui.RUNNING_FILE).exists():
                break
            time.sleep(0.05)
        return th, done

    def _api(self, port, path, method="GET"):
        import urllib.request
        req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", method=method,
                                     headers={"X-Stig-Token": TOKEN}, data=b"{}" if method == "POST" else None)
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read())

    def test_data_dir_is_per_user_on_every_platform(self):
        for plat, needle in (("darwin", "Application Support"), ("win32", "STIG Checker"),
                             ("linux", "stig-checker")):
            with mock.patch.object(ui.sys, "platform", plat):
                self.assertIn(needle, str(ui.app_data_dir()))

    def test_no_marker_means_not_running(self):
        with TemporaryDirectory() as tmp:
            self.assertIsNone(ui._already_running(Path(tmp)))
            (Path(tmp) / ui.RUNNING_FILE).write_text('{"port": 1, "token": "x"}')
            self.assertIsNone(ui._already_running(Path(tmp)), "a dead port must read as not running")

    def test_start_reuse_and_quit(self):
        with TemporaryDirectory() as tmp:
            port = ui._free_port()
            th, done = self._start(tmp, port)
            self.assertTrue((Path(tmp) / ui.RUNNING_FILE).exists())
            state = self._api(port, "/api/state")
            self.assertTrue(state["app"])
            self.assertEqual(state["files_dir"], str(Path(tmp).resolve() / "out"))
            self.assertTrue(self._api(port, "/api/ping", "POST")["ok"])

            # a second double-click hands over to the first instance
            opened = []
            with mock.patch.object(ui.webbrowser, "open", opened.append):
                code = ui.main(["--app", "--workdir", tmp])
            self.assertEqual(code, 0)
            self.assertEqual(opened, [f"http://127.0.0.1:{port}/?t={TOKEN}"])

            self.assertTrue(self._api(port, "/api/quit", "POST")["ok"])
            th.join(timeout=10)
            self.assertFalse(th.is_alive(), "Quit must stop the server")
            self.assertEqual(done.get("code"), 0)
            self.assertFalse((Path(tmp) / ui.RUNNING_FILE).exists(), "marker must not outlive the server")
            self.assertIn("stopped", (Path(tmp) / "stig-checker.log").read_text())


class TestLiveScanProgress(unittest.TestCase):
    """Windows hides the PowerShell window, so the page is the only place a
    person can see that a scan is moving. Progress has to leave the server
    after each check, not as one blob when everything is finished."""

    def test_page_consumes_an_event_stream(self):
        html = (Path(ui.__file__).resolve().parent / "app.html").read_text(encoding="utf-8")
        self.assertIn("text/event-stream", html)
        self.assertIn("readScanStream", html)
        self.assertIn("handleScanEvent", html)
        self.assertNotIn("running…", html)

    def _tiny_pack(self, folder: Path):
        from stigscan.pack import Check, CheckPack
        pack = CheckPack(
            pack_id="live-test",
            platform=platforms.detect(),
            checks=[
                Check(stig_id="TST-0001", title="first", mode="shell",
                      command="/bin/echo 1", comparator="equals", expected="1"),
                Check(stig_id="TST-0002", title="second", mode="shell",
                      command="/bin/echo 1", comparator="equals", expected="1"),
            ],
        )
        for c in pack.checks:
            c.approve("tester", "t")
        path = folder / "live-test.json"
        pack.save(path)
        return path

    def test_scan_stream_reaches_the_client_before_the_scan_finishes(self):
        import http.client
        from stigscan.runner import RunResult

        class SlowRunner:
            def __init__(self, *a, **k):
                pass
            def run(self, stig_id, command):
                time.sleep(0.4)
                return RunResult("1\n", "", 0, "live")

        with TemporaryDirectory() as tmp:
            pack_path = self._tiny_pack(Path(tmp))
            port = ui._free_port()
            with mock.patch.object(ui, "ShellRunner", SlowRunner):
                th, done = TestAppMode()._start(tmp, port)
                try:
                    import urllib.request
                    req = urllib.request.Request(
                        f"http://127.0.0.1:{port}/api/pack/load", method="POST",
                        headers={"X-Stig-Token": TOKEN, "Content-Type": "application/json",
                                 "Host": "127.0.0.1"},
                        data=json.dumps({"path": str(pack_path)}).encode())
                    with urllib.request.urlopen(req, timeout=5) as r:
                        self.assertTrue(json.loads(r.read())["loaded"])

                    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
                    t0 = time.time()
                    conn.request(
                        "POST", "/api/scan", body=b"{}",
                        headers={"X-Stig-Token": TOKEN, "Content-Type": "application/json",
                                 "Host": "127.0.0.1", "Accept": "text/event-stream"})
                    resp = conn.getresponse()
                    self.assertEqual(resp.status, 200)
                    self.assertIn("event-stream", resp.getheader("Content-Type"))

                    got = b""
                    while b'"phase": "check"' not in got:
                        chunk = resp.read(32)
                        self.assertTrue(chunk, "stream closed before any progress arrived")
                        got += chunk
                    elapsed = time.time() - t0
                    self.assertLess(
                        elapsed, 0.25,
                        f"first check event took {elapsed:.2f}s — the scan is buffering")
                    self.assertNotIn(b'"phase": "done"', got)
                    while True:
                        more = resp.read(1024)
                        if not more:
                            break
                        got += more
                    self.assertIn(b'"phase": "done"', got)
                    conn.close()
                finally:
                    try:
                        TestAppMode()._api(port, "/api/quit", "POST")
                    except Exception:
                        pass
                    th.join(timeout=10)


if __name__ == "__main__":
    unittest.main()
