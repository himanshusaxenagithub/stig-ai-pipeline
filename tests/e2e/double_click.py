"""End-to-end test of the double-click path. Not run by `unittest discover`
(it needs Playwright and a Chromium, which are not project dependencies):

    pip install playwright && playwright install chromium
    python3 tests/e2e/double_click.py 5        # five runs of each flow

Two flows, each from a fresh unzip, through the real launcher, into a real
browser, and out through Quit:

  website     docs/ after build_site.py, served over HTTP as Pages serves it
              -> pick MacBook -> select CAT I -> download the zip the browser
              builds -> unzip -> STIG Checker.command -> page opens on the
              Checks tab with the selection -> approve under a name -> the
              platform guard visibly refuses a macOS pack on a non-Mac ->
              Show files -> a second double-click reuses the instance -> Quit
  github-zip  what Code -> Download ZIP hands out (git archive of the index)
              -> STIG Checker.command -> Guide tab -> open the Ubuntu pack ->
              approve eight checks -> scan -> coverage first -> PDF written ->
              POA&M and fix drafts -> Show files -> second click -> Quit

Runs on Linux and macOS. On macOS the platform-guard step will not trigger
for the macOS pack (it is the right platform) -- the assertion there is
platform-aware. Results land in tests/e2e/_runs/ (or $E2E_OUT).

v0.7.6 was the first release these ran against; they found the three
defects listed in CHANGELOG.md for that version.
"""
import http.server, json, os, re, shutil, subprocess, sys, threading, time, zipfile, functools
from pathlib import Path
from playwright.sync_api import sync_playwright

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
OUT = Path(os.environ.get("E2E_OUT", HERE / "_runs"))
RUNS = int(sys.argv[1]) if len(sys.argv) > 1 else 5
STUBS = OUT / "stubs"
SITE = OUT / "site"


def make_stubs():
    STUBS.mkdir(parents=True, exist_ok=True)
    (STUBS / "browser-stub").write_text('#!/bin/bash\necho "$1" >> "$HOME/opened.txt"\n')
    (STUBS / "osascript").write_text('#!/bin/bash\necho "$@" >> "$HOME/dialogs.txt"\n')
    (STUBS / "xdg-open").write_text('#!/bin/bash\necho "$1" >> "$HOME/xdg.txt"\n')
    for f in STUBS.iterdir():
        f.chmod(0o755)


def build_site() -> Path:
    if SITE.exists():
        shutil.rmtree(SITE)
    shutil.copytree(REPO / "docs", SITE)
    subprocess.run([sys.executable, "packaging/build_site.py", "--out", str(SITE)],
                   cwd=REPO, check=True, capture_output=True)
    assert (SITE / "packages" / "scanner-src.zip").is_file()
    return SITE


def serve(folder: Path):
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(folder))
    handler.log_message = lambda *a, **k: None
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/"


def wait_for(pred, timeout=60, what="condition"):
    t0 = time.time()
    while time.time() - t0 < timeout:
        v = pred()
        if v:
            return v
        time.sleep(0.2)
    raise AssertionError(f"timed out waiting for {what}")


def finish(pg, b, proc, launcher, env, home, opened, url, marker, launcher_log, stage, errors):
    pg.click("#show-files")
    wait_for(lambda: (home / "xdg.txt").exists(), 10, "Show files")
    assert (home / "xdg.txt").read_text().strip().endswith("/out")

    before = len(opened.read_text().splitlines())
    second = subprocess.run(["bash", str(launcher)], env=env, cwd="/", timeout=30,
                            capture_output=True, stdin=subprocess.DEVNULL)
    assert second.returncode == 0, (second.returncode, second.stdout[-300:], second.stderr[-300:])
    lines = opened.read_text().splitlines()
    assert len(lines) == before + 1 and lines[-1] == url, lines
    assert proc.poll() is None, "first instance died"
    stage("second double-click reused the instance")

    pg.click("#quit")
    pg.wait_for_selector("text=STIG Checker has stopped", timeout=10000)
    assert not errors, errors
    b.close()
    wait_for(lambda: proc.poll() is not None, 30, "process to exit")
    assert proc.returncode == 0, (proc.returncode, launcher_log.read_text()[-500:])
    assert not marker.exists(), "running.json survived Quit"
    assert not (home / "dialogs.txt").exists(), "an error dialog was shown: " + (home / "dialogs.txt").read_text()
    stage("quit")


def one_run(n: int, site_url: str, p) -> dict:
    res = {"run": n}
    T0 = time.time()
    def stage(s):
        print(f"  [run {n} +{time.time()-T0:5.1f}s] {s}", flush=True)
    work = OUT / f"site-run{n}"
    if work.exists():
        shutil.rmtree(work)
    home = work / "home"
    home.mkdir(parents=True)

    b = p.chromium.launch(**({"executable_path": os.environ["CHROMIUM"]} if os.environ.get("CHROMIUM") else {}))
    ctx = b.new_context(viewport={"width": 1280, "height": 900}, accept_downloads=True)
    pg = ctx.new_page()
    errors = []
    pg.on("pageerror", lambda e: errors.append(str(e)))

    # ---- the website ---------------------------------------------------
    pg.goto(site_url)
    pg.wait_for_selector("#os-pick button")
    res["site_title"] = pg.title()
    if n == 1:
        pg.screenshot(path=str(OUT / "site-1-landing.png"), full_page=True)
    stage("site loaded")
    pg.click('#os-pick button[data-os="macos"]:not([data-demo])')
    pg.wait_for_selector("#rules-table tbody tr", timeout=60000)
    total_rows = pg.locator("#rules-table tbody tr").count()
    res["site_rules_listed"] = total_rows
    stage(f"guide chosen, {total_rows} rules listed")
    pg.click("#sel-cati")
    wait_for(lambda: int(re.sub(r"\D", "", pg.locator("#rules-count").inner_text() or "0") or 0) > 0,
             10, "CAT I selection")
    res["site_selected_text"] = pg.locator("#rules-count").inner_text()
    if n == 1:
        pg.screenshot(path=str(OUT / "site-2-rules.png"))
    pg.click("#go-download")
    pg.wait_for_selector("#go-build", timeout=10000)
    with pg.expect_download(timeout=60000) as dl:
        pg.click("#go-build")
    zip_path = work / dl.value.suggested_filename
    dl.value.save_as(str(zip_path))
    res["zip"] = zip_path.name
    res["zip_bytes"] = zip_path.stat().st_size
    assert zip_path.name == "STIG-Scanner-macOS.zip", zip_path.name
    stage(f"downloaded {zip_path.name} ({zip_path.stat().st_size:,} bytes)")
    assert not errors, errors
    pg.close(); ctx.close(); b.close()

    # ---- unzip like Archive Utility ---------------------------------------
    subprocess.run(["unzip", "-q", str(zip_path), "-d", str(work)], check=True)
    folder = work / "STIG-Scanner-macOS"
    launcher = folder / "STIG Checker.command"
    assert launcher.is_file(), "STIG Checker.command missing from the zip"
    assert os.access(launcher, os.X_OK), "STIG Checker.command is not executable after unzip"
    assert os.access(folder / "Start.command", os.X_OK), "Start.command is not executable after unzip"
    assert (folder / "selection.json").is_file()
    sel = json.loads((folder / "selection.json").read_text())
    assert (folder / sel["pack_path"]).is_file(), "the filtered pack is not in the zip"
    res["selected_rules"] = len(sel["rule_ids"])
    stage(f"unzipped; {len(sel['rule_ids'])} rules in selection.json")

    # ---- the double-click --------------------------------------------------
    env = dict(os.environ, HOME=str(home), PATH=f"{STUBS}:{os.environ['PATH']}",
               BROWSER=f"{STUBS}/browser-stub %s", XDG_DATA_HOME=str(home / "data"))
    env.pop("PYTHONPATH", None)
    launcher_log = work / "launcher.log"
    proc = subprocess.Popen(["bash", str(launcher)], env=env, cwd="/",
                            stdout=launcher_log.open("w"), stderr=subprocess.STDOUT,
                            stdin=subprocess.DEVNULL)
    opened = home / "opened.txt"
    wait_for(lambda: opened.exists() and opened.read_text().strip(), 30, "browser to be asked to open")
    url = opened.read_text().strip().splitlines()[0]
    assert re.match(r"^http://127\.0\.0\.1:\d+/\?t=[\w-]+$", url), url
    marker = home / "data" / "stig-checker" / "running.json"
    assert marker.exists(), "running.json not written"
    stage("launched, browser asked to open")

    # ---- the local page ------------------------------------------------------
    b = p.chromium.launch(**({"executable_path": os.environ["CHROMIUM"]} if os.environ.get("CHROMIUM") else {}))
    pg = b.new_page(viewport={"width": 1280, "height": 900})
    errors = []
    pg.on("pageerror", lambda e: errors.append(str(e)))
    pg.goto(url)
    # with a website selection the page opens straight on the Checks tab,
    # with the banner that says so; nothing to click first
    pg.wait_for_selector("#from-site", state="visible", timeout=15000)
    assert pg.title() == "STIG Checker"
    assert pg.locator("#s-checks").is_visible(), "should open on the Checks tab"
    res["from_site_text"] = pg.locator("#from-site").inner_text()[:120]
    stage("page shows the website selection")
    if n == 1:
        pg.screenshot(path=str(OUT / "site-3-local-guide.png"))

    pg.click("#tab-checks")
    pg.wait_for_selector("#pack-out table tbody tr", timeout=30000)
    rows = pg.locator("#pack-out table tbody tr").count()
    assert rows == len(sel["rule_ids"]), (rows, len(sel["rule_ids"]))
    assert pg.locator(".chip.s-approved").count() == 0, "nothing may arrive pre-approved"
    res["unreviewed_on_arrival"] = pg.locator(".chip.s-unreviewed").count()
    pg.fill("#by", f"E2E site run {n}")
    pg.check("#all")
    pg.click("#go-approve")
    wait_for(lambda: pg.locator(".chip.s-approved").count() > 0, 20, "approvals")
    res["approved"] = pg.locator(".chip.s-approved").count()
    stage(f"approved {res['approved']} of {rows}")
    if n == 1:
        pg.screenshot(path=str(OUT / "site-4-checks.png"))

    # ---- scan: a macOS pack on a Linux box must be refused, visibly ---------
    pg.click("#tab-scan")
    pg.click("#go-scan")
    import platform as _plat
    if _plat.system() == "Darwin":
        pg.wait_for_selector("#scan-coverage", state="visible", timeout=300000)
        res["coverage"] = pg.locator("#scan-coverage").inner_text().split("\n")[0][:120]
        stage("scanned the macOS pack on a Mac")
    else:
        pg.wait_for_selector("#scan-out .err", timeout=30000)
        refusal = pg.locator("#scan-out .err").first.inner_text()
        assert "authored for macos" in refusal and "refusing" in refusal, refusal
        res["platform_guard"] = refusal[:100]
        stage("platform guard refused the macOS pack on this non-Mac, visibly")

    finish(pg, b, proc, launcher, env, home, opened, url, marker, launcher_log, stage, errors)
    res["result"] = "PASS"
    return res



def source_zip() -> Path:
    """What GitHub's Code -> Download ZIP hands out: the tracked files, nested
    in a <repo>-main/ folder, no execute bits (GitHub's zip keeps them, but
    assume the worst and rely on the .command's own bootstrapping)."""
    out = OUT / "stig-ai-pipeline-main.zip"
    # archive the index (what the next commit will contain), not HEAD, so
    # uncommitted fixes are exercised too
    subprocess.run(["git", "add", "-A"], cwd=REPO, check=True)
    tree = subprocess.run(["git", "write-tree"], cwd=REPO, check=True,
                          capture_output=True, text=True).stdout.strip()
    subprocess.run(["git", "archive", "--format=zip", "--prefix=stig-ai-pipeline-main/",
                    "-o", str(out), tree], cwd=REPO, check=True)
    return out


def github_zip_run(n: int, p) -> dict:
    res = {"run": n, "flow": "github-zip"}
    T0 = time.time()
    def stage(s):
        print(f"  [gh {n} +{time.time()-T0:5.1f}s] {s}", flush=True)
    work = OUT / f"gh-run{n}"
    if work.exists():
        shutil.rmtree(work)
    home = work / "home"
    home.mkdir(parents=True)
    subprocess.run(["unzip", "-q", str(source_zip()), "-d", str(work)], check=True)
    folder = work / "stig-ai-pipeline-main"
    launcher = folder / "STIG Checker.command"
    assert launcher.is_file() and os.access(launcher, os.X_OK), "launcher missing or not executable"
    assert (folder / "Double-click this.txt").is_file()
    stage("unzipped the GitHub source zip")

    env = dict(os.environ, HOME=str(home), PATH=f"{STUBS}:{os.environ['PATH']}",
               BROWSER=f"{STUBS}/browser-stub %s", XDG_DATA_HOME=str(home / "data"))
    env.pop("PYTHONPATH", None)
    launcher_log = work / "launcher.log"
    proc = subprocess.Popen(["bash", str(launcher)], env=env, cwd="/",
                            stdout=launcher_log.open("w"), stderr=subprocess.STDOUT,
                            stdin=subprocess.DEVNULL)
    opened = home / "opened.txt"
    wait_for(lambda: opened.exists() and opened.read_text().strip(), 30, "browser to be asked to open")
    url = opened.read_text().strip().splitlines()[0]
    marker = home / "data" / "stig-checker" / "running.json"
    assert marker.exists()
    stage("launched")

    b = p.chromium.launch(**({"executable_path": os.environ["CHROMIUM"]} if os.environ.get("CHROMIUM") else {}))
    pg = b.new_page(viewport={"width": 1280, "height": 900})
    errors = []
    pg.on("pageerror", lambda e: errors.append(str(e)))
    pg.goto(url)
    pg.wait_for_selector("#platform", state="visible")
    assert pg.locator("#from-site").is_hidden(), "no website selection here"
    assert pg.locator("#catalog button.pick").count() == 2
    stage("page loaded on the Guide tab")

    pg.click("#tab-checks")
    opts = pg.locator("#pack-pick option")
    wait_for(lambda: "ubuntu" in pg.locator("#pack-pick").inner_text(), 10, "shipped packs")
    pg.select_option("#pack-pick", index=[i for i in range(opts.count())
                                            if "ubuntu" in opts.nth(i).inner_text()][0])
    pg.click("#go-load")
    wait_for(lambda: pg.locator("#pack-out table tbody tr").count() > 100, 30, "ubuntu pack")
    assert pg.locator(".chip.s-approved").count() == 0, "shipped packs must arrive unreviewed"
    pg.fill("#by", f"E2E github run {n}")
    picked = 0
    rows = pg.locator("#pack-out table tbody tr")
    for i in range(rows.count()):
        row = rows.nth(i)
        if row.locator(".warn").count() == 0 and row.locator("pre").count() > 0 \
                and row.locator(".pickme:not(:disabled)").count() == 1:
            row.locator(".pickme").check()
            picked += 1
            if picked == 8:
                break
    pg.click("#go-approve")
    wait_for(lambda: pg.locator(".chip.s-approved").count() >= 8, 20, "approvals")
    res["approved"] = pg.locator(".chip.s-approved").count()
    stage("approved 8 ubuntu checks under a name")

    pg.click("#tab-scan")
    pg.click("#go-scan")
    pg.wait_for_selector("#scan-coverage", state="visible", timeout=300000)
    cov = pg.locator("#scan-coverage").inner_text()
    assert "evaluated" in cov.lower(), cov
    res["coverage"] = cov.split("\n")[0][:120]
    wait_for(lambda: pg.locator("#scan-files").is_visible(), 20, "report file list")
    stage("scanned; coverage stated first")
    if n == 1:
        pg.screenshot(path=str(OUT / "gh-5-scan.png"), full_page=True)
    files_dir = home / "data" / "stig-checker" / "out"
    pdfs = list(files_dir.glob("*.pdf"))
    assert pdfs, f"no PDF in {files_dir}: {list(files_dir.iterdir())}"
    assert pdfs[0].read_bytes()[:5] == b"%PDF-"
    res["pdf"] = pdfs[0].name
    res["pdf_bytes"] = pdfs[0].stat().st_size
    jsons = list(files_dir.glob("*scan*.json")) or list(files_dir.glob("*.json"))
    assert jsons, "no JSON report"

    pg.click("#draft-poam")
    wait_for(lambda: pg.locator("#draft-out").inner_text().strip() != "", 60, "POA&M draft")
    res["poam_draft"] = pg.locator("#draft-out").inner_text()[:100]
    stage("POA&M drafted")
    pg.click("#draft-fixes")
    wait_for(lambda: "fix" in pg.locator("#draft-out").inner_text().lower()
             or "remediation" in pg.locator("#draft-out").inner_text().lower()
             or "harden" in pg.locator("#draft-out").inner_text().lower(), 60, "fix drafts")
    res["fix_draft"] = pg.locator("#draft-out").inner_text()[:100]
    stage("fixes drafted (drafts only)")
    assert not errors, errors

    finish(pg, b, proc, launcher, env, home, opened, url, marker, launcher_log, stage, errors)
    res["result"] = "PASS"
    return res


if __name__ == "__main__":
    make_stubs()
    site = build_site()
    srv, site_url = serve(site)
    results = []
    with sync_playwright() as p:
        for n in range(1, RUNS + 1):
            for flow, fn in (("website", lambda: one_run(n, site_url, p)),
                             ("github-zip", lambda: github_zip_run(n, p))):
                try:
                    r = fn()
                except Exception as e:
                    r = {"run": n, "flow": flow, "result": f"FAIL: {type(e).__name__}: {e}"}
                r.setdefault("flow", flow)
                results.append(r)
                print(json.dumps(r), flush=True)
    srv.shutdown()
    (OUT / "results.json").write_text(json.dumps(results, indent=2))
    print("PASSED" if all(r["result"] == "PASS" for r in results) else "SOME FAILED")
