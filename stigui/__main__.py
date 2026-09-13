"""stig-ui — a local page for people who do not live in a terminal.

    python3 -m stigui

Starts a small web server bound to 127.0.0.1 and opens the browser at it.
Nothing is published, nothing leaves the machine, and no third-party
package is required.

The page walks one person through the whole method: choose the guide for
this computer, read every rule in plain English, read the exact command
each check would run, approve the ones you accept under your own name,
then scan and read the report.

Three rules this server keeps, because the project's argument depends on
them:

* it listens on the loopback address only, never on a network interface;
* every request must carry the one-time token printed at startup, so no
  other page or process on the machine can drive it;
* it never approves a check and never runs an unapproved one. Approval is
  a person typing their name.
"""

from __future__ import annotations

import argparse
import json
import mimetypes
import os
import secrets
import socket
import subprocess
import sys
import threading
import time
import urllib.request
import webbrowser
from datetime import date, datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from stigprep.parser import parse_stig
from stigprep.render import to_markdown, to_json as checklist_json, to_csv
from stigprep.explain import explain
from stigprep.catalog import (CATALOG, desktop_guides, cli_only_guides,
                              recommended, fetch as fetch_guide, FetchError)
from stigscan import platforms
from stigscan.extract import build_pack
from stigscan.pack import CheckPack, PackError, APPROVED, MODE_SHELL
from stigscan.report import to_json as report_json, to_markdown as report_markdown, to_pdf
from stigscan.runner import ShellRunner
from stigscan.safety import audit
from stigscan.scan import run_scan, SEVERITY_LABEL
from stigscan.summary import summarize_report
from stigscan.selection import (
    SelectionError, apply_selection, find_selection, load_selection,
)

ROOT = Path(__file__).resolve().parents[1]
PAGE = Path(__file__).resolve().parent / "app.html"
TOKEN = secrets.token_urlsafe(24)


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ------------------------------------------------------------- app mode ----
#
# "App mode" is how the double-click program runs: no terminal, no working
# directory to speak of, and a person who will simply double-click again if
# nothing seems to happen. So in this mode the server keeps its files in the
# per-user application folder, remembers that it is running, hands a second
# launch to the first one, and stops itself when nobody has had the page
# open for a while. The command-line behaviour is unchanged.

APP_NAME = "STIG Checker"
RUNNING_FILE = "running.json"
IDLE_MINUTES = 10


def app_data_dir() -> Path:
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_NAME
    if sys.platform.startswith("win"):
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / APP_NAME
    base = os.environ.get("XDG_DATA_HOME") or str(Path.home() / ".local" / "share")
    return Path(base) / "stig-checker"


def _already_running(workdir: Path) -> str | None:
    """The URL of a live instance recorded in *workdir*, or None."""
    marker = workdir / RUNNING_FILE
    try:
        info = json.loads(marker.read_text(encoding="utf-8"))
        url = f"http://127.0.0.1:{int(info['port'])}/api/state"
        req = urllib.request.Request(url, headers={"X-Stig-Token": info["token"]})
        with urllib.request.urlopen(req, timeout=2) as r:
            if r.status == 200:
                return f"http://127.0.0.1:{int(info['port'])}/?t={info['token']}"
    except (OSError, ValueError, KeyError):
        pass
    return None


def _write_running(workdir: Path, port: int) -> None:
    marker = workdir / RUNNING_FILE
    marker.write_text(json.dumps({"port": port, "token": TOKEN, "pid": os.getpid(),
                                  "started": _stamp()}), encoding="utf-8")
    try:
        marker.chmod(0o600)
    except OSError:
        pass


def _clear_running(workdir: Path) -> None:
    try:
        (workdir / RUNNING_FILE).unlink()
    except OSError:
        pass


def open_folder(path: Path) -> None:
    """Show *path* in Finder / Explorer / the desktop's file manager."""
    if sys.platform == "darwin":
        subprocess.Popen(["open", str(path)])
    elif sys.platform.startswith("win"):
        os.startfile(str(path))  # type: ignore[attr-defined]
    else:
        subprocess.Popen(["xdg-open", str(path)])


# ---------------------------------------------------------------- state ----

class Session:
    """Everything one run of the page is working on."""

    def __init__(self, workdir: Path):
        self.workdir = workdir
        self.workdir.mkdir(parents=True, exist_ok=True)
        (self.workdir / "out").mkdir(exist_ok=True)
        self.benchmark = None
        self.source: Path | None = None
        self.checklist_path: Path | None = None
        self.pack: CheckPack | None = None
        self.pack_path: Path | None = None
        self.selection: dict | None = None
        self.rules_cache: list[dict] = []
        self.last_scan_path: Path | None = None
        self.lock = threading.Lock()

    # -- module 1 ----------------------------------------------------------
    def parse(self, path: Path, want_explain: bool = True) -> dict:
        benchmark = parse_stig(path)
        annotated = explain(benchmark, path, progress=False) if want_explain else 0
        self.benchmark, self.source = benchmark, path

        out = self.workdir / "out"
        base = _slug(benchmark.title or path.stem)
        written = {}
        for suffix, fn in (("md", to_markdown), ("json", checklist_json), ("csv", to_csv)):
            target = out / f"{base}_checklist.{suffix}"
            target.write_text(fn(benchmark), encoding="utf-8")
            written[suffix] = target.name
        self.checklist_path = out / f"{base}_checklist.json"

        counts: dict[str, int] = {}
        triage: dict[str, int] = {}
        for r in benchmark.rules:
            counts[r.severity] = counts.get(r.severity, 0) + 1
            bucket = (r.ai or {}).get("triage") or "unexplained"
            triage[bucket] = triage.get(bucket, 0) + 1

        result = {
            "title": benchmark.title,
            "version": benchmark.version,
            "release": benchmark.release_info,
            "source": path.name,
            "total": len(benchmark.rules),
            "high": counts.get("high", 0),
            "medium": counts.get("medium", 0),
            "low": counts.get("low", 0),
            "annotated": annotated,
            "triage": triage,
            "files": written,
            "rules": [_rule_row(r) for r in benchmark.rules],
        }
        self.rules_cache = result["rules"]
        return result

    def apply_website_selection(self, path: Path) -> dict:
        """Open a selection.json from the public site (or a local rebuild).

        The filtered pack is copied into the work folder so approvals stay
        with the person, not the zip they downloaded. Every check is left
        exactly as shipped — unreviewed — until they approve it here.
        """
        selection = load_selection(path)
        pack_path = Path(selection.get("pack_path") or "")
        if not pack_path.is_file():
            pack_path = path.parent / (selection.get("pack_path") or "")
        if not pack_path.is_file():
            source = selection.get("source_pack") or ""
            for candidate in (
                path.parent / "checkpacks" / f"{source}.json",
                path.parent / "checkpacks" / f"{source}-selected.json",
                ROOT / "checkpacks" / f"{source}.json",
            ):
                if candidate.is_file():
                    pack_path = candidate
                    break
        if not pack_path.is_file():
            raise SelectionError(
                "this selection names a check pack that is not in the folder")
        pack = CheckPack.load(pack_path)
        # A zip from the website already contains the filtered pack. A
        # selection that still points at the full shipped pack is filtered now.
        want = set(selection["rule_ids"])
        if {c.stig_id for c in pack.checks} != want:
            pack = apply_selection(pack, selection)
        target = self.workdir / f"{pack.pack_id}.json"
        pack.save(target)
        self.pack, self.pack_path = pack, target
        self.selection = selection
        from stigprep.explain import load_annotations
        ids = {c.stig_id for c in pack.checks}
        ann = load_annotations(Path("no-such-guide.zip"), ids)
        self.rules_cache = [_rule_row_from_check(c, ann.get(c.stig_id) or {}) for c in pack.checks]
        return self.pack_state()

    # -- module 2 ----------------------------------------------------------
    def author(self, platform_name: str) -> dict:
        if self.checklist_path is None:
            raise ValueError("parse a guide first")
        checklist = json.loads(self.checklist_path.read_text(encoding="utf-8"))
        prof = platforms.get(platform_name)
        pack_id = self.checklist_path.stem.replace("_checklist", "") + "-pack"
        pack = build_pack(checklist, pack_id, date.today().isoformat(), platform=prof.NAME)
        target = self.workdir / f"{pack_id}.json"
        pack.save(target)
        self.pack, self.pack_path = pack, target
        return self.pack_state()

    def load_pack(self, path: Path) -> dict:
        """Open a check pack, working on a copy when it came from the repository.

        Approvals belong to the person who made them, not to the checkout.
        A pack that ships with the project is copied into the work folder on
        first open, so ``git pull`` never discards someone's review and the
        repository's own packs stay unreviewed as published.
        """
        path = Path(path).resolve()
        if str(path).startswith(str(ROOT.resolve())) and self.workdir not in path.parents:
            mine = self.workdir / path.name
            if not mine.exists():
                mine.write_bytes(path.read_bytes())
            path = mine
        self.pack = CheckPack.load(path)
        self.pack_path = path
        return self.pack_state()

    def pack_state(self) -> dict:
        if self.pack is None:
            return {"loaded": False}
        pack = self.pack
        rows = []
        for c in pack.checks:
            problems = audit(c.command, pack.platform) if (c.mode == MODE_SHELL and c.command) else []
            rows.append({
                "stig_id": c.stig_id,
                "cat": SEVERITY_LABEL.get(c.severity, c.severity),
                "severity": c.severity,
                "title": c.title,
                "mode": c.mode,
                "command": c.command,
                "comparator": c.comparator,
                "expected": c.expected,
                "expected_source": c.expected_source,
                "requires_root": c.requires_root,
                "confidence": c.author_confidence,
                "note": c.author_note,
                "status": c.review_status,
                "reviewed_by": c.reviewed_by or "",
                "digest": (c.approved_digest or "")[:23],
                "drifted": c.is_drifted(),
                "objections": problems,
            })
        return {
            "loaded": True,
            "pack_id": pack.pack_id,
            "platform": pack.platform,
            "stig_title": pack.stig_title,
            "path": str(self.pack_path),
            "summary": pack.summary(),
            "checks": rows,
        }

    def decide(self, ids: list[str], by: str, note: str, approve: bool) -> dict:
        if self.pack is None:
            raise ValueError("no check pack loaded")
        by = (by or "").strip()
        if not by:
            raise ValueError("a name is required: approval records who accepted the command")
        stamp = _stamp()
        for sid in ids:
            check = self.pack.get(sid)
            if check is None:
                raise ValueError(f"{sid} is not in this pack")
            if approve:
                check.approve(by, stamp, note or "")
            else:
                check.reject(by, stamp, note or "")
        self.pack.save(self.pack_path)
        return self.pack_state()

    def scan(self, include_unreviewed: bool = False, on_progress=None) -> dict:
        if self.pack is None:
            raise ValueError("no check pack loaded")
        prof = platforms.get(self.pack.platform)
        here = platforms.detect()
        if here != prof.NAME:
            raise ValueError(
                f"this pack was authored for {prof.NAME} but this computer is {here}; "
                "refusing to run its commands here")
        if not prof.SUPPORTED:
            raise ValueError(f"scanning is not supported for {prof.NAME} in this release")

        record = self.workdir / "evidence" / datetime.now().strftime("%Y-%m-%d-%H%M%S")
        runner = ShellRunner(timeout=30, record_dir=str(record), platform=prof.NAME)
        report = run_scan(self.pack, runner, include_unreviewed=include_unreviewed,
                          on_progress=on_progress)

        out = self.workdir / "out"
        scan_json = out / f"{self.pack.pack_id}_scan.json"
        scan_json.write_text(report_json(report), encoding="utf-8")
        (out / f"{self.pack.pack_id}_scan.md").write_text(report_markdown(report), encoding="utf-8")
        (out / f"{self.pack.pack_id}_scan.pdf").write_bytes(to_pdf(report))
        self.last_scan_path = scan_json

        counts = report.counts()
        evaluated = counts["pass"] + counts["fail"]
        total = sum(counts.values())
        story = summarize_report(report)
        return {
            "host": report.host,
            "counts": counts,
            "evaluated": evaluated,
            "total": total,
            "coverage": story.coverage_line,
            "summary": story.to_dict(),
            "evidence": str(record),
            "files": [f"{self.pack.pack_id}_scan.json", f"{self.pack.pack_id}_scan.md",
                      f"{self.pack.pack_id}_scan.pdf"],
            "results": [
                {
                    "stig_id": r.stig_id,
                    "cat": SEVERITY_LABEL.get(r.severity, r.severity),
                    "severity": r.severity,
                    "title": r.title,
                    "status": r.status,
                    "detail": getattr(r, "detail", ""),
                    "trusted": getattr(r, "trusted", True),
                }
                for r in report.results
            ],
        }

    def latest_scan_json(self) -> Path:
        if self.last_scan_path and self.last_scan_path.is_file():
            return self.last_scan_path
        found = sorted(
            (self.workdir / "out").glob("*_scan.json"),
            key=lambda p: p.stat().st_mtime,
        )
        if not found:
            raise ValueError("no scan report yet — run a scan first")
        return found[-1]

    def draft_assessment(self) -> dict:
        """Write POA&M drafts from the last scan. Never closes an item."""
        from stigassess.interpret import draft_from_path
        from stigassess.render import to_csv, to_json as poam_json, to_markdown as poam_md

        scan = self.latest_scan_json()
        pack = draft_from_path(scan, checklist=self.checklist_path)
        out = self.workdir / "out"
        base = pack.pack_id
        (out / f"{base}.json").write_text(poam_json(pack), encoding="utf-8")
        (out / f"{base}.md").write_text(poam_md(pack), encoding="utf-8")
        (out / f"{base}.csv").write_text(to_csv(pack), encoding="utf-8")
        pack.save(out / f"{base}-pack.json")
        s = pack.summary()
        return {
            "kind": "poam",
            "closed": 0,
            "summary": s,
            "files": [f"{base}.json", f"{base}.md", f"{base}.csv"],
            "note": (
                "Drafts only. Nothing is closed. Approve and close on the "
                "command line under your own name."
            ),
            "entries": [
                {
                    "stig_id": e.stig_id,
                    "severity": e.severity,
                    "kind": e.kind,
                    "weakness": e.weakness,
                    "poam_status": e.poam_status,
                    "review_status": e.review_status,
                    "trusted": e.trusted,
                    "description": e.description,
                    "recommendation": e.recommendation,
                }
                for e in pack.entries
            ],
        }

    def draft_fixes(self) -> dict:
        """Write remediation drafts from the last scan. Never applies them."""
        from stigharden.author import author_from_path
        from stigharden.render import to_json as rem_json, to_markdown as rem_md, write_scripts

        scan = self.latest_scan_json()
        platform = self.pack.platform if self.pack else None
        pack = author_from_path(
            scan,
            checklist=self.checklist_path,
            checkpack=self.pack_path,
            platform=platform,
        )
        out = self.workdir / "out"
        scripts_dir = out / "remediations"
        pack.save(out / f"{pack.pack_id}.json")
        (out / f"{pack.pack_id}.md").write_text(rem_md(pack), encoding="utf-8")
        (out / f"{pack.pack_id}-report.json").write_text(rem_json(pack), encoding="utf-8")
        written = write_scripts(pack, scripts_dir)
        s = pack.summary()
        return {
            "kind": "harden",
            "applied": 0,
            "summary": s,
            "files": [f"{pack.pack_id}.json", f"{pack.pack_id}.md"]
                     + [f"remediations/{p.name}" for p in written],
            "note": (
                "Drafts only. Nothing was applied. Read each script, then "
                "approve and dry-run on the command line under your own name."
            ),
            "remediations": [
                {
                    "stig_id": r.stig_id,
                    "severity": r.severity,
                    "mode": r.mode,
                    "shape": r.shape,
                    "script": r.script,
                    "rationale": r.rationale,
                    "review_status": r.review_status,
                    "apply_status": r.apply_status,
                    "author_note": r.author_note,
                }
                for r in pack.remediations
            ],
        }


def _rule_row(rule) -> dict:
    ai = rule.ai or {}
    return {
        "stig_id": rule.stig_id,
        "group_id": rule.group_id,
        "cat": rule.cat,
        "severity": rule.severity,
        "title": rule.title,
        "summary": ai.get("summary", ""),
        "triage": ai.get("triage", ""),
        "automation": ai.get("automation", ""),
        "caution": ai.get("caution", ""),
        "check_text": rule.check_text,
        "fix_text": rule.fix_text,
    }


def _rule_row_from_check(check, ai: dict | None = None) -> dict:
    """A rules-tab row when the person arrived with a website selection."""
    ai = ai or {}
    return {
        "stig_id": check.stig_id,
        "group_id": check.group_id,
        "cat": SEVERITY_LABEL.get(check.severity, check.severity),
        "severity": check.severity,
        "title": check.title,
        "summary": ai.get("summary", ""),
        "triage": ai.get("triage", ""),
        "automation": ai.get("automation", ""),
        "caution": ai.get("caution", ""),
        "check_text": "",
        "fix_text": "",
    }


def _slug(text: str) -> str:
    import re
    slug = re.sub(r"[^A-Za-z0-9]+", "_", text).strip("_").lower() or "stig"
    return slug[:48].rstrip("_")


def shipped_packs(platform_name: str) -> list[dict]:
    out = []
    for path in sorted((ROOT / "checkpacks").glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if data.get("platform") != platform_name:
            continue
        out.append({
            "name": path.name,
            "path": str(path),
            "pack_id": data.get("pack_id", path.stem),
            "title": data.get("stig_title", ""),
            "checks": len(data.get("checks", [])),
        })
    return out


# -------------------------------------------------------------- handler ----

class Handler(BaseHTTPRequestHandler):
    server_version = "stig-ui"
    session: Session
    httpd: ThreadingHTTPServer | None = None
    app_mode: bool = False
    last_seen: float = 0.0

    def log_message(self, fmt, *args):  # quieter than the default
        pass

    # -- helpers ----------------------------------------------------------
    def _authorised(self, query: dict) -> bool:
        host = (self.headers.get("Host") or "").split(":")[0]
        if host not in ("127.0.0.1", "localhost"):
            return False
        supplied = self.headers.get("X-Stig-Token") or (query.get("t") or [""])[0]
        return secrets.compare_digest(supplied, TOKEN)

    def _send(self, code: int, body: bytes, ctype: str = "application/json"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, payload, code: int = 200):
        self._send(code, json.dumps(payload).encode("utf-8"))

    def _fail(self, message: str, code: int = 400):
        self._json({"error": message}, code)

    def _begin_sse(self):
        """Open a flushed event stream. The page needs each check as it
        finishes — on Windows a hidden PowerShell window is the only other
        signal, and there isn't one."""
        try:
            self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except OSError:
            pass
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache, no-store")
        self.send_header("X-Accel-Buffering", "no")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()

    def _write_sse(self, obj: dict) -> None:
        payload = json.dumps(obj, ensure_ascii=False)
        self.wfile.write(f"data: {payload}\n\n".encode("utf-8"))
        self.wfile.flush()
        raw = getattr(self.wfile, "raw", None)
        if raw is not None:
            try:
                raw.flush()
            except OSError:
                pass

    def _stream_scan(self, session: Session, include_unreviewed: bool) -> None:
        try:
            if session.pack is None:
                raise ValueError("no check pack loaded")
            prof = platforms.get(session.pack.platform)
            here = platforms.detect()
            if here != prof.NAME:
                raise ValueError(
                    f"this pack was authored for {prof.NAME} but this computer is {here}; "
                    "refusing to run its commands here")
            if not prof.SUPPORTED:
                raise ValueError(f"scanning is not supported for {prof.NAME} in this release")
        except ValueError as e:
            return self._fail(str(e))

        self._begin_sse()
        try:
            result = session.scan(include_unreviewed, on_progress=self._write_sse)
            self._write_sse({"phase": "done", **result})
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            return None
        except Exception as e:
            try:
                self._write_sse({"phase": "error", "error": f"{type(e).__name__}: {e}"})
            except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
                pass
        return None

    def _body(self) -> bytes:
        length = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(length) if length else b""

    # -- routes -----------------------------------------------------------
    def do_GET(self):
        url = urlparse(self.path)
        query = parse_qs(url.query)

        if url.path == "/":
            if not self._authorised(query):
                return self._send(403, b"Open the address printed in the terminal.", "text/plain")
            html = PAGE.read_text(encoding="utf-8").replace("__TOKEN__", TOKEN)
            return self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")

        if not self._authorised(query):
            return self._fail("not authorised", 403)

        if url.path == "/api/state":
            here = platforms.detect()
            return self._json({
                "platform": here,
                "platforms": list(platforms.NAMES),
                "recommended": recommended(here),
                "catalog": [
                    {"key": g.key, "label": g.label, "platform": g.platform,
                     "mine": g.platform == here}
                    for g in desktop_guides()
                ],
                "cli_only": [{"key": g.key, "label": g.label} for g in cli_only_guides()],
                "workdir": str(self.session.workdir),
                "files_dir": str(self.session.workdir / "out"),
                "app": Handler.app_mode,
                "packs": shipped_packs(platforms.detect()),
                "pack": self.session.pack_state(),
                "selection": self.session.selection,
                "rules": self.session.rules_cache,
            })

        if url.path == "/api/download":
            name = (query.get("file") or [""])[0]
            target = (self.session.workdir / "out" / name).resolve()
            if not str(target).startswith(str((self.session.workdir / "out").resolve())):
                return self._fail("no", 400)
            if not target.is_file():
                return self._fail("not found", 404)
            ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
            return self._send(200, target.read_bytes(), ctype)

        return self._fail("not found", 404)

    def do_POST(self):
        url = urlparse(self.path)
        query = parse_qs(url.query)
        if not self._authorised(query):
            return self._fail("not authorised", 403)

        session = self.session

        # The page pings while it is open; the idle timer reads this.
        if url.path == "/api/ping":
            Handler.last_seen = time.monotonic()
            return self._json({"ok": True})

        if url.path == "/api/quit":
            self._json({"ok": True})
            if Handler.httpd is not None:
                threading.Thread(target=Handler.httpd.shutdown, daemon=True).start()
            return None

        if url.path == "/api/open-folder":
            target = session.workdir / "out"
            target.mkdir(parents=True, exist_ok=True)
            try:
                open_folder(target)
            except OSError as e:
                return self._fail(f"could not open {target}: {e}")
            return self._json({"path": str(target)})

        try:
            with session.lock:
                if url.path == "/api/upload":
                    name = Path((query.get("name") or ["guide"])[0]).name
                    target = session.workdir / name
                    target.write_bytes(self._body())
                    return self._json({"path": str(target), "name": name})

                payload = json.loads(self._body() or b"{}")

                if url.path == "/api/fetch":
                    key = payload.get("key", "")
                    if key not in {g.key for g in desktop_guides()}:
                        return self._fail(
                            f"{key!r} is not offered here. Servers, Linux and databases are "
                            f"handled from the command line: python3 -m stigprep fetch {key}")
                    notes: list[str] = []
                    try:
                        got = fetch_guide(key, session.workdir, progress=notes.append)
                    except FetchError as e:
                        return self._fail(str(e))
                    return self._json({"path": str(got), "name": got.name,
                                       "notes": [n.strip() for n in notes]})

                if url.path == "/api/parse":
                    path = Path(payload["path"])
                    if not path.exists():
                        return self._fail(f"{path.name} not found")
                    return self._json(session.parse(path, payload.get("explain", True)))

                if url.path == "/api/pack/author":
                    return self._json(session.author(payload.get("platform") or platforms.detect()))

                if url.path == "/api/pack/load":
                    return self._json(session.load_pack(Path(payload["path"])))

                if url.path == "/api/pack/decide":
                    return self._json(session.decide(
                        payload.get("ids") or [],
                        payload.get("by", ""),
                        payload.get("note", ""),
                        approve=bool(payload.get("approve")),
                    ))

                if url.path == "/api/scan":
                    return self._stream_scan(session, bool(payload.get("include_unreviewed")))

                if url.path == "/api/assess":
                    if payload.get("close") or payload.get("approve"):
                        return self._fail(
                            "the page will not close or approve a POA&M item; "
                            "drafts only. Use python3 -m stigassess on the command line.")
                    return self._json(session.draft_assessment())

                if url.path == "/api/harden":
                    if payload.get("apply") or payload.get("approve"):
                        return self._fail(
                            "the page will not apply or approve a remediation; "
                            "drafts only. Use python3 -m stigharden on the command line.")
                    return self._json(session.draft_fixes())

            return self._fail("not found", 404)
        except (ValueError, KeyError, PackError, SelectionError) as e:
            return self._fail(str(e))
        except Exception as e:  # surfaced in the page rather than the terminal
            return self._fail(f"{type(e).__name__}: {e}", 500)


# ----------------------------------------------------------------- main ----

def _idle_watch(httpd: ThreadingHTTPServer, minutes: int) -> None:
    """Stop the server once the page has been closed for *minutes*."""
    limit = minutes * 60
    while True:
        time.sleep(15)
        if time.monotonic() - Handler.last_seen > limit:
            print(f"no page open for {minutes} minutes; stopping.", flush=True)
            httpd.shutdown()
            return


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="stig-ui", description=__doc__.splitlines()[0])
    ap.add_argument("--port", type=int, default=0, help="port (default: pick a free one)")
    ap.add_argument("--workdir", default=None,
                    help="where uploads and outputs go (default: ./stig-work, or the "
                         "per-user application folder with --app)")
    ap.add_argument("--no-browser", action="store_true", help="do not open a browser")
    ap.add_argument("--app", action="store_true",
                    help="run as the double-click application: keep files in the "
                         "per-user folder, reuse a running instance, log to a file, "
                         "and stop when the page has been closed for a while")
    ap.add_argument("--idle-minutes", type=int, default=None,
                    help=f"stop after this long with no page open (app mode: {IDLE_MINUTES})")
    ap.add_argument("--pack", default=None,
                    help="check pack to open on start")
    ap.add_argument("--selection", default=None,
                    help="selection.json from the public website")
    args = ap.parse_args(argv)

    if not PAGE.exists():
        print(f"error: {PAGE} is missing", file=sys.stderr)
        return 1

    workdir = Path(args.workdir).resolve() if args.workdir else (
        app_data_dir() if args.app else Path("stig-work").resolve())
    workdir.mkdir(parents=True, exist_ok=True)

    if args.app:
        # No terminal is attached. Everything that would have been printed
        # goes to a log beside the files, where a person can find it.
        log = open(workdir / "stig-checker.log", "a", encoding="utf-8", buffering=1)
        sys.stdout = sys.stderr = log
        print(f"--- {_stamp()} starting, pid {os.getpid()}")
        live = _already_running(workdir)
        if live:
            print("already running; opening the page again.")
            if not args.no_browser:
                webbrowser.open(live)
            return 0

    Handler.session = Session(workdir)
    Handler.app_mode = bool(args.app)
    selection_path = Path(args.selection).resolve() if args.selection else find_selection(ROOT)
    if selection_path and selection_path.is_file():
        try:
            Handler.session.apply_website_selection(selection_path)
        except (SelectionError, PackError, OSError) as e:
            print(f"warning: could not load selection {selection_path}: {e}", flush=True)
    elif args.pack:
        Handler.session.load_pack(Path(args.pack))
    Handler.last_seen = time.monotonic()
    port = args.port or _free_port()
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    Handler.httpd = httpd
    url = f"http://127.0.0.1:{port}/?t={TOKEN}"

    print("stig-ui is running.")
    print(f"  open   {url}")
    print(f"  files  {Handler.session.workdir}")
    print("  stop   Ctrl-C" if not args.app else "  stop   the Quit button on the page")
    print()
    print("This page is reachable only from this computer. Nothing is uploaded anywhere.")

    idle = args.idle_minutes if args.idle_minutes is not None else (IDLE_MINUTES if args.app else 0)
    if idle > 0:
        threading.Thread(target=_idle_watch, args=(httpd, idle), daemon=True).start()
    if args.app:
        _write_running(workdir, port)
    if not args.no_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")
    finally:
        httpd.server_close()
        if args.app:
            _clear_running(workdir)
            print(f"--- {_stamp()} stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
