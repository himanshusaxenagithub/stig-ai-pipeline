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
import secrets
import socket
import sys
import threading
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
from stigscan.report import to_json as report_json, to_markdown as report_markdown
from stigscan.runner import ShellRunner
from stigscan.safety import audit
from stigscan.scan import run_scan, SEVERITY_LABEL

ROOT = Path(__file__).resolve().parents[1]
PAGE = Path(__file__).resolve().parent / "app.html"
TOKEN = secrets.token_urlsafe(24)


def _stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


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

        return {
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

    def scan(self, include_unreviewed: bool = False) -> dict:
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
        report = run_scan(self.pack, runner, include_unreviewed=include_unreviewed)

        out = self.workdir / "out"
        (out / f"{self.pack.pack_id}_scan.json").write_text(report_json(report), encoding="utf-8")
        (out / f"{self.pack.pack_id}_scan.md").write_text(report_markdown(report), encoding="utf-8")

        counts = report.counts()
        evaluated = counts["pass"] + counts["fail"]
        total = sum(counts.values())
        return {
            "host": report.host,
            "counts": counts,
            "evaluated": evaluated,
            "total": total,
            "coverage": (
                f"{evaluated} of {total} rules "
                f"({(evaluated / total * 100 if total else 0):.1f}%) were actually evaluated on "
                "this host. The rest produced no compliance evidence and must not be counted as "
                "either compliant or non-compliant."
            ),
            "evidence": str(record),
            "files": [f"{self.pack.pack_id}_scan.json", f"{self.pack.pack_id}_scan.md"],
            "results": [
                {
                    "stig_id": r.stig_id,
                    "cat": SEVERITY_LABEL.get(r.severity, r.severity),
                    "title": r.title,
                    "status": r.status,
                    "detail": getattr(r, "detail", ""),
                }
                for r in report.results
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
                "packs": shipped_packs(platforms.detect()),
                "pack": self.session.pack_state(),
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
                    return self._json(session.scan(bool(payload.get("include_unreviewed"))))

            return self._fail("not found", 404)
        except (ValueError, KeyError, PackError) as e:
            return self._fail(str(e))
        except Exception as e:  # surfaced in the page rather than the terminal
            return self._fail(f"{type(e).__name__}: {e}", 500)


# ----------------------------------------------------------------- main ----

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="stig-ui", description=__doc__.splitlines()[0])
    ap.add_argument("--port", type=int, default=0, help="port (default: pick a free one)")
    ap.add_argument("--workdir", default="stig-work", help="where uploads and outputs go")
    ap.add_argument("--no-browser", action="store_true", help="do not open a browser")
    args = ap.parse_args(argv)

    if not PAGE.exists():
        print(f"error: {PAGE} is missing", file=sys.stderr)
        return 1

    Handler.session = Session(Path(args.workdir).resolve())
    port = args.port or _free_port()
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    url = f"http://127.0.0.1:{port}/?t={TOKEN}"

    print("stig-ui is running.")
    print(f"  open   {url}")
    print(f"  files  {Handler.session.workdir}")
    print("  stop   Ctrl-C")
    print()
    print("This page is reachable only from this computer. Nothing is uploaded anywhere.")

    if not args.no_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped.")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
