"""Export the GitHub Pages site data from the catalogue, annotations and packs.

    python3 packaging/build_site.py
    python3 packaging/build_site.py --out docs

Writes, under the output folder:

  data/catalog.json          desktop guides, pinned releases, SHA / rule counts
  data/guides/<key>.json     plain-English rule lists for the website
  data/checkpacks/<id>.json  full shipped packs used to build a scan selection
  packages/scanner-src.zip   source payload the browser turns into a scanner

The site itself (index.html, site.js, zip.js, demo.html, pages.css)
is hand-written and is not replaced. This script only refreshes
the data the start page reads.

GitHub Pages cannot fetch dl.dod.cyber.mil (browsers block it, and many
networks do too). The exported JSON is the filed explanation set this
project validated — the same content `stigprep parse --explain` attaches.
The local scanner still downloads the official zip when a person asks it to.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from stigprep.catalog import (  # noqa: E402
    CATALOG, DOWNLOAD_PAGE, BASE, desktop_guides, scannable_guides,
)
from stigprep.explain import _entries  # noqa: E402
from stigscan.pack import CheckPack  # noqa: E402
from stigscan.scan import SEVERITY_LABEL  # noqa: E402


def log(message: str) -> None:
    print(message, flush=True)


def _load_annotations(name: str) -> dict:
    path = ROOT / "annotations" / name
    if not path.is_file():
        return {}
    raw = json.loads(path.read_text(encoding="utf-8"))
    return _entries(raw)


def catalog_payload() -> dict:
    guides = []
    for g in desktop_guides():
        filename = g.template.format(rel=g.release)
        guides.append({
            "key": g.key,
            "label": g.label,
            "platform": g.platform,
            "release": g.release,
            "rules": g.rules,
            "sha256": g.sha256,
            "template": g.template,
            "filename": filename,
            "url": g.url(filename),
            "desktop": g.desktop,
            "checkpack": g.checkpack,
            "annotation": g.annotation,
            "scannable": bool(g.checkpack),
        })
    return {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "download_page": DOWNLOAD_PAGE,
        "base": BASE,
        "note": (
            "GitHub Pages cannot download from dl.dod.cyber.mil: browsers block "
            "the request (CORS) and many networks block the host. This site "
            "ships the filed explanations and check metadata this project "
            "validated (release and rule count below; SHA-256 when pinned). "
            "The local scanner still fetches the official zip, verifies it, "
            "and refuses a file that does not match."
        ),
        "guides": guides,
        "cli_only": [{"key": g.key, "label": g.label, "platform": g.platform}
                     for g in CATALOG if not g.desktop],
    }


def guide_payload(key: str) -> dict:
    guide = next(g for g in desktop_guides() if g.key == key)
    pack = None
    items = []
    annotated = 0
    if guide.checkpack:
        pack = CheckPack.load(ROOT / "checkpacks" / f"{guide.checkpack}.json")
        ann = _load_annotations(guide.annotation) if guide.annotation else {}
        for c in pack.checks:
            entry = ann.get(c.stig_id) or {}
            if entry.get("summary"):
                annotated += 1
            items.append({
                "stig_id": c.stig_id,
                "group_id": c.group_id,
                "severity": c.severity,
                "cat": SEVERITY_LABEL.get(c.severity, c.severity),
                "title": c.title,
                "summary": entry.get("summary", ""),
                "triage": entry.get("triage", ""),
                "automation": entry.get("automation", ""),
                "caution": entry.get("caution", ""),
                "mode": c.mode,
            })
    return {
        "key": guide.key,
        "label": guide.label,
        "platform": guide.platform,
        "title": pack.stig_title if pack else guide.label,
        "version": pack.stig_version if pack else f"R{guide.release}",
        "release": guide.release,
        "rules": len(items) or guide.rules or 0,
        "annotated": annotated,
        "checkpack": guide.checkpack,
        "annotation": guide.annotation,
        "official_url": guide.url(guide.template.format(rel=guide.release)),
        "download_page": DOWNLOAD_PAGE,
        "filename": guide.template.format(rel=guide.release),
        "sha256": guide.sha256,
        "expected_rules": guide.rules,
        "items": items,
    }


def _payload_files() -> list[Path]:
    """Same shape as packaging/build_scanpack.py — kept local so this
    script does not import the PyPI ``packaging`` package by accident."""
    out: list[Path] = []
    for name in ("stigprep", "stigscan", "stigassess", "stigharden", "stigui"):
        folder = ROOT / name
        if not folder.is_dir():
            continue
        for path in sorted(folder.rglob("*")):
            if path.is_file() and path.suffix != ".pyc" and "__pycache__" not in path.parts:
                out.append(path)
    for name in ("run.py", "Start.command", "Start.bat", "STIG Checker.command",
                 "STIG Checker.bat", "run-hidden.vbs", "Double-click this.txt",
                 "LICENSE"):
        path = ROOT / name
        if path.is_file():
            out.append(path)
    for name in ("ensure-python.sh", "ensure-python.ps1"):
        path = ROOT / "scripts" / name
        if path.is_file():
            out.append(path)
    return out


def write_scanner_src(dest: Path) -> Path:
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        dest.unlink()
    files = _payload_files()
    # Filed explanations the website scanner will need after unzip.
    for g in scannable_guides():
        if g.annotation:
            path = ROOT / "annotations" / g.annotation
            if path.is_file():
                files.append(path)
    with zipfile.ZipFile(dest, "w", compression=zipfile.ZIP_STORED) as zf:
        for path in files:
            rel = path.relative_to(ROOT).as_posix()
            zf.write(path, rel)
    return dest


def export(out_dir: Path) -> None:
    data = out_dir / "data"
    (data / "guides").mkdir(parents=True, exist_ok=True)
    (data / "checkpacks").mkdir(parents=True, exist_ok=True)
    (out_dir / "packages").mkdir(parents=True, exist_ok=True)

    for g in desktop_guides():
        if not g.checkpack:
            continue
        payload = guide_payload(g.key)
        target = data / "guides" / f"{g.key}.json"
        target.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        log(f"  wrote {target}  ({payload['annotated']}/{payload['rules']} explained)")
        src = ROOT / "checkpacks" / f"{g.checkpack}.json"
        dest = data / "checkpacks" / f"{g.checkpack}.json"
        dest.write_bytes(src.read_bytes())
        log(f"  wrote {dest}")

    src_zip = write_scanner_src(out_dir / "packages" / "scanner-src.zip")
    digest = hashlib.sha256(src_zip.read_bytes()).hexdigest()
    catalog = catalog_payload()
    catalog["payload"] = {
        "file": "packages/scanner-src.zip",
        "sha256": digest,
        "bytes": src_zip.stat().st_size,
    }
    (data / "catalog.json").write_text(
        json.dumps(catalog, indent=2) + "\n", encoding="utf-8")
    log(f"  wrote {src_zip}  ({src_zip.stat().st_size:,} bytes, stored, sha256 {digest[:12]}…)")
    log(f"  wrote {data / 'catalog.json'}  ({len(catalog['guides'])} desktop guides)")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", default=str(ROOT / "docs"),
                    help="site folder (default: docs/)")
    args = ap.parse_args(argv)
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    log(f"exporting site data into {out}")
    export(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
