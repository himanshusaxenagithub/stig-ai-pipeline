"""Build a configured local scanner from a website (or CLI) selection.

    python3 packaging/build_scanpack.py \
        --platform macos \
        --pack checkpacks/macos-26-v1r3.json \
        --id APPL-26-000054 --id APPL-26-002038 \
        -o dist/STIG-Scanner-macOS

The folder that comes out is the same shape as a source checkout: Python
files you can read, Start.command / Start.bat, a filtered check pack, and
selection.json. It is not a compiled program and it does not embed Python
— the existing Start scripts still fetch a private interpreter if the
machine has none.

Nothing in the pack is approved. The person who unzips it must read each
command and type their name before a scan runs. Scanning happens on their
machine; this script never executes a check.
"""

from __future__ import annotations

import argparse
import shutil
import stat
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from stigscan.pack import CheckPack, PackError  # noqa: E402
from stigscan.selection import (  # noqa: E402
    SelectionError, apply_selection, make_selection, write_selection,
)

APP_NAME = "STIG Checker"
PAYLOAD_DIRS = ["stigprep", "stigscan", "stigassess", "stigharden", "stigui"]
LAUNCHERS = [
    "Start.command", "Start.bat", "STIG Checker.command", "STIG Checker.bat",
    "run-hidden.vbs", "Double-click this.txt", "LICENSE",
]
SCRIPT_FILES = ["ensure-python.sh", "ensure-python.ps1"]

README = """STIG Checker — configured scan pack
===================================

This folder was built for {os_label} from a selection of {n} rule(s)
in {source_pack}.

What this is
------------

A local program. It does not send information about your computer
anywhere. The website you downloaded it from never ran a scan; it only
named the rules you picked.

Every check in this pack is unreviewed. That is deliberate. Approval
records who accepted the exact command, and an approval is worthless if
it was not made by the person accountable for this machine.

How to run it
-------------

1. Keep these files together. Do not drag one file to the Desktop.

2. Windows: double-click "STIG Checker.bat".
   Mac: right-click "STIG Checker.command" → Open → Open.

3. Windows may say "Windows protected your PC". Click More info, then
   Run anyway. Once.

4. If a box asks to download Python, click Yes. That is a private copy
   from python.org. It is not installed system-wide and needs no
   administrator password.

5. A page opens in your browser on this computer (127.0.0.1). The rules
   you selected are already loaded. Read each command, type your name,
   approve the ones you accept, then scan.

6. A PDF report is written with the JSON and Markdown reports. Use the
   Show files button on the page to open that folder.

If your network blocks dl.dod.cyber.mil, you do not need it for this
pack — the selected checks and the filed explanations are already here.
The official STIG zip is still at https://public.cyber.mil/stigs/downloads/
if you want the source document.

MIT licence. https://github.com/himanshusaxenagithub/stig-ai-pipeline
"""


def log(message: str) -> None:
    print(message, flush=True)


def payload_files(root: Path = ROOT) -> list[Path]:
    """Project files copied into every configured scanner."""
    out: list[Path] = []
    for name in PAYLOAD_DIRS:
        folder = root / name
        if not folder.is_dir():
            continue
        for path in sorted(folder.rglob("*")):
            if path.is_file() and path.suffix != ".pyc" and "__pycache__" not in path.parts:
                out.append(path)
    for name in LAUNCHERS:
        path = root / name
        if path.is_file():
            out.append(path)
    for name in SCRIPT_FILES:
        path = root / "scripts" / name
        if path.is_file():
            out.append(path)
    return out


def copy_payload(dest: Path, root: Path = ROOT) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    for name in PAYLOAD_DIRS:
        source = root / name
        if not source.exists():
            continue
        shutil.copytree(
            source, dest / name,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".DS_Store",
                                          "stig-work"),
            dirs_exist_ok=True,
        )
    scripts = dest / "scripts"
    scripts.mkdir(exist_ok=True)
    for name in SCRIPT_FILES:
        source = root / "scripts" / name
        if source.is_file():
            shutil.copy2(source, scripts / name)
            if name.endswith(".sh"):
                _executable(scripts / name)
    for name in LAUNCHERS:
        source = root / name
        if source.is_file():
            shutil.copy2(source, dest / name)
            if name.endswith(".command"):
                _executable(dest / name)


def _executable(path: Path) -> None:
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def copy_annotation(dest: Path, annotation: str | None, root: Path = ROOT) -> None:
    if not annotation:
        return
    source = root / "annotations" / annotation
    if not source.is_file():
        return
    target = dest / "annotations"
    target.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target / annotation)


def build_configured(
    dest: Path,
    *,
    platform: str,
    pack: CheckPack,
    rule_ids: list[str],
    guide_key: str = "",
    os_label: str = "",
    annotation: str | None = None,
    root: Path = ROOT,
) -> dict:
    """Write a configured scanner folder. Returns the selection dict."""
    if pack.platform != platform:
        raise SelectionError(
            f"pack {pack.pack_id} is for {pack.platform}, not {platform}")
    selection = make_selection(
        platform=platform,
        guide_key=guide_key or pack.pack_id,
        source_pack=pack.pack_id,
        rule_ids=rule_ids,
        pack_id=f"{pack.pack_id}-selected",
        pack_path=f"checkpacks/{pack.pack_id}-selected.json",
        os_label=os_label or platform,
    )
    filtered = apply_selection(pack, selection)
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    copy_payload(dest, root=root)
    copy_annotation(dest, annotation, root=root)
    (dest / "checkpacks").mkdir(exist_ok=True)
    filtered.save(dest / selection["pack_path"])
    write_selection(dest / "selection.json", selection)
    (dest / "Read me.txt").write_text(
        README.format(os_label=selection["os_label"], n=len(selection["rule_ids"]),
                      source_pack=pack.pack_id),
        encoding="utf-8",
    )
    return selection


def zip_dir(folder: Path, archive: Path) -> None:
    if archive.exists():
        archive.unlink()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(folder.rglob("*")):
            arcname = Path(folder.name) / path.relative_to(folder)
            if path.is_dir():
                info = zipfile.ZipInfo(str(arcname) + "/")
                info.external_attr = (0o40755 << 16) | 0x10
                zf.writestr(info, b"")
                continue
            info = zipfile.ZipInfo.from_file(path, str(arcname))
            info.compress_type = zipfile.ZIP_DEFLATED
            mode = path.stat().st_mode
            if path.suffix in {".command", ".sh"}:
                mode |= stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
            info.external_attr = (mode & 0xFFFF) << 16
            with path.open("rb") as fh:
                zf.writestr(info, fh.read())


def main(argv=None) -> int:
    here = { "Darwin": "macos", "Windows": "windows" }
    import platform as _p
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--platform", choices=["macos", "windows"],
                    default=here.get(_p.system()),
                    help="which machine the pack is for")
    ap.add_argument("--pack", required=True, help="source check pack JSON")
    ap.add_argument("--id", action="append", dest="ids", default=[],
                    help="rule id to include (repeatable). Default: every rule")
    ap.add_argument("--guide", default="", help="catalogue key, e.g. macos-26")
    ap.add_argument("--annotation", default=None,
                    help="filename under annotations/ to copy")
    ap.add_argument("-o", "--out", required=True, help="folder to write")
    ap.add_argument("--zip", dest="zip_path", default=None,
                    help="also write this zip archive")
    args = ap.parse_args(argv)
    if not args.platform:
        print("error: pass --platform macos or windows", file=sys.stderr)
        return 1

    pack_path = Path(args.pack)
    if not pack_path.is_file():
        pack_path = ROOT / args.pack
    try:
        pack = CheckPack.load(pack_path)
    except PackError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    ids = args.ids or [c.stig_id for c in pack.checks]
    dest = Path(args.out)
    try:
        selection = build_configured(
            dest, platform=args.platform, pack=pack, rule_ids=ids,
            guide_key=args.guide, annotation=args.annotation,
        )
    except (SelectionError, PackError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    log(f"wrote {dest}  ({len(selection['rule_ids'])} rules, still unreviewed)")
    if args.zip_path:
        archive = Path(args.zip_path)
        zip_dir(dest, archive)
        log(f"wrote {archive}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
