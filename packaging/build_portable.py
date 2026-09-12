"""Assemble a portable folder: this project plus a Python of its own.

    python3 packaging/build_portable.py

Run it once on a Mac and once on a Windows PC. Each run produces a folder,
and a .zip of it, that someone can unpack and double-click. They do not
need Python, an installer, administrator rights, or a terminal.

What comes out:

    stig-ai-pipeline-macos/
      Start.command          <- double-click this
      README.txt
      app/                   <- the project, unchanged and readable
        run.py  stigprep/  stigscan/  stigui/  annotations/  checkpacks/
      python/                <- a Python that lives in this folder only

Nothing is packed, compiled or obfuscated. The code ships as the same .py
files that are on GitHub, because a tool whose argument is "you can read
exactly what this runs" should not arrive as a black box. It also avoids
the antivirus false positives that packers attract, which for a program
that spawns PowerShell would be a serious problem.

Where the Python comes from:

* Windows — the embeddable distribution published by python.org. About
  15 MB, designed for exactly this, and it touches nothing on the machine.
* macOS — a relocatable build from the python-build-standalone project,
  which is what modern Python tooling uses for the same purpose.

Either can be overridden with --python-url or --python-dir when you are
offline or want to pin a specific build.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import platform
import shutil
import stat
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Everything the program needs at runtime, copied verbatim.
PAYLOAD = ["stigprep", "stigscan", "stigui", "annotations", "checkpacks", "skills"]
EXTRA_FILES = ["LICENSE", "README.md", "CHANGELOG.md"]

PY_VERSION = "3.12.7"
WINDOWS_EMBED = (f"https://www.python.org/ftp/python/{PY_VERSION}/"
                 f"python-{PY_VERSION}-embed-amd64.zip")
PBS_LATEST = ("https://api.github.com/repos/astral-sh/python-build-standalone/"
              "releases/latest")

RUN_PY = '''"""Start the local page. Kept tiny on purpose.

The portable folder ships its own Python, which knows nothing about this
project, so this file puts the folder it lives in on the import path and
hands over. Everything it imports is a plain .py file beside it.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from stigui.__main__ import main  # noqa: E402

raise SystemExit(main(sys.argv[1:]))
'''

START_COMMAND = '''#!/bin/bash
# Double-click this file. It opens a page in your browser.
cd "$(dirname "$0")" || exit 1
./python/bin/python3 app/run.py
echo
read -r -p "Press return to close this window."
'''

START_BAT = '''@echo off
REM Double-click this. It opens a page in your browser.
cd /d "%~dp0"
if exist "program\\python\\pythonw.exe" (
  start "" "program\\python\\pythonw.exe" "program\\app\\run.py"
) else (
  start "" "program\\python\\python.exe" "program\\app\\run.py"
)
'''

READ_ME_TXT = '''stig-ai-pipeline
================

Double-click {launcher}

A page opens in your browser. Pick MacBook or Windows PC, and it downloads
the official Department of Defense security guide for that machine, explains
every rule in plain English, and shows you exactly what each check would run
before anything runs.

Nothing is installed. Nothing leaves this computer. Delete this folder to
remove it completely.

{gatekeeper}
The program is ordinary Python files, not a compiled binary. On Windows
they are in program\app. On a Mac, right-click the application and choose
Show Package Contents, then Contents/Resources/app. You are meant to be
able to read them.

MIT licence. https://github.com/himanshusaxenagithub/stig-ai-pipeline
'''

GATEKEEPER_NOTE = '''The first time you open it, macOS may say it cannot check the application
for malicious software, because it was downloaded from the internet.
Right-click STIG Checker, choose Open, then click Open again in the box
that appears. You only have to do this once.

'''


def log(message: str) -> None:
    print(message, flush=True)


def fetch(url: str) -> bytes:
    log(f"  downloading {url}")
    request = urllib.request.Request(url, headers={"User-Agent": "stig-ai-pipeline build"})
    with urllib.request.urlopen(request, timeout=180) as response:
        return response.read()


# ------------------------------------------------------------- python ----

def windows_python(dest: Path, url: str) -> None:
    data = fetch(url)
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        zf.extractall(dest)
    # The embeddable build disables importing from anywhere but itself.
    # run.py sets sys.path explicitly, but site must be importable for the
    # standard library to behave normally.
    for pth in dest.glob("python*._pth"):
        text = pth.read_text(encoding="utf-8")
        if "import site" not in text:
            pth.write_text(text.replace("#import site", "import site"), encoding="utf-8")


def macos_python_url() -> str:
    """Newest relocatable CPython for this Mac from python-build-standalone."""
    arch = "aarch64" if platform.machine() in ("arm64", "aarch64") else "x86_64"
    want = f"cpython-{PY_VERSION}+"
    tail = f"-{arch}-apple-darwin-install_only.tar.gz"
    try:
        release = json.loads(fetch(PBS_LATEST).decode("utf-8"))
    except Exception as e:
        raise SystemExit(
            f"could not reach python-build-standalone ({e}).\n"
            "Download a build yourself from\n"
            "  https://github.com/astral-sh/python-build-standalone/releases\n"
            f"pick one ending in {tail}, then re-run with\n"
            "  --python-url <that url>   or   --python-dir <the unpacked folder>"
        ) from e
    for asset in release.get("assets", []):
        name = asset.get("name", "")
        if name.startswith(want) and name.endswith(tail):
            return asset["browser_download_url"]
    for asset in release.get("assets", []):
        name = asset.get("name", "")
        if name.startswith("cpython-3.12.") and name.endswith(tail):
            return asset["browser_download_url"]
    raise SystemExit(
        f"no build matching *{tail} in the latest python-build-standalone release.\n"
        "Pass --python-url with one you have chosen yourself."
    )


def macos_python(dest: Path, url: str) -> None:
    data = fetch(url)
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        tf.extractall(dest.parent / "_py_tmp")
    unpacked = dest.parent / "_py_tmp" / "python"
    if not unpacked.is_dir():
        candidates = [p for p in (dest.parent / "_py_tmp").iterdir() if p.is_dir()]
        unpacked = candidates[0] if candidates else None
    if unpacked is None:
        raise SystemExit("the Python archive did not contain what was expected")
    shutil.move(str(unpacked), str(dest))
    shutil.rmtree(dest.parent / "_py_tmp", ignore_errors=True)


APP_NAME = "STIG Checker"

# macOS: a real application bundle. One icon, one double-click, no terminal
# window, and nothing for the person to read before they can start. The
# payload sits in Contents/Resources exactly as it does on Windows.
APP_LAUNCHER = """#!/bin/bash
HERE="$(cd "$(dirname "$0")/../Resources" && pwd)"
LOG="$HOME/Library/Logs/STIG Checker.log"
mkdir -p "$HOME/Library/Logs"
"$HERE/python/bin/python3" "$HERE/app/run.py" >"$LOG" 2>&1
CODE=$?
if [ $CODE -ne 0 ]; then
  osascript -e 'display dialog "STIG Checker could not start. The details are in Console, under Log Reports, as STIG Checker.log." buttons {"OK"} default button 1 with icon caution with title "STIG Checker"' >/dev/null 2>&1
fi
exit $CODE
"""

INFO_PLIST = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key>            <string>{name}</string>
  <key>CFBundleDisplayName</key>     <string>{name}</string>
  <key>CFBundleExecutable</key>      <string>{name}</string>
  <key>CFBundleIdentifier</key>      <string>io.github.himanshusaxenagithub.stigchecker</string>
  <key>CFBundlePackageType</key>     <string>APPL</string>
  <key>CFBundleShortVersionString</key> <string>0.5.0</string>
  <key>CFBundleVersion</key>         <string>0.5.0</string>
  <key>CFBundleInfoDictionaryVersion</key> <string>6.0</string>
  <key>LSMinimumSystemVersion</key>  <string>11.0</string>
  <key>LSUIElement</key>             <true/>
  <key>NSHighResolutionCapable</key> <true/>
</dict>
</plist>
"""


# -------------------------------------------------------------- build ----

def build(target: str, out_dir: Path, python_url: str | None,
          python_dir: Path | None, make_zip: bool) -> Path:
    name = f"stig-ai-pipeline-{'macos' if target == 'macos' else 'windows'}"
    folder = out_dir / name
    if folder.exists():
        shutil.rmtree(folder)

    # Where the payload and the bundled Python go. On macOS both live inside
    # the .app, so the person sees one application and not a folder of parts.
    if target == "macos":
        bundle = folder / f"{APP_NAME}.app"
        resources = bundle / "Contents" / "Resources"
        macos_dir = bundle / "Contents" / "MacOS"
        macos_dir.mkdir(parents=True)
        app = resources / "app"
        py_dir = resources / "python"
    else:
        program = folder / "program"
        app = program / "app"
        py_dir = program / "python"
    app.mkdir(parents=True)

    log(f"assembling {folder}")
    for item in PAYLOAD:
        source = ROOT / item
        if not source.exists():
            log(f"  skipping {item} (not in this checkout)")
            continue
        shutil.copytree(source, app / item,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".DS_Store"))
        log(f"  copied {item}/")
    for item in EXTRA_FILES:
        if (ROOT / item).exists():
            shutil.copy2(ROOT / item, app / item)
    (app / "run.py").write_text(RUN_PY, encoding="utf-8")

    if python_dir:
        log(f"  using the Python at {python_dir}")
        shutil.copytree(python_dir, py_dir)
    elif target == "windows":
        windows_python(py_dir, python_url or WINDOWS_EMBED)
    else:
        macos_python(py_dir, python_url or macos_python_url())

    if target == "macos":
        (bundle / "Contents" / "Info.plist").write_text(
            INFO_PLIST.format(name=APP_NAME), encoding="utf-8")
        launcher = macos_dir / APP_NAME
        launcher.write_text(APP_LAUNCHER, encoding="utf-8")
        launcher.chmod(launcher.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        # The bundled interpreter must stay executable through the copy.
        for path in (py_dir / "bin").glob("python*"):
            path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        readme = READ_ME_TXT.format(launcher=f"{APP_NAME}", gatekeeper=GATEKEEPER_NOTE)
    else:
        (folder / f"{APP_NAME}.bat").write_text(START_BAT, encoding="utf-8")
        readme = READ_ME_TXT.format(launcher=f"{APP_NAME}.bat", gatekeeper="")
    (folder / "README.txt").write_text(readme, encoding="utf-8")

    size = sum(f.stat().st_size for f in folder.rglob("*") if f.is_file())
    log(f"  {size / 1_048_576:.0f} MB in {sum(1 for _ in folder.rglob('*'))} files")

    if make_zip:
        archive = shutil.make_archive(str(out_dir / name), "zip", root_dir=out_dir, base_dir=name)
        log(f"  wrote {archive}")
    return folder


def main(argv=None) -> int:
    here = {"Darwin": "macos", "Windows": "windows"}.get(platform.system())
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--target", choices=["macos", "windows"], default=here,
                    help="which folder to build (default: this computer)")
    ap.add_argument("--out", default="dist", help="where to put it")
    ap.add_argument("--python-url", help="a specific Python build to bundle")
    ap.add_argument("--python-dir", type=Path,
                    help="a Python you have already unpacked, to build offline")
    ap.add_argument("--no-zip", action="store_true")
    args = ap.parse_args(argv)

    if args.target is None:
        print("error: run this on a Mac or a Windows PC, or pass --target",
              file=sys.stderr)
        return 1
    if args.target != here and not (args.python_url or args.python_dir):
        print(f"note: building a {args.target} folder on {platform.system()}. "
              "The bundled Python must match the target, so pass --python-url "
              "or --python-dir for that platform.", file=sys.stderr)

    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    folder = build(args.target, out_dir, args.python_url, args.python_dir, not args.no_zip)

    launcher = APP_NAME if args.target == "macos" else f"{APP_NAME}.bat"
    print()
    print(f"Done. Open {folder} and double-click {launcher}.")
    print("The .zip beside it is what you send to other people.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
