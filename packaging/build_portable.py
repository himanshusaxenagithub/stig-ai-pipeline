"""Build the double-click program: STIG Checker, for a Mac and for a Windows PC.

    python3 packaging/build_portable.py          # or double-click Build.command

Run it on a Mac to get the Mac version and on a Windows PC to get the
Windows version. Each run leaves two things in dist/:

    dist/macos/STIG Checker/          the program, ready to double-click
    dist/STIG-Checker-macOS.zip       the same thing, ready to send

    dist/windows/STIG Checker/        STIG Checker.bat + program/
    dist/STIG-Checker-Windows.zip

The person who receives the zip unzips it and double-clicks STIG Checker.
A page opens in their browser. They do not need Python, an installer,
administrator rights, or a terminal.

What is inside:

* macOS — a real application bundle. Contents/MacOS/STIG Checker is a
  short shell script; Contents/Resources holds the project as plain .py
  files and a Python of its own from the python-build-standalone project.
* Windows — STIG Checker.bat starts program/python/pythonw.exe on
  program/app/run.py. The Python is the embeddable build from python.org.

Nothing is packed, compiled or obfuscated. The code ships as the same .py
files that are on GitHub, because a tool whose argument is "you can read
exactly what this runs" should not arrive as a black box. It also avoids
the antivirus false positives that packers attract, which for a program
that spawns PowerShell would be a serious problem.

What is not inside: a developer signature. Without one, macOS 15 and
later refuse the first launch until the person clicks Open Anyway in
System Settings, and Windows shows a SmartScreen warning. The read-me
that ships beside the program gives those steps exactly. A signature
removes both prompts; pass --sign and --notarize on a Mac with an Apple
Developer ID and the build signs, notarises and staples the bundle.
Those two steps are written from Apple's documentation and have not yet
been exercised here.
"""

from __future__ import annotations

import argparse
import io
import json
import math
import os
import platform
import shutil
import stat
import struct
import subprocess
import sys
import tarfile
import urllib.request
import zipfile
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

APP_NAME = "STIG Checker"
VERSION = "0.5.0"
BUNDLE_ID = "io.github.himanshusaxenagithub.stigchecker"

# Everything the program needs at runtime, copied verbatim.
PAYLOAD = ["stigprep", "stigscan", "stigui", "annotations", "checkpacks", "skills"]
EXTRA_FILES = ["LICENSE", "README.md", "CHANGELOG.md"]

PY_VERSION = "3.12.7"
WINDOWS_EMBED = (f"https://www.python.org/ftp/python/{PY_VERSION}/"
                 f"python-{PY_VERSION}-embed-amd64.zip")
PBS_LATEST = ("https://api.github.com/repos/astral-sh/python-build-standalone/"
              "releases/latest")

RUN_PY = '''"""Start STIG Checker. Kept tiny on purpose.

The program ships its own Python, which knows nothing about this folder,
so this file puts the folder it lives in on the import path and hands
over to the page in application mode. Everything it imports is a plain
.py file beside it.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from stigui.__main__ import main  # noqa: E402

raise SystemExit(main(["--app"] + sys.argv[1:]))
'''

# macOS: what the bundle runs when it is double-clicked. It has no terminal,
# so anything Python cannot say for itself is written to a log and, if the
# start fails outright, said in a dialog.
APP_LAUNCHER = '''#!/bin/bash
HERE="$(cd "$(dirname "$0")/../Resources" && pwd)"
DATA="$HOME/Library/Application Support/STIG Checker"
mkdir -p "$DATA"
"$HERE/python/bin/python3" "$HERE/app/run.py" >>"$DATA/launcher.log" 2>&1
CODE=$?
if [ $CODE -ne 0 ]; then
  osascript -e 'display dialog "STIG Checker could not start. The reason is in stig-checker.log and launcher.log, in your Library folder under Application Support > STIG Checker." buttons {"OK"} default button 1 with icon caution with title "STIG Checker"' >/dev/null 2>&1
fi
exit $CODE
'''

INFO_PLIST = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key>                  <string>{name}</string>
  <key>CFBundleDisplayName</key>           <string>{name}</string>
  <key>CFBundleExecutable</key>            <string>{name}</string>
  <key>CFBundleIconFile</key>              <string>{name}.icns</string>
  <key>CFBundleIdentifier</key>            <string>{bundle_id}</string>
  <key>CFBundlePackageType</key>           <string>APPL</string>
  <key>CFBundleShortVersionString</key>    <string>{version}</string>
  <key>CFBundleVersion</key>               <string>{version}</string>
  <key>CFBundleInfoDictionaryVersion</key> <string>6.0</string>
  <key>LSMinimumSystemVersion</key>        <string>11.0</string>
  <key>LSUIElement</key>                   <true/>
  <key>NSHighResolutionCapable</key>       <true/>
  <key>NSHumanReadableCopyright</key>      <string>MIT licence</string>
</dict>
</plist>
'''

# Windows: pythonw so no console window stays on screen. The page opens in
# the browser; the Quit button on it stops the program.
START_BAT = '''@echo off
REM Double-click this. STIG Checker opens in your browser.
cd /d "%~dp0"
if exist "program\\python\\pythonw.exe" (
  start "" "program\\python\\pythonw.exe" "program\\app\\run.py"
) else (
  start "" "program\\python\\python.exe" "program\\app\\run.py"
)
'''

READ_ME_MAC = '''STIG Checker
============

Double-click STIG Checker. A page opens in your browser.

The first time only, macOS will refuse, because this program was
downloaded from the internet and is not signed with an Apple developer
certificate. This is what to do. It takes about thirty seconds.

  macOS 15 (Sequoia) or newer, including macOS 26:

    1. Double-click STIG Checker. A box says it was not opened. Click Done.
    2. Open System Settings, then Privacy & Security.
    3. Scroll down. Next to "STIG Checker was blocked", click Open Anyway.
    4. Enter your password or use Touch ID, then click Open Anyway again.
    5. From now on it opens with a double-click.

  macOS 14 or older:

    1. Right-click (or Control-click) STIG Checker and choose Open.
    2. Click Open in the box that appears. From now on it opens normally.

What it does
------------

Pick MacBook, and it downloads the official Department of Defense
security guide for macOS, explains every one of its rules in plain
English, shows you the exact command each check would run before
anything runs, and only runs the checks you approve under your own name.

Nothing is installed and nothing leaves this computer. Your reports are
saved in your Library folder under Application Support > STIG Checker;
the Show files button on the page opens that folder. To remove the
program, drag it to the Trash.

The program is ordinary Python files, not a compiled binary. Right-click
STIG Checker, choose Show Package Contents, and look in
Contents/Resources/app. You are meant to be able to read them.

MIT licence. https://github.com/himanshusaxenagithub/stig-ai-pipeline
'''

READ_ME_WIN = '''STIG Checker
============

Double-click "STIG Checker". A page opens in your browser.

The first time only, Windows may show "Windows protected your PC",
because this program was downloaded from the internet and is not signed
with a certificate. Click "More info", then "Run anyway". After that it
opens normally.

What it does
------------

Pick Windows PC, and it downloads the official Department of Defense
security guide for Windows 11, explains every one of its rules in plain
English, shows you the exact command each check would run before
anything runs, and only runs the checks you approve under your own name.

Nothing is installed and nothing leaves this computer. Your reports are
saved under your user folder in AppData\\Local\\STIG Checker; the Show
files button on the page opens that folder. To remove the program,
delete this folder.

The program is ordinary Python files, not a compiled binary. They are in
program\\app. You are meant to be able to read them.

MIT licence. https://github.com/himanshusaxenagithub/stig-ai-pipeline
'''


def log(message: str) -> None:
    print(message, flush=True)


def fetch(url: str) -> bytes:
    log(f"  downloading {url}")
    request = urllib.request.Request(url, headers={"User-Agent": "stig-ai-pipeline build"})
    with urllib.request.urlopen(request, timeout=180) as response:
        return response.read()


# --------------------------------------------------------------- icon ----
#
# An icon, so the thing on the desktop looks like a program and not a
# folder. Drawn here rather than shipped as a file so the build has no
# binary inputs and no image library: a navy rounded square with a white
# tick, written as PNGs inside an .icns container.

def _png(size: int, pixels: list[bytes]) -> bytes:
    def chunk(kind: bytes, body: bytes) -> bytes:
        return (struct.pack(">I", len(body)) + kind + body
                + struct.pack(">I", zlib.crc32(kind + body) & 0xFFFFFFFF))
    raw = b"".join(b"\x00" + row for row in pixels)
    return (b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 9))
            + chunk(b"IEND", b""))


def _seg_dist(px, py, ax, ay, bx, by) -> float:
    vx, vy = bx - ax, by - ay
    t = max(0.0, min(1.0, ((px - ax) * vx + (py - ay) * vy) / (vx * vx + vy * vy)))
    return math.hypot(px - (ax + t * vx), py - (ay + t * vy))


def icon_png(size: int) -> bytes:
    s = size
    radius = s * 0.22
    navy = (0x16, 0x24, 0x3B)
    # the tick: two strokes, proportions of the canvas
    a = (0.27 * s, 0.53 * s)
    b = (0.44 * s, 0.70 * s)
    c = (0.74 * s, 0.33 * s)
    width = 0.075 * s
    rows = []
    for y in range(s):
        row = bytearray()
        for x in range(s):
            px, py = x + 0.5, y + 0.5
            # rounded-square coverage
            dx = max(abs(px - s / 2) - (s / 2 - radius), 0.0)
            dy = max(abs(py - s / 2) - (s / 2 - radius), 0.0)
            edge = math.hypot(dx, dy) - radius
            cover = max(0.0, min(1.0, 0.5 - edge))
            if cover <= 0:
                row += b"\x00\x00\x00\x00"
                continue
            d = min(_seg_dist(px, py, *a, *b), _seg_dist(px, py, *b, *c))
            tick = max(0.0, min(1.0, width - d + 0.5))
            r = int(navy[0] + (255 - navy[0]) * tick)
            g = int(navy[1] + (255 - navy[1]) * tick)
            bl = int(navy[2] + (255 - navy[2]) * tick)
            row += bytes((r, g, bl, int(255 * cover)))
        rows.append(bytes(row))
    return _png(s, rows)


def icns() -> bytes:
    kinds = {16: b"icp4", 32: b"icp5", 64: b"icp6", 128: b"ic07",
             256: b"ic08", 512: b"ic09", 1024: b"ic10"}
    parts = []
    for size, kind in kinds.items():
        png = icon_png(size)
        parts.append(kind + struct.pack(">I", 8 + len(png)) + png)
    body = b"".join(parts)
    return b"icns" + struct.pack(">I", 8 + len(body)) + body


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
    tmp = dest.parent / "_py_tmp"
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        tf.extractall(tmp)
    unpacked = tmp / "python"
    if not unpacked.is_dir():
        candidates = [p for p in tmp.iterdir() if p.is_dir()]
        unpacked = candidates[0] if candidates else None
    if unpacked is None:
        raise SystemExit("the Python archive did not contain what was expected")
    shutil.move(str(unpacked), str(dest))
    shutil.rmtree(tmp, ignore_errors=True)


# --------------------------------------------------------------- zip ----

def zip_dir(folder: Path, archive: Path) -> None:
    """Zip *folder* so that it unpacks to one folder of the same name.

    Written by hand rather than shutil.make_archive so that file modes
    survive (the launcher and the interpreter must stay executable) and
    the entries are in a stable order.
    """
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
            info.external_attr = (path.stat().st_mode & 0xFFFF) << 16
            with path.open("rb") as fh:
                zf.writestr(info, fh.read())


# ------------------------------------------------------------- build ----

def copy_payload(app: Path) -> None:
    app.mkdir(parents=True)
    for item in PAYLOAD:
        source = ROOT / item
        if not source.exists():
            log(f"  skipping {item} (not in this checkout)")
            continue
        shutil.copytree(source, app / item,
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", ".DS_Store",
                                                      "stig-work", "*.ai-cache.json.tmp"))
        log(f"  copied {item}/")
    for item in EXTRA_FILES:
        if (ROOT / item).exists():
            shutil.copy2(ROOT / item, app / item)
    (app / "run.py").write_text(RUN_PY, encoding="utf-8")


def _executable(path: Path) -> None:
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def build_macos(out_dir: Path, python_url: str | None, python_dir: Path | None) -> tuple[Path, Path]:
    folder = out_dir / "macos" / APP_NAME
    if folder.parent.exists():
        shutil.rmtree(folder.parent)
    bundle = folder / f"{APP_NAME}.app"
    contents = bundle / "Contents"
    resources = contents / "Resources"
    (contents / "MacOS").mkdir(parents=True)
    resources.mkdir()

    log(f"assembling {bundle}")
    copy_payload(resources / "app")

    py_dir = resources / "python"
    if python_dir:
        log(f"  using the Python at {python_dir}")
        shutil.copytree(python_dir, py_dir, ignore_dangling_symlinks=True)
    else:
        macos_python(py_dir, python_url or macos_python_url())
    for path in (py_dir / "bin").glob("python*"):
        if path.is_file():
            _executable(path)

    (contents / "Info.plist").write_text(
        INFO_PLIST.format(name=APP_NAME, bundle_id=BUNDLE_ID, version=VERSION), encoding="utf-8")
    launcher = contents / "MacOS" / APP_NAME
    launcher.write_text(APP_LAUNCHER, encoding="utf-8")
    _executable(launcher)
    (resources / f"{APP_NAME}.icns").write_bytes(icns())
    log("  drew the icon")
    (folder / "Read me.txt").write_text(READ_ME_MAC, encoding="utf-8")

    archive = out_dir / "STIG-Checker-macOS.zip"
    return folder, archive


def build_windows(out_dir: Path, python_url: str | None, python_dir: Path | None) -> tuple[Path, Path]:
    folder = out_dir / "windows" / APP_NAME
    if folder.parent.exists():
        shutil.rmtree(folder.parent)
    program = folder / "program"
    log(f"assembling {folder}")
    copy_payload(program / "app")

    py_dir = program / "python"
    if python_dir:
        log(f"  using the Python at {python_dir}")
        shutil.copytree(python_dir, py_dir)
    else:
        windows_python(py_dir, python_url or WINDOWS_EMBED)

    (folder / f"{APP_NAME}.bat").write_text(START_BAT, encoding="utf-8")
    (folder / "Read me.txt").write_text(READ_ME_WIN, encoding="utf-8")
    archive = out_dir / "STIG-Checker-Windows.zip"
    return folder, archive


def sign_and_notarize(bundle: Path, archive: Path, identity: str | None, profile: str | None) -> None:
    """Sign, and optionally notarise and staple, a macOS bundle.

    Requires an Apple Developer ID. Written from Apple's documented
    commands; not yet exercised in this project — read the output.
    """
    if not identity:
        return
    entitlements = bundle.parent / "entitlements.plist"
    entitlements.write_text('''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>com.apple.security.cs.allow-unsigned-executable-memory</key><true/>
  <key>com.apple.security.cs.disable-library-validation</key><true/>
</dict></plist>
''', encoding="utf-8")
    log(f"  signing with {identity}")
    subprocess.run(["codesign", "--force", "--deep", "--options", "runtime", "--timestamp",
                    "--entitlements", str(entitlements), "--sign", identity, str(bundle)], check=True)
    subprocess.run(["codesign", "--verify", "--deep", "--strict", str(bundle)], check=True)
    if not profile:
        return
    log("  notarising (this waits for Apple)")
    zip_dir(bundle.parent, archive)
    subprocess.run(["xcrun", "notarytool", "submit", str(archive),
                    "--keychain-profile", profile, "--wait"], check=True)
    subprocess.run(["xcrun", "stapler", "staple", str(bundle)], check=True)


def build(target: str, out_dir: Path, python_url: str | None, python_dir: Path | None,
          make_zip: bool, sign: str | None, notarize: str | None) -> tuple[Path, Path | None]:
    if target == "macos":
        folder, archive = build_macos(out_dir, python_url, python_dir)
        sign_and_notarize(folder / f"{APP_NAME}.app", archive, sign, notarize)
    else:
        folder, archive = build_windows(out_dir, python_url, python_dir)

    size = sum(f.stat().st_size for f in folder.rglob("*") if f.is_file())
    log(f"  {size / 1_048_576:.0f} MB in {sum(1 for _ in folder.rglob('*'))} files")

    if make_zip:
        zip_dir(folder, archive)
        log(f"  wrote {archive}  ({archive.stat().st_size / 1_048_576:.0f} MB)")
        return folder, archive
    return folder, None


def main(argv=None) -> int:
    here = {"Darwin": "macos", "Windows": "windows"}.get(platform.system())
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--target", choices=["macos", "windows"], default=here,
                    help="which program to build (default: this computer's)")
    ap.add_argument("--out", default="dist", help="where to put it")
    ap.add_argument("--python-url", help="a specific Python build to bundle")
    ap.add_argument("--python-dir", type=Path,
                    help="a Python you have already unpacked, to build offline")
    ap.add_argument("--no-zip", action="store_true")
    ap.add_argument("--sign", metavar="IDENTITY",
                    help='macOS: codesign with this identity, e.g. "Developer ID Application: Name (TEAMID)"')
    ap.add_argument("--notarize", metavar="KEYCHAIN_PROFILE",
                    help="macOS: also notarise with notarytool using this keychain profile, and staple")
    args = ap.parse_args(argv)

    if args.target is None:
        print("error: run this on a Mac or a Windows PC, or pass --target", file=sys.stderr)
        return 1
    if args.target != here and not (args.python_url or args.python_dir):
        print(f"note: building the {args.target} program on {platform.system()}. "
              "The bundled Python must match the target, so pass --python-url "
              "or --python-dir for that platform.", file=sys.stderr)

    out_dir = Path(args.out).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    folder, archive = build(args.target, out_dir, args.python_url, args.python_dir,
                            not args.no_zip, args.sign, args.notarize)

    print()
    print(f"Done. Open {folder} and double-click {APP_NAME}.")
    if archive:
        print(f"Send people {archive.name}. They unzip it and double-click {APP_NAME}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
