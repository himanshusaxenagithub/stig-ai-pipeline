# Building STIG Checker

Run once on a Mac and once on a Windows PC. Double-click `Build.command` or
`Build.bat` at the top of the project, or:

    python3 packaging/build_portable.py        # macOS
    py packaging\build_portable.py             # Windows

Each run leaves, under `dist/`:

    macos/STIG Checker/            STIG Checker.app + Read me.txt
    STIG-Checker-macOS.zip         the same, to send

    windows/STIG Checker/          STIG Checker.bat + Read me.txt + program/
    STIG-Checker-Windows.zip

The zip is what goes on the releases page. Whoever downloads it unzips it
and double-clicks STIG Checker; a page opens in their browser. No Python, no
installer, no administrator rights.

## What is in it

Plain `.py` files — the same ones that are in this repository — beside a
Python that lives inside the program and touches nothing else on the machine
(python-build-standalone on macOS, the python.org embeddable build on
Windows). Nothing is compiled, packed or obfuscated: a tool whose argument is
"read exactly what this runs" should not arrive as a black box, and packers
attract antivirus false positives, which for a program that spawns PowerShell
would be fatal.

The program starts `stigui` in *app mode* (`--app`): reports and downloads go
to the per-user application folder, a second double-click reopens the page
rather than starting another copy, the page has Quit and Show files buttons,
and the server stops itself after ten minutes with no page open. Anything it
would have printed goes to `stig-checker.log` in that folder.

## The first-open prompt

Unsigned software downloaded from the internet is refused on first open —
macOS 15 and later need Open Anyway in System Settings → Privacy & Security,
older macOS needs right-click → Open, Windows needs More info → Run anyway.
`Read me.txt` beside the program gives those steps. The only way to remove
the prompt is a developer signature:

    python3 packaging/build_portable.py --sign "Developer ID Application: Name (TEAMID)" \
                                        --notarize <notarytool keychain profile>

That signs with the hardened runtime, notarises with `notarytool --wait`, and
staples the ticket. It is written from Apple's documentation and has not yet
been run in this project; read its output the first time. Windows signing
(an Authenticode certificate and `signtool`) is not wired in.

## Offline, or pinning a Python

    python3 packaging/build_portable.py --python-url <url>
    python3 packaging/build_portable.py --python-dir <unpacked folder>

The macOS build is chosen from the latest python-build-standalone release
for this machine's architecture; the Windows build is pinned to the version
in the script.
