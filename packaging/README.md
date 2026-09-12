# Building the portable downloads

Two folders, one per platform, that someone can unpack and double-click.
No Python on their machine, no installer, no administrator rights, no
terminal.

## What you run

On the Mac:

    python3 packaging/build_portable.py

On the Windows PC:

    py packaging\build_portable.py

Each run produces `dist/stig-ai-pipeline-macos/` (or `-windows/`) and a
`.zip` of it. Upload the two zips to a GitHub release.

The build has to happen on the platform it is for, because the bundled
Python is a native binary. There is no cross-building.

## What it puts in the folder

    Start.command / Start.bat     the thing to double-click
    README.txt                    three sentences for the person who opens it
    app/                          this project, unchanged
    python/                       a Python that exists only inside this folder

The code ships as the same `.py` files that are on GitHub. Nothing is
packed, compiled or obfuscated, for two reasons. A tool whose argument is
"you can read exactly what this runs" should not arrive as a black box.
And packers attract antivirus false positives, which for a program that
spawns PowerShell to read the registry would be a serious problem.

No source change was needed to make this work: `app/` has the same shape as
the repository, so `annotations/`, `checkpacks/` and `stigui/app.html` are
found exactly as they are in a checkout.

## Where the Python comes from

* **Windows** — the embeddable distribution from python.org, about 15 MB,
  published for exactly this purpose.
* **macOS** — a relocatable build from
  [python-build-standalone](https://github.com/astral-sh/python-build-standalone),
  which is what modern Python tooling uses for the same job.

Both are downloaded at build time. If you are offline, or want to pin a
specific build, fetch it yourself and pass it in:

    python3 packaging/build_portable.py --python-url <url>
    python3 packaging/build_portable.py --python-dir <unpacked folder>

## Before you publish

Test the folder you just built by double-clicking the launcher, not by
running it from a terminal — the terminal hides the two problems a real
user hits.

**macOS.** A zip downloaded from the internet is quarantined, and a
quarantined `.command` will not open on double-click. The first launch
needs right-click, Open, then Open again. `README.txt` says so. Removing
that step means notarising the build with an Apple Developer account, which
is a cost to decide on separately.

**Windows.** SmartScreen will warn on an unsigned launcher the first few
times: More info, then Run anyway. It settles as more people download it.
Signing removes it and costs money annually.

Neither is a defect. Both are what unsigned open-source software looks like,
and plenty of respected tools ship exactly this way. Just do not be
surprised by them in front of someone who is trying the tool for you.
