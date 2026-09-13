"""Start STIG Checker from this folder. The launchers call this file.

Why it exists: the private Python that Start.bat downloads on a PC with no
Python is python.org's *embeddable* build, and that build ships a
python312._pth file which makes the interpreter ignore PYTHONPATH and stop
adding the current folder to sys.path. `python -m stigui` then fails with
"No module named stigui" even though stigui is right there. Putting this
folder on sys.path by hand, here, works under every interpreter: system,
Homebrew, python-build-standalone, or the embeddable build.

Usage (what the launchers run):

    python run.py --app                       # the double-click program
    python run.py --app --selection selection.json
    python run.py --help                      # everything stigui accepts
"""

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from stigui.__main__ import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
