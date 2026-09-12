#!/bin/bash
# Double-click this file to open stig-ai-pipeline in your browser.
cd "$(dirname "$0")" || exit 1
if command -v python3 >/dev/null 2>&1; then PY=python3
elif command -v python >/dev/null 2>&1; then PY=python
else
  echo "Python 3 is not installed. Get it from https://www.python.org/downloads/"
  read -r -p "Press return to close."
  exit 1
fi
"$PY" -m stigui
read -r -p "Press return to close."
