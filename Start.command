#!/bin/bash
# Double-click this file to open stig-ai-pipeline in your browser.
cd "$(dirname "$0")" || exit 1

if [ ! -d "stigui" ]; then
  echo "Keep Start.command inside the unzipped folder, next to stigui."
  read -r -p "Press return to close."
  exit 1
fi

find_python() {
  local c
  for c in python3 python /usr/bin/python3 /usr/local/bin/python3 /opt/homebrew/bin/python3; do
    command -v "$c" >/dev/null 2>&1 && { echo "$c"; return 0; }
  done
  local bundled="$HOME/Library/Application Support/STIG Checker/runtime/bin/python3"
  [ -x "$bundled" ] && { echo "$bundled"; return 0; }
  return 1
}

if ! PY="$(find_python)"; then
  osascript >/dev/null 2>&1 <<'APPLESCRIPT' || true
display dialog "This Mac does not have Python.

STIG Checker can download a private copy (~25 MB). It is not installed system-wide and needs no administrator password." buttons {"Download", "Cancel"} default button 1 with title "STIG Checker" with icon note
if button returned of result is "Cancel" then error number -128
APPLESCRIPT
  if [ $? -ne 0 ]; then exit 1; fi
  echo "Downloading a private Python…"
  if ! PY="$(bash scripts/ensure-python.sh)"; then
    osascript -e 'display dialog "Could not download Python. Install it from python.org, then double-click again." buttons {"OK"} default button 1 with title "STIG Checker" with icon caution' >/dev/null 2>&1
    open "https://www.python.org/downloads/" 2>/dev/null || true
    read -r -p "Press return to close."
    exit 1
  fi
fi

echo "Opening in your browser…"
echo "Leave this window open while you use the page; closing it stops the program."
export PYTHONPATH="$(pwd)"
exec "$PY" -m stigui --app
