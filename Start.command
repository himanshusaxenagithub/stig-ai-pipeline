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
  return 1
}

if ! PY="$(find_python)"; then
  echo "Python 3 is not installed."
  echo "Get it from https://www.python.org/downloads/ then double-click this file again."
  osascript -e 'display dialog "STIG Checker needs Python 3.9 or newer, once.\n\n1. Install it from the page that is about to open.\n2. Double-click Start.command again." buttons {"OK"} default button 1 with title "STIG Checker" with icon caution' >/dev/null 2>&1
  command -v open >/dev/null 2>&1 && open "https://www.python.org/downloads/"
  read -r -p "Press return to close."
  exit 1
fi

echo "Opening in your browser…"
echo "Leave this window open while you use the page; closing it stops the program."
exec "$PY" -m stigui --app
