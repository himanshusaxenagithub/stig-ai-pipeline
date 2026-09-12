#!/bin/bash
# Double-click this to produce the application you hand to other people.
cd "$(dirname "$0")" || exit 1
python3 packaging/build_portable.py || { echo; read -r -p "Press return to close."; exit 1; }
open dist 2>/dev/null
echo
echo "dist/ now holds 'STIG Checker' and a .zip of it."
echo "The .zip is what you send. They unzip it and double-click STIG Checker."
echo
read -r -p "Press return to close this window."
