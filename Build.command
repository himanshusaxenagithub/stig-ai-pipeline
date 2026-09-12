#!/bin/bash
# Double-click this to build the folder you hand to someone else.
# It puts stig-ai-pipeline-macos/ and a .zip of it into dist/.
cd "$(dirname "$0")" || exit 1
python3 packaging/build_portable.py
echo
echo "The zip in dist/ is what you send people. They unzip it and"
echo "double-click Start.command. They do not need Python."
echo
read -r -p "Press return to close this window."
