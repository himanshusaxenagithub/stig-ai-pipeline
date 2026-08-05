#!/bin/bash
# Download the official Apple macOS STIG from DISA (public.cyber.mil).
# Run this ON YOUR MAC (it needs normal internet access).
#
# Usage:  ./scripts/download_stig.sh [15|26]
# With no argument it detects your macOS version with sw_vers.

set -euo pipefail

MAJOR="${1:-}"
if [ -z "$MAJOR" ] && command -v sw_vers >/dev/null 2>&1; then
  MAJOR="$(sw_vers -productVersion | cut -d. -f1)"
  echo "Detected macOS major version: $MAJOR"
fi

if [ "$MAJOR" != "15" ] && [ "$MAJOR" != "26" ]; then
  echo "Usage: $0 [15|26]   (could not auto-detect a supported version)"
  exit 1
fi

BASE="https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip"
# DISA bumps the release number a few times a year; try newest first.
for REL in 12 11 10 9 8 7 6 5 4 3 2 1; do
  FILE="U_Apple_macOS_${MAJOR}_V1R${REL}_STIG.zip"
  URL="$BASE/$FILE"
  echo "Trying $FILE ..."
  if curl -fsL -o "$FILE" "$URL" 2>/dev/null; then
    echo
    echo "Downloaded: $FILE"
    echo "Next: python3 -m stigprep parse $FILE"
    exit 0
  fi
done

echo
echo "Couldn't find the STIG automatically. Download it manually from:"
echo "  https://public.cyber.mil/stigs/downloads/  (search: 'Apple macOS')"
exit 1
