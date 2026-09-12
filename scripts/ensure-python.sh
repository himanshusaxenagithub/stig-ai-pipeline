#!/bin/bash
# Download a private CPython if this Mac has none.
# Used by Start.command. Nothing is added to PATH. Nothing needs admin.
set -e
RUNTIME="$HOME/Library/Application Support/STIG Checker/runtime"
if [ -x "$RUNTIME/bin/python3" ]; then
  echo "$RUNTIME/bin/python3"
  exit 0
fi

arch=$(uname -m)
case "$arch" in
  arm64|aarch64) arch=aarch64 ;;
  x86_64) arch=x86_64 ;;
  *) echo "unsupported Mac architecture: $arch" >&2; exit 1 ;;
esac

# Relocatable official build from python-build-standalone (same source the
# portable Release zip uses). Picked by name from the latest release.
api="https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest"
tail="-${arch}-apple-darwin-install_only.tar.gz"
url=$(python3 -c "print('')" 2>/dev/null || true)
# No system python yet — parse the API with python we don't have. Use grep.
json=$(curl -fsSL -A "stig-ai-pipeline" "$api")
url=$(printf '%s' "$json" | grep -o "https://[^"]*cpython-3.12[^"]*${tail}" | head -n 1)
if [ -z "$url" ]; then
  echo "could not find a macOS Python build to download" >&2
  exit 1
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
echo "Downloading a private Python from the official standalone builds…" >&2
curl -fL --progress-bar -o "$tmp/py.tgz" "$url"
mkdir -p "$HOME/Library/Application Support/STIG Checker"
tar -xzf "$tmp/py.tgz" -C "$tmp"
if [ -d "$tmp/python" ]; then
  rm -rf "$RUNTIME"
  mv "$tmp/python" "$RUNTIME"
elif [ -x "$tmp"/*/bin/python3 ]; then
  rm -rf "$RUNTIME"
  mv "$tmp"/*/ "$RUNTIME"
else
  echo "the archive did not contain a python/ folder" >&2
  exit 1
fi
chmod +x "$RUNTIME/bin/python3" "$RUNTIME/bin/python" 2>/dev/null || true
echo "$RUNTIME/bin/python3"
