#!/bin/bash
# Same program as Start.command; friendlier name when someone downloads the GitHub ZIP.
cd "$(dirname "$0")" || exit 1
exec bash "./Start.command"
