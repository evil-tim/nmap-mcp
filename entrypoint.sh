#!/bin/bash
set -euo pipefail  # Exit on error, undefined vars, pipe failures

INSTALL_DIR="/app"
HOST="${HOST:-0.0.0.0}"

cd "$INSTALL_DIR" || { echo "Failed to cd to $INSTALL_DIR"; exit 1; }

exec uv run fastmcp run main.py:mcp --transport http --host "$HOST" --port 7777