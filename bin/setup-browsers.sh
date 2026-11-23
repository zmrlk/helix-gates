#!/usr/bin/env bash
# Portable Playwright installation; platform dependencies follow upstream installer.
set -euo pipefail
PW=$(node "$(dirname "$0")/dependencies.cjs" playwright)
node "$(dirname "$PW")/cli.js" install chromium webkit firefox
node "$(dirname "$0")/ux.cjs" engines
