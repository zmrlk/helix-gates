#!/bin/sh
# Tests never start a real model CLI: scripts/run_tests_parallel.py links agy, codex, grok,
# claude and gemini to this file first in PATH and fails the run when any of them is called.
# The log sits next to the link, so a caller that strips the environment is still recorded.
echo "$(basename "$0") [${HELIX_TEST_GUARD_BATCH:-?}]" >> "$(dirname "$0")/calls.log"
echo "Helix tests: real model CLI $(basename "$0") blocked; patch the caller instead" >&2
exit 1
