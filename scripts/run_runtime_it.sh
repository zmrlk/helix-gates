#!/bin/sh
set -eu
HELIX_RUNTIME_IT=1 python3 "$(dirname "$0")/../tests/integration/test_runtime_it.py"
HELIX_RUNTIME_IT=1 python3 "$(dirname "$0")/../tests/integration/test_seed_volume_it.py"
