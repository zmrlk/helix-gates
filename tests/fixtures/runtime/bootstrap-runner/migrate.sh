#!/bin/sh
if [ "${APP_FORCE_FRESH:-0}" != "1" ]; then
  echo 'ERROR: empty migration ledger; fresh database requires bootstrap' >&2
  exit 2
fi
echo 'bootstrap applied'
