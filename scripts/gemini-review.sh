#!/bin/sh
# Portable entry point; arguments and stdin remain data.
exec python3 "$(dirname "$0")/review-screenshots.py" "$@"
