#!/usr/bin/env sh
set -eu
TARGET="${1:-http://host.docker.internal:8000}"
mkdir -p reports
docker run --rm \
  -v "$(pwd)/reports:/zap/wrk/:rw" \
  ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t "$TARGET" -r zap-report.html -J zap-report.json
