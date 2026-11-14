#!/usr/bin/env bash
set -u

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"
mkdir -p artifacts

overall_status=0

echo "[1/3] Running secrets scan (Gitleaks)..."
python3 scripts/scan_secrets.py
secrets_status=$?
if [ "$secrets_status" -eq 2 ]; then
  overall_status=2
elif [ "$secrets_status" -eq 1 ] && [ "$overall_status" -eq 0 ]; then
  overall_status=1
fi

echo "[2/3] Running SAST scan (Semgrep)..."
python3 scripts/scan_sast.py
sast_status=$?
if [ "$sast_status" -eq 2 ]; then
  overall_status=2
elif [ "$sast_status" -eq 1 ] && [ "$overall_status" -eq 0 ]; then
  overall_status=1
fi

echo "[3/3] Generating triage report..."
python3 scripts/triage_report.py
triage_status=$?
if [ "$triage_status" -ne 0 ]; then
  overall_status=2
fi

echo "All stages attempted. Review artifacts/."
exit "$overall_status"
