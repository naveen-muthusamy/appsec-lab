#!/usr/bin/env python3
"""Run Gitleaks and apply an inspectable baseline.

Exit codes:
  0: scan completed and no new secrets remain after baseline filtering
  1: one or more new secrets remain
  2: scanner/configuration/runtime error
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import hashlib

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts"
CONFIG = ROOT / "config" / "gitleaks.toml"
BASELINE = ROOT / "baseline.json"


def run_gitleaks(output: Path, baseline: bool) -> int:
    command = [
        "gitleaks", "dir", ".",
        "--config", str(CONFIG),
        "--report-format", "json",
        "--report-path", str(output),
        "--exit-code", "0",
        "--no-banner",
    ]
    if baseline:
        command += ["--baseline-path", str(BASELINE)]
    result = subprocess.run(command, cwd=ROOT, check=False)
    return result.returncode


def read_findings(path: Path) -> list:
    if not path.exists() or path.stat().st_size == 0:
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Invalid Gitleaks JSON in {path}: {exc}") from exc
    if not isinstance(data, list):
        raise RuntimeError(f"Expected a JSON array in {path}")
    return data

#-----------------------------------------------------------#

def clean_findings(findings: list) -> list:
    """Hide secrets and add a fingerprint without the line number."""
    for f in findings:
        secret = f.get("Secret", "")
        secret_hash = hashlib.sha256(secret.encode()).hexdigest()[:12]
        f["Fingerprint"] = f'{f["RuleID"]}:{f["File"]}:{secret_hash}'
        f["Secret"] = "REDACTED"
        f["Match"] = "REDACTED"
    findings.sort(key=lambda x: (x["File"], x["StartLine"], x["RuleID"]))
    return findings

#-----------------------------------------------------------#

def load_baseline() -> set:
    """Return accepted fingerprints. Every entry must have a reason."""
    try:
        data = json.loads(BASELINE.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"baseline.json is not valid JSON: {exc}")
    accepted = set()
    for entry in data.get("entries", []):
        if not entry.get("fingerprint") or not entry.get("reason"):
            raise RuntimeError(f"Baseline entry needs 'fingerprint' and 'reason': {entry}")
        accepted.add(entry["fingerprint"])
    return accepted

#----------------------------------------------------------#

def main() -> int:
    if shutil.which("gitleaks") is None:
        print("ERROR: gitleaks is not installed or not in PATH.", file=sys.stderr)
        return 2
    if not CONFIG.is_file() or not BASELINE.is_file():
        print("ERROR: required config/gitleaks.toml or baseline.json is missing.", file=sys.stderr)
        return 2

    ARTIFACTS.mkdir(exist_ok=True)
    raw_path = ARTIFACTS / "secrets.raw.json"
    filtered_path = ARTIFACTS / "secrets.filtered.json"

    try:
        print("Running Gitleaks...")
        rc = run_gitleaks(raw_path, baseline=False)
        if rc not in (0,):
            print(f"ERROR: Gitleaks raw scan failed (exit {rc}).", file=sys.stderr)
            return 2
#-----------------------------------------------------------#
        raw = clean_findings(read_findings(raw_path))
        raw_path.write_text(json.dumps(raw, indent=2) + "\n", encoding="utf-8")

#-----------------------------------------------------------#

#        print("Running Gitleaks with baseline to identify new findings...")
#        rc = run_gitleaks(filtered_path, baseline=True)
#        if rc not in (0,):
#            print(f"ERROR: Gitleaks baseline scan failed (exit {rc}).", file=sys.stderr)
#            return 2
#
#        raw = read_findings(raw_path)
#        filtered = read_findings(filtered_path)
#-----------------------------------------------------------#
        accepted = load_baseline()
        filtered = [f for f in raw if f["Fingerprint"] not in accepted]
        filtered_path.write_text(json.dumps(filtered, indent=2) + "\n", encoding="utf-8")
#-----------------------------------------------------------#
        print(f"Raw findings: {len(raw)}")
        print(f"New findings after baseline: {len(filtered)}")
        return 1 if filtered else 0
    except (OSError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

if __name__ == "__main__":
    sys.exit(main())
