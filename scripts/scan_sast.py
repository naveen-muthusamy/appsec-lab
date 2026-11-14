#!/usr/bin/env python3
"""Run Semgrep, filter findings by MIN_SEVERITY, and write deterministic JSON."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts"
CONFIG = ROOT / "config" / "semgrep.yml"

SEVERITY_ORDER = {"INFO": 1, "LOW": 1, "WARNING": 2, "MEDIUM": 2, "ERROR": 3, "HIGH": 3, "CRITICAL": 4}


def severity_of(result: dict) -> str:
    raw = str(result.get("extra", {}).get("severity", "INFO")).upper()
    return {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}.get(raw, raw)


def main() -> int:
    if shutil.which("semgrep") is None:
        print("ERROR: semgrep is not installed or not in PATH.", file=sys.stderr)
        return 2
    if not CONFIG.is_file():
        print("ERROR: config/semgrep.yml is missing.", file=sys.stderr)
        return 2

    threshold = os.environ.get("MIN_SEVERITY", "HIGH").strip().upper()
    if threshold not in SEVERITY_ORDER:
        print("ERROR: MIN_SEVERITY must be INFO, LOW, MEDIUM, HIGH, or CRITICAL.", file=sys.stderr)
        return 2

    ARTIFACTS.mkdir(exist_ok=True)
    raw_path = ARTIFACTS / "sast.raw.json"
    filtered_path = ARTIFACTS / "sast.json"

    command = [
        "semgrep", "scan",
        "--config", str(CONFIG),
        "--json",
        "--output", str(raw_path),
        "--metrics=off",
        "--quiet",
        ".",
    ]
    result = subprocess.run(command, cwd=ROOT, check=False)
    # Semgrep commonly returns 0 for findings and 2 for scan errors.
    if result.returncode not in (0, 1):
        print(f"ERROR: Semgrep scan failed (exit {result.returncode}).", file=sys.stderr)
        return 2
    if not raw_path.exists():
        print("ERROR: Semgrep did not create its JSON output.", file=sys.stderr)
        return 2

    try:
        data = json.loads(raw_path.read_text(encoding="utf-8"))
        data.pop("time", None)
        raw_path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        results = data.get("results", [])
        kept = [
            item for item in results
            if SEVERITY_ORDER.get(severity_of(item), 1) >= SEVERITY_ORDER[threshold]
        ]
        kept.sort(key=lambda item: (
            -SEVERITY_ORDER.get(severity_of(item), 1),
            str(item.get("path", "")),
            int(item.get("start", {}).get("line", 0)),
            str(item.get("check_id", "")),
        ))
        
        filtered = dict(data)
        filtered.pop("time", None)
        filtered["results"] = kept
        filtered["errors"] = data.get("errors", [])
        filtered["appsec_filter"] = {
            "min_severity": threshold,
            "raw_count": len(results),
            "filtered_count": len(kept),
            "mapping": {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"},
        }
        filtered_path.write_text(
            json.dumps(filtered, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except (OSError, json.JSONDecodeError, AttributeError, TypeError) as exc:
        print(f"ERROR: unable to process Semgrep output: {exc}", file=sys.stderr)
        return 2

    print(f"Semgrep raw findings: {len(results)}")
    print(f"Findings at/above {threshold}: {len(kept)}")
    print(f"Filtered report: {filtered_path.relative_to(ROOT)}")
    return 1 if kept else 0


if __name__ == "__main__":
    sys.exit(main())
