#!/usr/bin/env python3
"""Build a stable Markdown triage report from Gitleaks and Semgrep JSON outputs."""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts"
ORDER = {"CRITICAL": 4, "HIGH": 3, "ERROR": 3, "MEDIUM": 2, "WARNING": 2, "LOW": 1, "INFO": 1}


def load_json(path: Path):
    if not path.exists() or path.stat().st_size == 0:
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    ARTIFACTS.mkdir(exist_ok=True)
    secret_raw = load_json(ARTIFACTS / "secrets.raw.json")
    secret_new = load_json(ARTIFACTS / "secrets.filtered.json")
    sast_data = load_json(ARTIFACTS / "sast.json")

    findings = []
    if isinstance(secret_new, list):
        for item in secret_new:
            findings.append({
                "severity": "HIGH",
                "category": "Secrets",
                "path": item.get("File", "unknown"),
                "line": item.get("StartLine", 0),
                "rule": item.get("RuleID", "gitleaks"),
                "message": item.get("Description", "Potential exposed secret"),
            })

    if isinstance(sast_data, dict):
        for item in sast_data.get("results", []):
            extra = item.get("extra", {})
            raw_sev = str(extra.get("severity", "INFO")).upper()
            sev = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}.get(raw_sev, raw_sev)
            findings.append({
                "severity": sev,
                "category": "SAST",
                "path": item.get("path", "unknown"),
                "line": item.get("start", {}).get("line", 0),
                "rule": item.get("check_id", "semgrep"),
                "message": extra.get("message", "Static analysis finding"),
            })

    findings.sort(key=lambda x: (
        -ORDER.get(x["severity"], 0),
        x["path"],
        int(x["line"] or 0),
        x["rule"],
    ))

    severity_counts = Counter(item["severity"] for item in findings)
    category_counts = Counter(item["category"] for item in findings)
    raw_secret_count = len(secret_raw) if isinstance(secret_raw, list) else 0
    new_secret_count = len(secret_new) if isinstance(secret_new, list) else 0
    suppressed_count = max(raw_secret_count - new_secret_count, 0)

    lines = [
        "# Security Triage Report",
        "",
        "Generated from the latest local scan artifacts. Findings are ordered by severity (descending), then file path, line, and rule ID.",
        "",
        "## Counts by severity",
        "",
    ]
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        lines.append(f"- {sev}: {severity_counts.get(sev, 0)}")
    lines += ["", "## Counts by category", ""]
    for category in sorted(category_counts):
        lines.append(f"- {category}: {category_counts[category]}")
    lines += ["", "## Top 5 findings", ""]

    if findings:
        for index, item in enumerate(findings[:5], start=1):
            lines.append(
                f"{index}. **{item['severity']} — {item['category']}** "
                f"`{item['path']}:{item['line']}` — `{item['rule']}`: "
                f"{item['message'].replace(chr(10), ' ')}"
            )
    else:
        lines.append("No findings at the configured thresholds.")

    lines += [
        "",
        "## Secrets baseline summary",
        "",
        f"- Raw Gitleaks findings: {raw_secret_count}",
        f"- New findings after baseline: {new_secret_count}",
        f"- Findings suppressed by baseline: {suppressed_count}",
        "",
        "## Notes",
        "",
        "- A finding suppressed by the Gitleaks baseline is treated as previously accepted; review `baseline.json` regularly.",
        "- The SAST report includes only findings at or above `MIN_SEVERITY`.",
        "- This report is informational and does not replace manual security review.",
        "",
    ]
    output = ARTIFACTS / "triage.md"
    output.write_text("\n".join(lines), encoding="utf-8")
    print(f"Generated {output.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
