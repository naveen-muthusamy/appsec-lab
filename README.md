# AppSec Take-Home — Secrets Scanning and Triage

This repository implements Task 1 (Gitleaks secrets scanning with baseline) and Task 3 (triage report).

## Requirements
- Linux or macOS
- Python 3.9+
- Gitleaks 8.21.2 available as `gitleaks`

### Install Gitleaks (Linux x64):

```bash
curl -sSLO https://github.com/gitleaks/gitleaks/releases/download/v8.21.2/gitleaks_8.21.2_linux_x64.tar.gz
tar -xzf gitleaks_8.21.2_linux_x64.tar.gz gitleaks
sudo mv gitleaks /usr/local/bin/
```

macOS: `brew install gitleaks`

### Check availability:

```bash
gitleaks version
python3 --version
```

## One-command execution

From the repository root:

```bash
chmod +x run.sh
./run.sh
```

The command runs the secrets scan and generates `artifacts/triage.md`.

### You can also run individual stages:

```bash
python3 scripts/scan_secrets.py
python3 scripts/triage_report.py
```

### Or use Make:

```bash
make
make secrets
make triage
```

## Outputs

| File | Description |
|---|---|
| `artifacts/secrets.raw.json` | All Gitleaks findings before baseline filtering (secret values redacted) |
| `artifacts/secrets.filtered.json` | New Gitleaks findings after baseline filtering |
| `artifacts/triage.md` | Deterministic summary and top-five triage list |

Generated artifacts are local outputs. They are not committed by default.

## Task 1 — Secrets scanning and baseline

The Gitleaks configuration extends the default rules and explicitly excludes `.git`, dependency directories, virtual environments, Terraform working directories, and generated artifacts.

Gitleaks scans with relative paths, so results are the same on any machine. Secret values are replaced with `REDACTED` in all artifacts.

### Each finding gets a fingerprint:

```
<rule id>:<file path>:<first 12 chars of sha256(secret)>
e.g. aws-access-token:sample/cfg.py:53de5baa315b
```

- No secret is stored, so `baseline.json` is never flagged itself.
- No line number, so moving code up or down does not break the baseline.
- If the secret value changes, the hash changes and it is reported as new.


### Accepting a finding (baseline):

1. Run the scan once and review `artifacts/secrets.raw.json`.
2. Confirm the finding is a genuine, accepted historical finding and that any exposed credential has been rotated.
3. Copy its `Fingerprint` into `baseline.json` and add a `reason`:

```json
{
  "entries": [
    {
      "fingerprint": "aws-access-token:sample/cfg.py:53de5baa315b",
      "reason": "Fake AWS key used only for demo; not a real credential"
    }
  ]
}
```

4. Run `./run.sh` again. Only findings not in the baseline are written to `artifacts/secrets.filtered.json`.

An entry without a `reason` stops the scan with exit code `2`. The script never updates the baseline automatically.

Do not baseline an active credential or a finding that has not been investigated.

## Task 3 — Triage report

`scripts/triage_report.py` reads the secrets artifacts and writes `artifacts/triage.md` with counts by severity and category, the top five findings (ordered by severity, file path, line, rule ID), and a suppressed-vs-new summary. Gitleaks does not assign severity, so all secrets are reported as HIGH.

## Sample data

`sample/` contains **fake** secrets so the scan has something to find. None are real credentials. With the included baseline, `./run.sh` finds 4 secrets: 1 baselined, 3 new, exit code `1`.

## Exit codes

- `0`: completed successfully with no new findings after baseline.
- `1`: completed successfully and found one or more new findings.
- `2`: missing dependency, invalid configuration or baseline, scanner failure, or invalid output.

`run.sh` runs the triage report even when the scan reports findings. Its final exit code is `0` when no new findings remain, `1` when one or more remain, and `2` on error.

Exit codes above are for `./run.sh`. `make` follows its own convention and returns `2` whenever `./run.sh` exits non-zero.

## Tuning choices (submission note)

The starter's baseline copied full Gitleaks findings, including the plaintext secret, so `baseline.json` was itself flagged and the scan could never pass; it also depended on absolute paths and line numbers. I replaced it with a fingerprint (rule + relative path + hash of the secret) plus a required reason, redacted secrets in all artifacts, and scan with relative paths so results match on any machine. Gitleaks uses its default rules with explicit path exclusions for dependency and generated folders.

## Important

Run this assessment against the assessment repository itself or a separate sample project. Never commit real credentials, raw secret values, or sensitive production data. Review generated artifacts before sharing them.
