# AppSec Sandbox

Automated application security analysis pipeline that orchestrates SAST, SCA, secrets detection, and DAST scanning against containerized targets, normalizes findings into a CWE-keyed model, and deduplicates across tools.

## Architecture

```
appsec-sandbox
├── Target Deploy
│   └── Clone repo or start container
├── Scanners
│   ├── Semgrep   (SAST)
│   ├── Trivy     (SCA)
│   ├── Gitleaks  (Secrets)
│   └── ZAP       (DAST)
├── Normalizer
│   ├── SARIF/JSON parsing
│   ├── Unified CWE model
│   └── Cross-tool dedup
└── Reporter
    ├── HTML report
    └── JSON report
```

Static scanners run against cloned source. ZAP runs against the live container in an isolated Docker network. The normalizer parses each tool's output format, maps to a unified `Finding` model keyed on CWE, and deduplicates across tools so the same vulnerability reported by multiple scanners appears once with all sources cited.

## Prerequisites

- Python 3.11+
- Docker with Compose v2
- Scanner tools: `semgrep`, `trivy`, `gitleaks` (ZAP runs as a container)

## Quick Start

```bash
# Install
pip install -e .

# Run against OWASP Juice Shop (static only, no Docker needed)
git clone https://github.com/juice-shop/juice-shop.git /tmp/juice-shop
appsec-sandbox analyze /tmp/juice-shop --skip-dast

# Full scan with DAST (needs Docker)
appsec-sandbox analyze https://github.com/juice-shop/juice-shop.git

# Reports land in reports/<scan-id>/
```

## What the Normalizer Does

Each scanner emits its own format. The normalizer handles the differences:

| Scanner   | Class   | Output Format | CWE Source                          |
|-----------|---------|---------------|-------------------------------------|
| Semgrep   | SAST    | SARIF         | `properties.cwe`                    |
| Trivy     | SCA     | SARIF         | `properties.tags`                   |
| Gitleaks  | Secrets | SARIF         | Hardcoded `CWE-798`                 |
| ZAP       | DAST    | Custom JSON   | `alert.cweid`                       |

**Deduplication rules:**
- Same CWE + same location type + same location = **merged** (one finding, both tools cited)
- Same CWE + different location types (source file vs runtime URL) = **correlated** (both survive, cross-referenced)
- No CWE = **never merged** (no reliable key)

## Sample Output

```
$ appsec-sandbox analyze /tmp/juice-shop --skip-dast
Cloning...
Running semgrep...
  semgrep: 23 findings
Running trivy...
  trivy: 41 findings
Running gitleaks...
  gitleaks: 3 findings
Normalizing 67 raw findings...
  58 unique findings (9 duplicates merged)

Scan complete in 34.2s
  JSON: reports/a1b2c3d4/report.json
  HTML: reports/a1b2c3d4/report.html
```

## Running Tests

```bash
pip install pytest
pytest tests/ -v
```

## Project Structure

```
appsec-sandbox/
├── cli.py                  # entry point and orchestrator
├── config.py               # scan parameters
├── docker-compose.yml      # isolated scan network
├── runners/
│   ├── base.py             # ScannerRunner ABC
│   ├── semgrep_runner.py   # SAST
│   ├── trivy_runner.py     # SCA
│   ├── gitleaks_runner.py  # Secrets
│   └── zap_runner.py       # DAST
├── normalizer/
│   ├── models.py           # Finding dataclass
│   ├── sarif_parser.py     # Generic SARIF → Finding
│   ├── zap_parser.py       # ZAP JSON → Finding
│   └── dedup.py            # Cross-tool dedup + correlation
├── reporter/
│   ├── json_report.py      # Structured JSON output
│   └── html_report.py      # Self-contained HTML report
├── targets/                # Pre-built target configs
└── tests/
```
