"""Tests for the normalizer: SARIF parsing, ZAP parsing, and dedup."""

import json
from pathlib import Path
from tempfile import NamedTemporaryFile

from normalizer.dedup import deduplicate
from normalizer.models import Finding, LocationType, Severity
from normalizer.sarif_parser import parse_sarif
from normalizer.zap_parser import parse_zap_json

FIXTURES = Path(__file__).parent / "fixtures"


def _write_tmp_json(data: dict, suffix: str = ".json") -> Path:
    f = NamedTemporaryFile(mode="w", suffix=suffix, delete=False)
    json.dump(data, f)
    f.close()
    return Path(f.name)


# --- SARIF parser tests ---

SAMPLE_SARIF = {
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    "version": "2.1.0",
    "runs": [
        {
            "tool": {
                "driver": {
                    "name": "semgrep",
                    "rules": [
                        {
                            "id": "javascript.express.xss",
                            "shortDescription": {"text": "Cross-site Scripting"},
                            "defaultConfiguration": {"level": "error"},
                            "properties": {},
                        }
                    ],
                }
            },
            "results": [
                {
                    "ruleId": "javascript.express.xss",
                    "level": "error",
                    "message": {"text": "User input in response without sanitization"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "routes/search.ts"},
                                "region": {"startLine": 42},
                            }
                        }
                    ],
                    "properties": {"cwe": ["CWE-79: Cross-site Scripting"]},
                }
            ],
        }
    ],
}


def test_sarif_parser_basic():
    path = _write_tmp_json(SAMPLE_SARIF, suffix=".sarif")
    findings = parse_sarif(path, tool_name="semgrep")
    assert len(findings) == 1
    f = findings[0]
    assert f.cwe == "CWE-79"
    assert f.severity == Severity.HIGH  # error -> high
    assert f.location == "routes/search.ts:42"
    assert f.tool == "semgrep"
    assert f.location_type == LocationType.FILE


def test_sarif_parser_gitleaks_default_cwe():
    """Gitleaks findings should get CWE-798 by default."""
    sarif = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "gitleaks", "rules": []}},
                "results": [
                    {
                        "ruleId": "generic-api-key",
                        "level": "warning",
                        "message": {"text": "API key detected"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": ".env"},
                                    "region": {"startLine": 3},
                                }
                            }
                        ],
                        "properties": {},
                    }
                ],
            }
        ],
    }
    path = _write_tmp_json(sarif, suffix=".sarif")
    findings = parse_sarif(path, tool_name="gitleaks")
    assert findings[0].cwe == "CWE-798"


# --- ZAP parser tests ---

SAMPLE_ZAP = {
    "alerts": [
        {
            "alert": "Cross Site Scripting (Reflected)",
            "name": "Cross Site Scripting (Reflected)",
            "riskcode": "3",
            "cweid": "79",
            "url": "http://target:3000/search?q=test",
            "desc": "Reflected XSS found in search parameter",
            "pluginid": "40012",
        }
    ]
}


def test_zap_parser_basic():
    path = _write_tmp_json(SAMPLE_ZAP)
    findings = parse_zap_json(path)
    assert len(findings) == 1
    f = findings[0]
    assert f.cwe == "CWE-79"
    assert f.severity == Severity.HIGH  # riskcode 3
    assert f.location_type == LocationType.URL
    # Query params should be stripped
    assert "?" not in f.location


# --- Dedup tests ---

def test_dedup_same_cwe_same_location():
    """Same CWE + same location type + same location = merge."""
    f1 = Finding(
        cwe="CWE-79", title="XSS", severity=Severity.HIGH,
        description="", location="routes/search.ts:42",
        location_type=LocationType.FILE, tool="semgrep", tool_rule_id="xss",
    )
    f2 = Finding(
        cwe="CWE-79", title="XSS variant", severity=Severity.MEDIUM,
        description="", location="routes/search.ts:42",
        location_type=LocationType.FILE, tool="trivy", tool_rule_id="xss2",
    )
    deduped, count = deduplicate([f1, f2])
    assert len(deduped) == 1
    assert count == 1
    assert "trivy" in deduped[0].correlated_tools


def test_dedup_same_cwe_different_location_type():
    """Same CWE but file vs URL = correlated, not merged."""
    f1 = Finding(
        cwe="CWE-79", title="XSS source", severity=Severity.HIGH,
        description="", location="routes/search.ts:42",
        location_type=LocationType.FILE, tool="semgrep", tool_rule_id="xss",
    )
    f2 = Finding(
        cwe="CWE-79", title="XSS runtime", severity=Severity.HIGH,
        description="", location="http://target:3000/search",
        location_type=LocationType.URL, tool="zap", tool_rule_id="40012",
    )
    deduped, count = deduplicate([f1, f2])
    assert len(deduped) == 2  # both survive
    assert count == 0  # no merges
    # But they should be cross-correlated
    assert "zap" in deduped[0].correlated_tools or "semgrep" in deduped[1].correlated_tools


def test_dedup_no_cwe_never_merged():
    """Findings without CWE are never merged."""
    f1 = Finding(
        cwe=None, title="Thing 1", severity=Severity.LOW,
        description="", location="a.js:1",
        location_type=LocationType.FILE, tool="semgrep", tool_rule_id="r1",
    )
    f2 = Finding(
        cwe=None, title="Thing 2", severity=Severity.LOW,
        description="", location="a.js:1",
        location_type=LocationType.FILE, tool="trivy", tool_rule_id="r2",
    )
    deduped, count = deduplicate([f1, f2])
    assert len(deduped) == 2
    assert count == 0
