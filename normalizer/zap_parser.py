"""ZAP JSON alert parser — maps ZAP's native format to Finding objects."""

import json
from pathlib import Path
from urllib.parse import urlparse

from normalizer.models import Finding, LocationType, Severity

# ZAP riskcode: 0=Info, 1=Low, 2=Medium, 3=High
ZAP_RISK_MAP: dict[int, Severity] = {
    0: Severity.INFO,
    1: Severity.LOW,
    2: Severity.MEDIUM,
    3: Severity.HIGH,
}


def _normalize_url(url: str) -> str:
    """Strip query params and fragments for dedup. Keep scheme + host + path."""
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"


def parse_zap_json(zap_path: Path) -> list[Finding]:
    """Parse ZAP JSON alerts export into Finding objects."""
    with open(zap_path) as f:
        data = json.load(f)

    alerts = data.get("alerts", [])
    findings: list[Finding] = []

    for alert in alerts:
        risk = int(alert.get("riskcode", 0))
        cwe_id = alert.get("cweid", "")
        cwe = f"CWE-{cwe_id}" if cwe_id and cwe_id != "0" else None

        url = alert.get("url", "unknown")

        findings.append(
            Finding(
                cwe=cwe,
                title=alert.get("name", alert.get("alert", "Unknown")),
                severity=ZAP_RISK_MAP.get(risk, Severity.INFO),
                description=alert.get("desc", ""),
                location=_normalize_url(url),
                location_type=LocationType.URL,
                tool="zap",
                tool_rule_id=str(alert.get("pluginid", "")),
                raw=alert,
            )
        )

    return findings
