"""Generic SARIF parser — handles Semgrep, Trivy, and Gitleaks output."""

import json
from pathlib import Path

from normalizer.models import (
    Finding,
    LocationType,
    Severity,
    SARIF_LEVEL_MAP,
)


def _extract_cwe(result: dict, tool_name: str) -> str | None:
    """Extract CWE from a SARIF result. Location varies by tool."""
    props = result.get("properties", {})

    # Semgrep: properties.cwe is a list like ["CWE-79: ..."]
    cwe_list = props.get("cwe", [])
    if cwe_list:
        return cwe_list[0].split(":")[0].strip()

    # Trivy: CWE may appear in properties.tags
    tags = props.get("tags", [])
    for tag in tags:
        if tag.upper().startswith("CWE-"):
            return tag.split(":")[0].strip().upper()

    # Gitleaks: no native CWE mapping — hardcode secrets to CWE-798
    if tool_name == "gitleaks":
        return "CWE-798"

    return None


def _extract_location(result: dict) -> str:
    """Pull file:line from SARIF physicalLocation."""
    locations = result.get("locations", [])
    if not locations:
        return "unknown"

    phys = locations[0].get("physicalLocation", {})
    artifact = phys.get("artifactLocation", {})
    uri = artifact.get("uri", "unknown")

    region = phys.get("region", {})
    line = region.get("startLine")

    if line:
        return f"{uri}:{line}"
    return uri


def parse_sarif(sarif_path: Path, tool_name: str) -> list[Finding]:
    """Parse a SARIF file into a list of Finding objects."""
    with open(sarif_path) as f:
        data = json.load(f)

    findings: list[Finding] = []

    for run in data.get("runs", []):
        rules: dict[str, dict] = {}
        tool_component = run.get("tool", {}).get("driver", {})
        for rule in tool_component.get("rules", []):
            rules[rule["id"]] = rule

        for result in run.get("results", []):
            rule_id = result.get("ruleId", "unknown")
            rule_meta = rules.get(rule_id, {})

            level = result.get("level")
            if not level:
                level = (
                    rule_meta.get("defaultConfiguration", {}).get("level", "warning")
                )
            severity = SARIF_LEVEL_MAP.get(level, Severity.MEDIUM)

            short_desc = rule_meta.get("shortDescription", {})
            title = short_desc.get("text", rule_id)

            description = result.get("message", {}).get("text", "")

            findings.append(
                Finding(
                    cwe=_extract_cwe(result, tool_name),
                    title=title,
                    severity=severity,
                    description=description,
                    location=_extract_location(result),
                    location_type=LocationType.FILE,
                    tool=tool_name,
                    tool_rule_id=rule_id,
                    raw=result,
                )
            )

    return findings
