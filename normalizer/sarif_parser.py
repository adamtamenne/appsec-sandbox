"""Generic SARIF parser — handles Semgrep, Trivy, and Gitleaks output."""

import json
from pathlib import Path

from normalizer.models import (
    Finding,
    LocationType,
    Severity,
    SARIF_LEVEL_MAP,
)


def _extract_cwe(result: dict, rule_meta: dict, tool_name: str) -> str | None:
    """Extract CWE from SARIF rule or result properties.

    Semgrep puts CWE on the rule, not the result. Check both.
    """
    for props in [rule_meta.get("properties", {}), result.get("properties", {})]:
        cwe_list = props.get("cwe", [])
        if cwe_list:
            return cwe_list[0].split(":")[0].strip()

        tags = props.get("tags", [])
        for tag in tags:
            if isinstance(tag, str) and tag.upper().startswith("CWE-"):
                return tag.split(":")[0].strip().upper()

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

    # Strip clone working directory prefix
    if "source/" in uri:
        uri = uri.split("source/", 1)[1]

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

            title = (
                rule_meta.get("shortDescription", {}).get("text")
                or rule_meta.get("fullDescription", {}).get("text", "")[:120]
                or rule_id
            )

            description = result.get("message", {}).get("text", "")

            findings.append(
                Finding(
                    cwe=_extract_cwe(result, rule_meta, tool_name),
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
