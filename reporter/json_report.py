"""JSON report generator."""

import json
from pathlib import Path

from normalizer.models import Finding, Severity


def generate_json(
    findings: list[Finding], metadata: dict, output_path: Path
) -> Path:
    """Write the structured JSON report."""
    severity_counts = {s.value: 0 for s in Severity}
    for f in findings:
        severity_counts[f.severity.value] += 1

    report = {
        **metadata,
        "summary": {
            "total": len(findings),
            **severity_counts,
            "with_correlation": sum(
                1 for f in findings if f.correlated_tools
            ),
        },
        "findings": [
            {
                "cwe": f.cwe,
                "title": f.title,
                "severity": f.severity.value,
                "location": f.location,
                "location_type": f.location_type.value,
                "tool": f.tool,
                "tool_rule_id": f.tool_rule_id,
                "correlated_tools": f.correlated_tools,
                "description": f.description,
            }
            for f in findings
        ],
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report, indent=2))
    return output_path
