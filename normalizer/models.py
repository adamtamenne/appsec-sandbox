"""Unified finding model for cross-tool normalization."""

from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# SARIF level -> Severity
SARIF_LEVEL_MAP: dict[str, Severity] = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "note": Severity.LOW,
    "none": Severity.INFO,
}


class LocationType(Enum):
    """Distinguishes file-based (SAST/SCA) from URL-based (DAST) locations."""
    FILE = "file"
    URL = "url"


@dataclass
class Finding:
    cwe: str | None  # e.g. "CWE-79", None if unmapped
    title: str
    severity: Severity
    description: str
    location: str  # file:line for SAST, URL path for DAST
    location_type: LocationType
    tool: str  # which scanner found it
    tool_rule_id: str  # scanner's own rule identifier
    raw: dict = field(default_factory=dict)
    correlated_tools: list[str] = field(default_factory=list)

    @property
    def severity_rank(self) -> int:
        """Numeric rank for sorting (0 = critical, 4 = info)."""
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        return order.index(self.severity)
