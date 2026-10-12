"""Scan configuration."""

from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ScanConfig:
    target_image: str = ""
    target_port: int = 3000
    output_dir: Path = field(default_factory=lambda: Path("reports"))
    compose_file: Path = field(default_factory=lambda: Path("docker-compose.yml"))
    zap_timeout_seconds: int = 600  # 10 min default for active scan
    scanners_enabled: list[str] = field(
        default_factory=lambda: ["semgrep", "trivy", "gitleaks", "zap"]
    )
