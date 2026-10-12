"""Trivy SCA scanner runner."""

import shutil
import subprocess
from pathlib import Path

from runners.base import ScannerRunner


class TrivyRunner(ScannerRunner):
    """Runs Trivy filesystem scan against source, outputs SARIF."""

    def setup(self) -> None:
        if not shutil.which("trivy"):
            raise RuntimeError(
                "trivy not found. Install: https://aquasecurity.github.io/trivy/"
            )

    def run(self, source_path: Path | None, target_url: str | None) -> None:
        if source_path is None:
            raise ValueError("Trivy requires source_path")

        output_file = self.output_dir / "trivy.sarif"
        result = subprocess.run(
            [
                "trivy", "fs",
                "--format", "sarif",
                "--output", str(output_file),
                str(source_path),
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"Trivy failed: {result.stderr}")

    def collect(self) -> Path:
        output_file = self.output_dir / "trivy.sarif"
        if not output_file.exists():
            raise FileNotFoundError(f"No output at {output_file}")
        return output_file
