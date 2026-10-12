"""Gitleaks secrets scanner runner."""

import shutil
import subprocess
from pathlib import Path

from runners.base import ScannerRunner


class GitleaksRunner(ScannerRunner):
    """Runs Gitleaks against full git history, outputs SARIF."""

    def setup(self) -> None:
        if not shutil.which("gitleaks"):
            raise RuntimeError(
                "gitleaks not found. Install: https://github.com/gitleaks/gitleaks"
            )

    def run(self, source_path: Path | None, target_url: str | None) -> None:
        if source_path is None:
            raise ValueError("Gitleaks requires source_path")

        output_file = self.output_dir / "gitleaks.sarif"
        result = subprocess.run(
            [
                "gitleaks", "detect",
                "--source", str(source_path),
                "--report-format", "sarif",
                "--report-path", str(output_file),
            ],
            capture_output=True,
            text=True,
        )
        # Gitleaks exits 1 when leaks found, which is expected
        if result.returncode not in (0, 1):
            raise RuntimeError(f"Gitleaks failed: {result.stderr}")

    def collect(self) -> Path:
        output_file = self.output_dir / "gitleaks.sarif"
        if not output_file.exists():
            raise FileNotFoundError(f"No output at {output_file}")
        return output_file
