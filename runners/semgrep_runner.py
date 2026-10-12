"""Semgrep SAST scanner runner."""

import shutil
import subprocess
from pathlib import Path

from runners.base import ScannerRunner


class SemgrepRunner(ScannerRunner):
    """Runs Semgrep with auto config against source, outputs SARIF."""

    def setup(self) -> None:
        if not shutil.which("semgrep"):
            raise RuntimeError(
                "semgrep not found. Install: pip install semgrep"
            )

    def run(self, source_path: Path | None, target_url: str | None) -> None:
        if source_path is None:
            raise ValueError("Semgrep requires source_path")

        output_file = self.output_dir / "semgrep.sarif"
        result = subprocess.run(
            [
                "semgrep", "scan",
                "--config", "auto",
                "--sarif",
                "--output", str(output_file),
                str(source_path),
            ],
            capture_output=True,
            text=True,
        )
        # Semgrep exits 1 when findings exist, which is expected
        if result.returncode not in (0, 1):
            raise RuntimeError(f"Semgrep failed: {result.stderr}")

    def collect(self) -> Path:
        output_file = self.output_dir / "semgrep.sarif"
        if not output_file.exists():
            raise FileNotFoundError(f"No output at {output_file}")
        return output_file
