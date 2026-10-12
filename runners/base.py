"""Abstract base class for scanner runners."""

from abc import ABC, abstractmethod
from pathlib import Path


class ScannerRunner(ABC):
    """Every scanner implements setup/run/collect.

    The orchestrator does not care how a scanner works internally.
    It calls setup(), run(), collect() and moves on.
    """

    def __init__(self, output_dir: Path):
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    @abstractmethod
    def setup(self) -> None:
        """Install or verify the scanner is available."""

    @abstractmethod
    def run(self, source_path: Path | None, target_url: str | None) -> None:
        """Execute the scan.

        source_path: path to cloned repo (used by SAST, SCA, secrets).
        target_url: URL of running container (used by DAST).
        """

    @abstractmethod
    def collect(self) -> Path:
        """Return path to the raw output file (SARIF or JSON)."""
