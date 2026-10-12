"""ZAP DAST scanner runner."""

import json
import time
from pathlib import Path

import requests

from runners.base import ScannerRunner

ZAP_API_BASE = "http://localhost:8080"  # ZAP container mapped port


class ZapRunner(ScannerRunner):
    """Drives ZAP via its REST API against the running target container."""

    def __init__(self, output_dir: Path, timeout: int = 600):
        super().__init__(output_dir)
        self.timeout = timeout

    def setup(self) -> None:
        """Verify ZAP API is reachable (container should already be up)."""
        for attempt in range(30):
            try:
                r = requests.get(f"{ZAP_API_BASE}/JSON/core/view/version/", timeout=5)
                if r.ok:
                    return
            except requests.ConnectionError:
                pass
            time.sleep(2)
        raise RuntimeError("ZAP API not reachable after 60 seconds")

    def run(self, source_path: Path | None, target_url: str | None) -> None:
        if target_url is None:
            raise ValueError("ZAP requires target_url")

        # Spider the target
        r = requests.get(
            f"{ZAP_API_BASE}/JSON/spider/action/scan/",
            params={"url": target_url},
            timeout=30,
        )
        r.raise_for_status()
        spider_id = r.json()["scan"]

        # Wait for spider to finish
        while True:
            r = requests.get(
                f"{ZAP_API_BASE}/JSON/spider/view/status/",
                params={"scanId": spider_id},
                timeout=10,
            )
            if int(r.json()["status"]) >= 100:
                break
            time.sleep(2)

        # Active scan
        r = requests.get(
            f"{ZAP_API_BASE}/JSON/ascan/action/scan/",
            params={"url": target_url},
            timeout=30,
        )
        r.raise_for_status()
        scan_id = r.json()["scan"]

        # Wait for active scan with timeout
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            r = requests.get(
                f"{ZAP_API_BASE}/JSON/ascan/view/status/",
                params={"scanId": scan_id},
                timeout=10,
            )
            if int(r.json()["status"]) >= 100:
                break
            time.sleep(5)
        else:
            # Timed out, stop the scan and collect what we have
            requests.get(
                f"{ZAP_API_BASE}/JSON/ascan/action/stop/",
                params={"scanId": scan_id},
                timeout=10,
            )

        # Export alerts
        r = requests.get(
            f"{ZAP_API_BASE}/JSON/core/view/alerts/",
            params={"baseurl": target_url},
            timeout=30,
        )
        r.raise_for_status()

        output_file = self.output_dir / "zap.json"
        output_file.write_text(json.dumps(r.json(), indent=2))

    def collect(self) -> Path:
        output_file = self.output_dir / "zap.json"
        if not output_file.exists():
            raise FileNotFoundError(f"No output at {output_file}")
        return output_file
