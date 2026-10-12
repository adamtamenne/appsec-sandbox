"""AppSec Sandbox CLI — orchestrates the full scan pipeline."""

import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import click

from config import ScanConfig
from normalizer.dedup import deduplicate
from normalizer.models import Finding
from normalizer.sarif_parser import parse_sarif
from normalizer.zap_parser import parse_zap_json
from reporter.html_report import generate_html
from reporter.json_report import generate_json
from runners.gitleaks_runner import GitleaksRunner
from runners.semgrep_runner import SemgrepRunner
from runners.trivy_runner import TrivyRunner
from runners.zap_runner import ZapRunner


def clone_repo(repo_url: str, dest: Path) -> Path:
    """Clone a git repo. Full history (no --depth 1) so Gitleaks can scan history."""
    click.echo(f"Cloning {repo_url}...")
    subprocess.run(
        ["git", "clone", repo_url, str(dest)],
        check=True,
        capture_output=True,
    )
    return dest


def deploy_target(config: ScanConfig) -> str:
    """Bring up the target container and return its internal URL."""
    click.echo("Deploying target in isolated network...")
    subprocess.run(
        ["docker", "compose", "-f", str(config.compose_file), "up", "-d", "--wait"],
        check=True,
        capture_output=True,
        env={
            **dict(__import__("os").environ),
            "TARGET_IMAGE": config.target_image,
            "TARGET_PORT": str(config.target_port),
        },
    )
    return f"http://target:{config.target_port}"


def teardown_target(config: ScanConfig) -> None:
    """Tear down the target containers."""
    click.echo("Tearing down target...")
    subprocess.run(
        ["docker", "compose", "-f", str(config.compose_file), "down", "-v"],
        capture_output=True,
    )


@click.group()
def cli():
    """AppSec Sandbox — automated multi-tool security analysis."""


@cli.command()
@click.argument("target")
@click.option("--image", is_flag=True, help="Target is a Docker image, not a repo URL.")
@click.option("--port", default=3000, help="Port the target app listens on.")
@click.option("--output", "-o", default="reports", help="Output directory for reports.")
@click.option("--skip-dast", is_flag=True, help="Skip ZAP DAST scan (faster, static only).")
def analyze(target: str, image: bool, port: int, output: str, skip_dast: bool):
    """Run the full scan pipeline against TARGET (repo URL or Docker image)."""
    scan_id = str(uuid4())[:8]
    start = time.monotonic()
    output_dir = Path(output) / scan_id
    output_dir.mkdir(parents=True, exist_ok=True)

    config = ScanConfig(
        target_port=port,
        output_dir=output_dir,
    )

    # --- Resolve target ---
    if image:
        config.target_image = target
        source_path = None
    else:
        source_path = output_dir / "source"
        clone_repo(target, source_path)
        # TODO: build image from source or use pre-built target config
        config.target_image = target  # placeholder

    # --- Static scans (no running container needed) ---
    all_findings: list[Finding] = []
    static_runners = [
        ("semgrep", SemgrepRunner(output_dir / "semgrep")),
        ("trivy", TrivyRunner(output_dir / "trivy")),
        ("gitleaks", GitleaksRunner(output_dir / "gitleaks")),
    ]

    for name, runner in static_runners:
        if source_path is None:
            click.echo(f"Skipping {name} (no source path for image-only target)")
            continue
        try:
            click.echo(f"Running {name}...")
            runner.setup()
            runner.run(source_path=source_path, target_url=None)
            raw_output = runner.collect()
            findings = parse_sarif(raw_output, tool_name=name)
            click.echo(f"  {name}: {len(findings)} findings")
            all_findings.extend(findings)
        except Exception as e:
            click.echo(f"  {name} failed: {e}", err=True)

    # --- DAST scan (needs running container) ---
    if not skip_dast:
        try:
            target_url = deploy_target(config)
            zap = ZapRunner(output_dir / "zap")
            click.echo("Running ZAP...")
            zap.setup()
            zap.run(source_path=source_path, target_url=target_url)
            raw_output = zap.collect()
            findings = parse_zap_json(raw_output)
            click.echo(f"  zap: {len(findings)} findings")
            all_findings.extend(findings)
        except Exception as e:
            click.echo(f"  ZAP failed: {e}", err=True)
        finally:
            teardown_target(config)

    # --- Normalize and deduplicate ---
    click.echo(f"Normalizing {len(all_findings)} raw findings...")
    deduped, merge_count = deduplicate(all_findings)
    click.echo(f"  {len(deduped)} unique findings ({merge_count} duplicates merged)")

    # --- Generate reports ---
    elapsed = round(time.monotonic() - start, 1)
    metadata = {
        "scan_id": scan_id,
        "target": target,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": elapsed,
        "tools_run": [name for name, _ in static_runners]
        + (["zap"] if not skip_dast else []),
    }

    json_path = generate_json(deduped, metadata, output_dir / "report.json")
    html_path = generate_html(deduped, metadata, output_dir / "report.html")

    click.echo(f"\nScan complete in {elapsed}s")
    click.echo(f"  JSON: {json_path}")
    click.echo(f"  HTML: {html_path}")


def main():
    cli()


if __name__ == "__main__":
    main()
