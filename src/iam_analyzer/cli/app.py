"""Typer application entry point for iam-analyzer."""

# ruff: noqa: FBT002, PLR0913

from __future__ import annotations

import re
from pathlib import Path  # noqa: TC003 - Typer resolves Path from runtime annotations.
from typing import Annotated

import typer

from iam_analyzer.logging_config import configure_logging
from iam_analyzer.models import FindingStatus, ScanResult, Severity
from iam_analyzer.reporter import render_terminal_report, write_json_report
from iam_analyzer.scanner import AwsSessionManager, ScannerError
from iam_analyzer.scanner import orchestrator as scan_orchestrator

_BENCHMARK = "CIS AWS Foundations Benchmark v5.0.0"
_PROFILE_PATTERN = re.compile(r"^[a-zA-Z0-9_-]+$")
_DEFAULT_REGION = "us-east-1"
_SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}

app = typer.Typer(
    no_args_is_help=True,
    rich_markup_mode="rich",
    help=f"AWS IAM and CloudTrail posture analyzer for {_BENCHMARK}.",
)


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context) -> None:
    """AWS IAM and CloudTrail posture analyzer for CIS AWS Foundations Benchmark v5.0.0."""
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())
        ctx.exit(0)


def _validate_profile(profile: str | None) -> str | None:
    if profile is not None and _PROFILE_PATTERN.fullmatch(profile) is None:
        msg = "Profile must match [a-zA-Z0-9_-]+"
        raise typer.BadParameter(msg)
    return profile


def _has_high_or_critical(scan_result: ScanResult) -> bool:
    return scan_result.summary.CRITICAL > 0 or scan_result.summary.HIGH > 0


def _filter_scan_result(scan_result: ScanResult, severity_filter: Severity | None) -> ScanResult:
    if severity_filter is None:
        return scan_result

    minimum_rank = _SEVERITY_RANK[severity_filter]
    filtered_findings = [
        finding
        for finding in scan_result.findings
        if finding.status is FindingStatus.PASS or _SEVERITY_RANK[finding.severity] <= minimum_rank
    ]
    return scan_result.model_copy(update={"findings": filtered_findings})


def run_scan(*, profile: str | None, region: str) -> ScanResult:
    """Run the currently wired scan flow and return a validated result."""
    session_manager = AwsSessionManager(profile=profile, region=region)
    return scan_orchestrator.run_scan(session_manager, region=region)


@app.command(help=f"Scan an AWS account against {_BENCHMARK}.")
def scan(
    profile: Annotated[
        str | None,
        typer.Option(
            "--profile",
            callback=_validate_profile,
            help="AWS profile name resolved through the standard boto3 credential chain.",
        ),
    ] = None,
    region: Annotated[
        str,
        typer.Option("--region", help="AWS region for regional checks."),
    ] = _DEFAULT_REGION,
    output_file: Annotated[
        Path | None,
        typer.Option("--output-file", help="Write JSON findings to this path."),
    ] = None,
    severity_filter: Annotated[
        Severity | None,
        typer.Option(
            "--severity-filter",
            help="Filter terminal output to this severity and above.",
        ),
    ] = None,
    exit_code: Annotated[
        bool,
        typer.Option("--exit-code", help="Exit non-zero if CRITICAL or HIGH findings are present."),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option("--verbose", help="Enable DEBUG-level structured logging."),
    ] = False,
) -> None:
    """Scan an AWS account using read-only credentials resolved by boto3."""
    configure_logging("DEBUG" if verbose else "INFO")

    try:
        scan_result = run_scan(profile=profile, region=region)
    except ScannerError as error:
        typer.echo(str(error), err=True)
        raise typer.Exit(code=2) from error

    render_terminal_report(_filter_scan_result(scan_result, severity_filter))
    if output_file is not None:
        write_json_report(scan_result, output_file)

    if exit_code and _has_high_or_critical(scan_result):
        raise typer.Exit(code=1)
