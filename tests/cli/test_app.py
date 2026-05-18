"""Tests for the Typer CLI entry point."""

# ruff: noqa: D103, INP001

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from typer.testing import CliRunner

from iam_analyzer.checks.registry import CONTROL_REGISTRY
from iam_analyzer.cli import app as cli_app
from iam_analyzer.models import (
    Finding,
    FindingStatus,
    ScanMetadata,
    ScanResult,
    ScanSummary,
    Severity,
)

if TYPE_CHECKING:
    import pytest

runner = CliRunner()
_SCANNER_FAILURE_EXIT_CODE = 2
_SCANNER_FAILURE_MESSAGE = "scanner failed"


def _finding(*, severity: Severity = Severity.HIGH) -> Finding:
    return Finding.model_validate(
        {
            "control_id": "CIS-1.5",
            "control_title": CONTROL_REGISTRY["CIS-1.5"].title,
            "severity": severity,
            "status": FindingStatus.FAIL,
            "resource_id": "arn:aws:iam::123456789012:root",
            "remediation": "Remediate CIS-1.5 with AWS IAM root MFA documentation.",
            "raw_evidence": {"mfa_enabled": False},
        },
    )


def _scan_result(*, findings: list[Finding] | None = None) -> ScanResult:
    finding_list = findings or []
    return ScanResult(
        scan_metadata=ScanMetadata(
            account_id="123456789012",
            scan_timestamp=datetime(2026, 5, 18, 16, 0, tzinfo=UTC),
            benchmark="CIS AWS Foundations Benchmark v5.0.0",
            controls_evaluated=("CIS-1.5",),
            duration_ms=50,
        ),
        summary=ScanSummary(
            CRITICAL=sum(1 for finding in finding_list if finding.severity is Severity.CRITICAL),
            HIGH=sum(1 for finding in finding_list if finding.severity is Severity.HIGH),
            MEDIUM=sum(1 for finding in finding_list if finding.severity is Severity.MEDIUM),
            LOW=sum(1 for finding in finding_list if finding.severity is Severity.LOW),
            PASS=sum(1 for finding in finding_list if finding.status is FindingStatus.PASS),
        ),
        findings=finding_list,
    )


def _configure_logging_noop(_log_level: str) -> None:
    return None


def _render_terminal_report_noop(_scan_result: ScanResult) -> None:
    return None


def _run_empty_scan(*, profile: str | None, region: str) -> ScanResult:
    _ = profile, region
    return _scan_result()


def test_scan_help_mentions_cis_benchmark_version() -> None:
    result = runner.invoke(cli_app.app, ["scan", "--help"])

    assert result.exit_code == 0
    assert "CIS AWS Foundations Benchmark v5.0.0" in result.output


def test_scan_rejects_invalid_profile_path_traversal() -> None:
    result = runner.invoke(cli_app.app, ["scan", "--profile", "../bad"])

    assert result.exit_code != 0
    assert "profile" in result.output.lower()


def test_scan_accepts_valid_profile(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str | None, str]] = []
    monkeypatch.setattr(cli_app, "configure_logging", _configure_logging_noop)
    monkeypatch.setattr(cli_app, "render_terminal_report", _render_terminal_report_noop)
    monkeypatch.setattr(
        cli_app,
        "run_scan",
        lambda *, profile, region: calls.append((profile, region)) or _scan_result(),
    )

    result = runner.invoke(cli_app.app, ["scan", "--profile", "audit_profile-1"])

    assert result.exit_code == 0
    assert calls == [("audit_profile-1", "us-east-1")]


def test_scan_exit_code_returns_non_zero_for_high_findings_when_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def run_high_scan(*, profile: str | None, region: str) -> ScanResult:
        _ = profile, region
        return _scan_result(findings=[_finding()])

    monkeypatch.setattr(cli_app, "configure_logging", _configure_logging_noop)
    monkeypatch.setattr(cli_app, "render_terminal_report", _render_terminal_report_noop)
    monkeypatch.setattr(cli_app, "run_scan", run_high_scan)

    result = runner.invoke(cli_app.app, ["scan", "--exit-code"])

    assert result.exit_code == 1


def test_scan_exit_code_returns_non_zero_for_critical_findings_when_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def run_critical_scan(*, profile: str | None, region: str) -> ScanResult:
        _ = profile, region
        return _scan_result(findings=[_finding(severity=Severity.CRITICAL)])

    monkeypatch.setattr(cli_app, "configure_logging", _configure_logging_noop)
    monkeypatch.setattr(cli_app, "render_terminal_report", _render_terminal_report_noop)
    monkeypatch.setattr(cli_app, "run_scan", run_critical_scan)

    result = runner.invoke(cli_app.app, ["scan", "--exit-code"])

    assert result.exit_code == 1


def test_scan_scanner_error_does_not_use_policy_gate_exit_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def run_failed_scan(*, profile: str | None, region: str) -> ScanResult:
        _ = profile, region
        error_message = _SCANNER_FAILURE_MESSAGE
        raise cli_app.ScannerError(error_message)

    monkeypatch.setattr(cli_app, "configure_logging", _configure_logging_noop)
    monkeypatch.setattr(cli_app, "run_scan", run_failed_scan)

    result = runner.invoke(cli_app.app, ["scan"])

    assert result.exit_code == _SCANNER_FAILURE_EXIT_CODE
    assert _SCANNER_FAILURE_MESSAGE in result.output


def test_scan_severity_filter_limits_terminal_result_counts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rendered_results: list[ScanResult] = []

    def render_terminal_report_fake(scan_result: ScanResult) -> None:
        rendered_results.append(scan_result)

    def run_mixed_scan(*, profile: str | None, region: str) -> ScanResult:
        _ = profile, region
        return _scan_result(
            findings=[
                _finding(severity=Severity.CRITICAL),
                _finding(severity=Severity.HIGH),
            ],
        )

    monkeypatch.setattr(cli_app, "configure_logging", _configure_logging_noop)
    monkeypatch.setattr(cli_app, "render_terminal_report", render_terminal_report_fake)
    monkeypatch.setattr(cli_app, "run_scan", run_mixed_scan)

    result = runner.invoke(cli_app.app, ["scan", "--severity-filter", "CRITICAL"])

    assert result.exit_code == 0
    assert len(rendered_results[0].findings) == 1
    assert rendered_results[0].summary.CRITICAL == 1
    assert rendered_results[0].summary.HIGH == 0


def test_scan_output_file_invokes_json_reporter(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    output_path = tmp_path / "findings.json"
    written_paths: list[Path] = []

    def write_json_report_fake(_scan_result: ScanResult, path: str | Path) -> Path:
        report_path = Path(path)
        written_paths.append(report_path)
        return report_path

    monkeypatch.setattr(cli_app, "configure_logging", _configure_logging_noop)
    monkeypatch.setattr(cli_app, "render_terminal_report", _render_terminal_report_noop)
    monkeypatch.setattr(cli_app, "run_scan", _run_empty_scan)
    monkeypatch.setattr(
        cli_app,
        "write_json_report",
        write_json_report_fake,
    )

    result = runner.invoke(cli_app.app, ["scan", "--output-file", str(output_path)])

    assert result.exit_code == 0
    assert written_paths == [output_path]


def test_scan_verbose_configures_debug_logging(monkeypatch: pytest.MonkeyPatch) -> None:
    configured_levels: list[str] = []
    monkeypatch.setattr(cli_app, "configure_logging", configured_levels.append)
    monkeypatch.setattr(cli_app, "render_terminal_report", _render_terminal_report_noop)
    monkeypatch.setattr(cli_app, "run_scan", _run_empty_scan)

    result = runner.invoke(cli_app.app, ["scan", "--verbose"])

    assert result.exit_code == 0
    assert configured_levels == ["DEBUG"]
