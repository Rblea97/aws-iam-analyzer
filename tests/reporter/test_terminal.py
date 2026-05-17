"""Tests for Rich terminal report rendering."""

# ruff: noqa: D103, INP001

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import TYPE_CHECKING

import structlog
from rich.console import Console

from iam_analyzer.checks.registry import CONTROL_REGISTRY
from iam_analyzer.logging_config import configure_logging
from iam_analyzer.models import (
    Finding,
    FindingStatus,
    ScanMetadata,
    ScanResult,
    ScanSummary,
    Severity,
)
from iam_analyzer.reporter.terminal import render_terminal_report

if TYPE_CHECKING:
    import pytest


def _finding(
    *,
    control_id: str = "CIS-1.5",
    severity: Severity = Severity.HIGH,
    status: FindingStatus = FindingStatus.FAIL,
    resource_id: str | None = "arn:aws:iam::123456789012:root",
    remediation: str = "Enable MFA for the root user.",
) -> Finding:
    return Finding.model_validate(
        {
            "control_id": control_id,
            "control_title": CONTROL_REGISTRY[control_id].title,
            "severity": severity,
            "status": status,
            "resource_id": resource_id,
            "remediation": remediation,
            "raw_evidence": {"checked": True},
        },
    )


def _scan_result(findings: list[Finding], summary: ScanSummary) -> ScanResult:
    return ScanResult(
        scan_metadata=ScanMetadata(
            account_id="123456789012",
            scan_timestamp=datetime(2026, 5, 17, 22, 30, tzinfo=UTC),
            benchmark="CIS AWS Foundations Benchmark v5.0.0",
            controls_evaluated=("CIS-1.5", "CIS-1.6", "CIS-1.7"),
            duration_ms=125,
        ),
        summary=summary,
        findings=findings,
    )


def _console() -> Console:
    return Console(record=True, force_terminal=False, width=140)


def test_terminal_report_includes_summary_counts() -> None:
    console = _console()
    result = _scan_result(
        [_finding()],
        ScanSummary(CRITICAL=1, HIGH=2, MEDIUM=3, LOW=4, PASS=5),
    )

    render_terminal_report(result, console=console)
    output = console.export_text()

    assert "123456789012" in output
    assert "2026-05-17T22:30:00Z" in output
    assert "Total findings" in output
    assert "15" in output
    for header in ("Control ID", "Severity", "Status", "Resource", "Title"):
        assert header in output
    for label in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "PASS"):
        assert label in output


def test_pass_findings_are_not_mixed_into_failure_table() -> None:
    console = _console()
    result = _scan_result(
        [
            _finding(control_id="CIS-1.5", severity=Severity.HIGH, status=FindingStatus.FAIL),
            _finding(
                control_id="CIS-1.6",
                severity=Severity.LOW,
                status=FindingStatus.PASS,
                resource_id="passed-resource",
                remediation="No remediation required.",
            ),
        ],
        ScanSummary(CRITICAL=0, HIGH=1, MEDIUM=0, LOW=0, PASS=1),
    )

    render_terminal_report(result, console=console)
    output = console.export_text()

    assert "CIS-1.5" in output
    assert "CIS-1.6" not in output
    assert "passed-resource" not in output
    assert "Passing Controls" in output
    assert "PASS findings: 1 (collapsed)" in output


def test_non_passing_findings_are_sorted_by_severity() -> None:
    console = _console()
    result = _scan_result(
        [
            _finding(control_id="CIS-1.14", severity=Severity.LOW),
            _finding(control_id="CIS-1.7", severity=Severity.CRITICAL),
            _finding(control_id="CIS-1.6", severity=Severity.MEDIUM),
            _finding(control_id="CIS-1.10", severity=Severity.HIGH),
        ],
        ScanSummary(CRITICAL=1, HIGH=1, MEDIUM=1, LOW=1, PASS=0),
    )

    render_terminal_report(result, console=console)
    output = console.export_text()

    assert (
        output.index("CRITICAL")
        < output.index("HIGH")
        < output.index("MEDIUM")
        < output.index("LOW")
    )


def test_zero_non_passing_findings_prints_all_controls_passed_panel() -> None:
    console = _console()
    result = _scan_result(
        [_finding(status=FindingStatus.PASS, remediation="No remediation required.")],
        ScanSummary(CRITICAL=0, HIGH=0, MEDIUM=0, LOW=0, PASS=1),
    )

    render_terminal_report(result, console=console)
    output = console.export_text()

    assert "All evaluated controls passed" in output
    assert "Findings requiring attention" not in output
    assert "Passing Controls" in output


def test_aws_derived_text_is_escaped_before_markup_rendering() -> None:
    console = _console()
    result = _scan_result(
        [
            _finding(
                resource_id="[bold]root[/bold]",
            ),
        ],
        ScanSummary(CRITICAL=0, HIGH=1, MEDIUM=0, LOW=0, PASS=0),
    )

    render_terminal_report(result, console=console)
    output = console.export_text()

    assert "[bold]root[/bold]" in output


def test_configure_logging_emits_json_to_stderr_only(capsys: pytest.CaptureFixture[str]) -> None:
    configure_logging("INFO")

    structlog.get_logger("iam_analyzer.test").info("scan_started", account_id="123456789012")
    captured = capsys.readouterr()

    assert captured.out == ""
    event = json.loads(captured.err)
    assert event["event"] == "scan_started"
    assert event["account_id"] == "123456789012"
    assert event["level"] == "info"
    assert event["timestamp"].endswith("Z")
