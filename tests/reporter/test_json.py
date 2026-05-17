"""Tests for JSON report writing."""

# ruff: noqa: D103, INP001

from __future__ import annotations

import json
import os
import stat
from datetime import UTC, datetime
from typing import TYPE_CHECKING

from iam_analyzer.checks.registry import CONTROL_REGISTRY
from iam_analyzer.models import (
    Finding,
    FindingStatus,
    ScanMetadata,
    ScanResult,
    ScanSummary,
    Severity,
)
from iam_analyzer.reporter.json import write_json_report

if TYPE_CHECKING:
    from pathlib import Path

_REPORT_FILE_MODE = 0o600


def _finding() -> Finding:
    return Finding.model_validate(
        {
            "control_id": "CIS-1.5",
            "control_title": CONTROL_REGISTRY["CIS-1.5"].title,
            "severity": Severity.HIGH,
            "status": FindingStatus.FAIL,
            "resource_id": "arn:aws:iam::123456789012:root",
            "remediation": "Enable MFA for the root user.",
            "raw_evidence": {"mfa_enabled": False},
        },
    )


def _scan_result() -> ScanResult:
    return ScanResult(
        scan_metadata=ScanMetadata(
            account_id="123456789012",
            scan_timestamp=datetime(2026, 5, 17, 22, 30, tzinfo=UTC),
            benchmark="CIS AWS Foundations Benchmark v5.0.0",
            controls_evaluated=("CIS-1.5",),
            duration_ms=42,
        ),
        summary=ScanSummary(CRITICAL=0, HIGH=1, MEDIUM=0, LOW=0, PASS=0),
        findings=[_finding()],
    )


def test_write_json_report_uses_required_top_level_shape_and_model_dump(tmp_path: Path) -> None:
    result = _scan_result()
    output_path = tmp_path / "report.json"

    write_json_report(result, output_path)

    report = json.loads(output_path.read_text(encoding="utf-8"))
    assert list(report) == ["findings", "scan_metadata", "summary"]
    assert set(report) == {"scan_metadata", "summary", "findings"}
    assert report == result.model_dump(mode="json")
    assert isinstance(report["findings"][0]["evaluated_at"], str)


def test_write_json_report_replaces_existing_file_without_leaving_temp_file(tmp_path: Path) -> None:
    output_path = tmp_path / "report.json"
    output_path.write_text("stale", encoding="utf-8")

    write_json_report(_scan_result(), output_path)

    assert json.loads(output_path.read_text(encoding="utf-8"))["summary"]["HIGH"] == 1
    assert not list(tmp_path.glob("*.json.tmp"))


def test_write_json_report_sets_owner_only_permissions_when_supported(tmp_path: Path) -> None:
    output_path = tmp_path / "report.json"

    write_json_report(_scan_result(), output_path)

    mode = stat.S_IMODE(output_path.stat().st_mode)
    if os.name == "posix":
        assert mode == _REPORT_FILE_MODE
    else:
        assert output_path.exists()
