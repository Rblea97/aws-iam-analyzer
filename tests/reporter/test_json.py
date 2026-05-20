"""Tests for JSON report writing."""

# ruff: noqa: D103, INP001

from __future__ import annotations

import json
import os
import stat
from datetime import UTC, datetime
from pathlib import Path

import pytest

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


def test_write_json_report_temp_file_is_owner_only_before_replace(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    if os.name != "posix":
        pytest.skip("POSIX mode bits are not reliable on this platform")

    output_path = tmp_path / "report.json"
    observed_modes: list[int] = []
    original_replace = os.replace
    original_umask = os.umask(0)

    def replace_after_mode_check(
        source: str | os.PathLike[str],
        destination: str | os.PathLike[str],
    ) -> None:
        observed_modes.append(stat.S_IMODE(Path(source).stat().st_mode))
        original_replace(source, destination)

    try:
        monkeypatch.setattr("iam_analyzer.reporter.json.os.replace", replace_after_mode_check)
        write_json_report(_scan_result(), output_path)
    finally:
        os.umask(original_umask)

    assert observed_modes == [_REPORT_FILE_MODE]
    assert stat.S_IMODE(output_path.stat().st_mode) == _REPORT_FILE_MODE


def test_write_json_report_cleans_temp_file_when_write_fails(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    output_path = tmp_path / "report.json"

    def raise_during_dump(*_args: object, **_kwargs: object) -> None:
        message = "simulated write failure"
        raise OSError(message)

    monkeypatch.setattr("iam_analyzer.reporter.json.json.dump", raise_during_dump)

    with pytest.raises(OSError, match="simulated write failure"):
        write_json_report(_scan_result(), output_path)

    assert not output_path.exists()
    assert not (tmp_path / "report.json.tmp").exists()
