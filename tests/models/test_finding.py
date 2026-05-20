"""Tests for validated finding and scan result models."""

# ruff: noqa: D103, INP001

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from iam_analyzer.checks.registry import (
    CANDIDATE_CONTROL_IDS,
    CONTROL_REGISTRY,
    ENTERPRISE_HARDENING_CONTROL_IDS,
    STRICT_CIS_CONTROL_IDS,
    ControlMetadata,
)
from iam_analyzer.models import (
    Finding,
    FindingStatus,
    ScanMetadata,
    ScanResult,
    ScanSummary,
    Severity,
)


def valid_finding_data(**overrides: object) -> dict[str, object]:
    control_id = str(overrides.get("control_id", "CIS-1.5"))
    data: dict[str, object] = {
        "control_id": control_id,
        "control_title": CONTROL_REGISTRY.get(
            control_id,
            CONTROL_REGISTRY["CIS-1.5"],
        ).title,
        "severity": Severity.HIGH,
        "status": FindingStatus.FAIL,
        "resource_id": "arn:aws:iam::123456789012:root",
        "remediation": "Enable MFA for the root user.",
        "raw_evidence": {"mfa_enabled": False},
    }
    data.update(overrides)
    return data


def test_unknown_control_ids_are_rejected() -> None:
    with pytest.raises(ValidationError, match="Unknown control_id"):
        Finding.model_validate(valid_finding_data(control_id="CIS-9.99"))


@pytest.mark.parametrize("remediation", ["", "   "])
def test_empty_remediation_is_rejected(remediation: str) -> None:
    with pytest.raises(ValidationError):
        Finding.model_validate(valid_finding_data(remediation=remediation))


def test_missing_remediation_is_rejected() -> None:
    data = valid_finding_data()
    del data["remediation"]

    with pytest.raises(ValidationError):
        Finding.model_validate(data)


def test_empty_control_title_is_rejected() -> None:
    with pytest.raises(ValidationError):
        Finding.model_validate(valid_finding_data(control_title=""))


def test_control_title_must_match_registry_metadata() -> None:
    with pytest.raises(ValidationError, match="control_title"):
        Finding.model_validate(valid_finding_data(control_title="Wrong title"))


def test_caller_supplied_evaluated_at_is_rejected() -> None:
    with pytest.raises(ValidationError, match="evaluated_at"):
        Finding.model_validate(
            valid_finding_data(evaluated_at=datetime(2026, 5, 17, tzinfo=UTC)),
        )


def test_finding_is_immutable_after_creation() -> None:
    finding = Finding.model_validate(valid_finding_data())

    with pytest.raises(ValidationError, match="frozen"):
        finding.remediation = "Do something else."


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("severity", "URGENT"),
        ("status", "UNKNOWN"),
    ],
)
def test_enum_fields_reject_arbitrary_strings(field: str, value: str) -> None:
    with pytest.raises(ValidationError):
        Finding.model_validate(valid_finding_data(**{field: value}))


def test_exact_enum_strings_are_accepted() -> None:
    finding = Finding.model_validate(valid_finding_data(severity="HIGH", status="FAIL"))

    assert finding.severity is Severity.HIGH
    assert finding.status is FindingStatus.FAIL


def test_nested_json_raw_evidence_is_accepted() -> None:
    finding = Finding.model_validate(
        valid_finding_data(
            raw_evidence={
                "trail": {
                    "enabled": True,
                    "error_count": 0,
                    "latency_ms": 12.5,
                    "tags": ["prod", None, {"owner": "security"}],
                },
            },
        ),
    )

    assert finding.raw_evidence["trail"]["tags"][2]["owner"] == "security"


@pytest.mark.parametrize(
    "raw_evidence",
    [
        {"checked_at": datetime(2026, 5, 17, tzinfo=UTC)},
        {"ids": {"one", "two"}},
        {"resource": object()},
        {"score": float("inf")},
        {"score": float("nan")},
        {1: "non-string key"},
        {"nested": {"bad": datetime(2026, 5, 17, tzinfo=UTC)}},
    ],
)
def test_non_json_raw_evidence_is_rejected(raw_evidence: object) -> None:
    with pytest.raises(ValidationError, match="raw_evidence"):
        Finding.model_validate(valid_finding_data(raw_evidence=raw_evidence))


def test_model_dump_json_returns_json_compatible_timestamp_string() -> None:
    finding = Finding.model_validate(valid_finding_data())

    dumped = finding.model_dump(mode="json")

    assert isinstance(dumped["evaluated_at"], str)
    assert dumped["evaluated_at"].endswith("Z")


@pytest.mark.parametrize(
    "control_id",
    [
        *STRICT_CIS_CONTROL_IDS,
        *CANDIDATE_CONTROL_IDS,
        *ENTERPRISE_HARDENING_CONTROL_IDS,
    ],
)
def test_all_known_control_ids_are_accepted(control_id: str) -> None:
    finding = Finding.model_validate(valid_finding_data(control_id=control_id))

    assert finding.control_id == control_id


def test_control_registry_is_immutable() -> None:
    with pytest.raises(TypeError):
        CONTROL_REGISTRY["CIS-0.0"] = ControlMetadata(
            control_id="CIS-0.0",
            title="Mutation should fail",
            category="strict_cis",
        )


def test_scan_result_model_dump_json_matches_required_top_level_structure() -> None:
    finding = Finding.model_validate(valid_finding_data())
    result = ScanResult(
        scan_metadata=ScanMetadata(
            account_id="123456789012",
            scan_timestamp=datetime(2026, 5, 17, 22, 30, tzinfo=UTC),
            benchmark="CIS AWS Foundations Benchmark v5.0.0",
            controls_evaluated=("CIS-1.5",),
            duration_ms=1250,
        ),
        summary=ScanSummary(CRITICAL=0, HIGH=1, MEDIUM=0, LOW=0, PASS=0),
        findings=[finding],
    )

    dumped = result.model_dump(mode="json")

    assert set(dumped) == {"scan_metadata", "summary", "findings"}
    assert dumped["scan_metadata"] == {
        "account_id": "123456789012",
        "schema_version": "1.1",
        "scan_timestamp": "2026-05-17T22:30:00Z",
        "benchmark": "CIS AWS Foundations Benchmark v5.0.0",
        "controls_evaluated": ["CIS-1.5"],
        "duration_ms": 1250,
    }
    assert dumped["summary"] == {
        "CRITICAL": 0,
        "ERROR": 0,
        "FAIL": 0,
        "HIGH": 1,
        "MANUAL_CHECK": 0,
        "MEDIUM": 0,
        "NOT_APPLICABLE": 0,
        "LOW": 0,
        "PASS": 0,
    }
    assert dumped["findings"][0]["control_id"] == "CIS-1.5"
    assert isinstance(dumped["findings"][0]["evaluated_at"], str)
