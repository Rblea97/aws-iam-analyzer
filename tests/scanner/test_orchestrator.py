"""Tests for registry-based scan orchestration."""

# ruff: noqa: D103, INP001

from __future__ import annotations

from typing import Any

import pytest

from iam_analyzer.checks.catalog import CheckSpec
from iam_analyzer.checks.logging import LoggingClientBundle
from iam_analyzer.checks.registry import CONTROL_REGISTRY
from iam_analyzer.models import Finding, FindingStatus, ScanResult, Severity
from iam_analyzer.scanner.orchestrator import run_scan

_EXPECTED_DURATION_MS = 125
_EXPECTED_HIGH_FINDINGS = 2


class _FakeSessionManager:
    account_id = "123456789012"

    def __init__(self) -> None:
        self.clients: dict[str, object] = {}
        self.client_calls: list[str] = []

    def client(self, service_name: str) -> object:
        self.client_calls.append(service_name)
        return self.clients.setdefault(service_name, object())


class _FakeLogger:
    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    def info(self, event: str, **kwargs: Any) -> None:  # noqa: ANN401
        self.events.append((event, kwargs))


def _isolate_logger(monkeypatch: pytest.MonkeyPatch) -> _FakeLogger:
    logger = _FakeLogger()
    monkeypatch.setattr("iam_analyzer.scanner.orchestrator._LOGGER", logger)
    return logger


@pytest.fixture(autouse=True)
def isolate_orchestrator_logger(monkeypatch: pytest.MonkeyPatch) -> None:
    _isolate_logger(monkeypatch)


def _finding(
    control_id: str,
    *,
    status: FindingStatus = FindingStatus.PASS,
    severity: Severity = Severity.LOW,
) -> Finding:
    return Finding(
        control_id=control_id,
        control_title=CONTROL_REGISTRY[control_id].title,
        severity=severity,
        status=status,
        resource_id=None,
        remediation=f"Remediate {control_id} with AWS documentation.",
        raw_evidence={"test": True},
    )


def test_run_scan_executes_every_check_in_registry_order() -> None:
    session_manager = _FakeSessionManager()
    executed: list[str] = []

    def first_check(client: object, paginator_util: object) -> list[Finding]:
        assert client is session_manager.clients["iam"]
        assert paginator_util is not None
        executed.append("CIS-1.3")
        return [_finding("CIS-1.3")]

    def second_check(client: object, paginator_util: object) -> list[Finding]:
        assert client is session_manager.clients["iam"]
        assert paginator_util is not None
        executed.append("CIS-1.5")
        return [_finding("CIS-1.5")]

    result = run_scan(
        session_manager,
        region="us-east-1",
        check_specs=(
            CheckSpec(
                control_id="CIS-1.3",
                title="CIS-1.3 test control",
                service="iam",
                required_services=("iam",),
                function=first_check,
            ),
            CheckSpec(
                control_id="CIS-1.5",
                title="CIS-1.5 test control",
                service="iam",
                required_services=("iam",),
                function=second_check,
            ),
        ),
    )

    assert executed == ["CIS-1.3", "CIS-1.5"]
    assert result.scan_metadata.controls_evaluated == ("CIS-1.3", "CIS-1.5")


def test_run_scan_reuses_clients_by_service_name() -> None:
    session_manager = _FakeSessionManager()

    def passing_check(client: object, _paginator_util: object) -> list[Finding]:
        assert client is session_manager.clients["iam"]
        return [_finding("CIS-1.3")]

    run_scan(
        session_manager,
        region="us-east-1",
        check_specs=(
            CheckSpec(
                control_id="CIS-1.3",
                title="CIS-1.3 test control",
                service="iam",
                required_services=("iam",),
                function=passing_check,
            ),
            CheckSpec(
                control_id="CIS-1.5",
                title="CIS-1.5 test control",
                service="iam",
                required_services=("iam",),
                function=lambda _client, _paginator: [_finding("CIS-1.5")],
            ),
        ),
    )

    assert session_manager.client_calls == ["iam"]


def test_run_scan_builds_logging_bundle_from_reused_service_clients() -> None:
    session_manager = _FakeSessionManager()

    def logging_check(client: object, _paginator_util: object) -> list[Finding]:
        assert isinstance(client, LoggingClientBundle)
        assert client.cloudtrail is session_manager.clients["cloudtrail"]
        assert client.s3 is session_manager.clients["s3"]
        return [_finding("CIS-3.1")]

    run_scan(
        session_manager,
        region="us-west-2",
        check_specs=(
            CheckSpec(
                control_id="CIS-3.1",
                title="CIS-3.1 test control",
                service="logging",
                required_services=("cloudtrail", "s3"),
                function=logging_check,
            ),
        ),
    )

    assert session_manager.client_calls == ["cloudtrail", "s3"]


def test_run_scan_counts_summary_buckets_and_duration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session_manager = _FakeSessionManager()
    perf_values = iter([10.0, 10.125])
    monkeypatch.setattr(
        "iam_analyzer.scanner.orchestrator.perf_counter",
        lambda: next(perf_values),
    )

    result = run_scan(
        session_manager,
        region="us-east-1",
        check_specs=(
            CheckSpec(
                control_id="CIS-1.3",
                title="CIS-1.3 test control",
                service="iam",
                required_services=("iam",),
                function=lambda _client, _paginator: [
                    _finding("CIS-1.3", status=FindingStatus.PASS, severity=Severity.LOW),
                    _finding("CIS-1.5", status=FindingStatus.FAIL, severity=Severity.HIGH),
                ],
            ),
        ),
    )

    assert result.summary.PASS == 1
    assert result.summary.HIGH == 1
    assert result.summary.CRITICAL == 0
    assert result.summary.MEDIUM == 0
    assert result.summary.LOW == 0
    assert result.scan_metadata.duration_ms == _EXPECTED_DURATION_MS


def test_run_scan_counts_statuses_separately_from_severity() -> None:
    session_manager = _FakeSessionManager()

    result = run_scan(
        session_manager,
        region="us-east-1",
        check_specs=(
            CheckSpec(
                control_id="CIS-1.3",
                title="CIS-1.3 test control",
                service="iam",
                required_services=("iam",),
                function=lambda _client, _paginator: [
                    _finding("CIS-1.3", status=FindingStatus.PASS, severity=Severity.LOW),
                    _finding("CIS-1.5", status=FindingStatus.FAIL, severity=Severity.HIGH),
                    _finding(
                        "CIS-3.1",
                        status=FindingStatus.MANUAL_CHECK,
                        severity=Severity.HIGH,
                    ),
                ],
            ),
        ),
    )

    assert result.summary.PASS == 1
    assert result.summary.FAIL == 1
    assert result.summary.MANUAL_CHECK == 1
    assert result.summary.HIGH == _EXPECTED_HIGH_FINDINGS


def test_run_scan_logs_completion_event(monkeypatch: pytest.MonkeyPatch) -> None:
    session_manager = _FakeSessionManager()
    logger = _FakeLogger()
    monkeypatch.setattr("iam_analyzer.scanner.orchestrator._LOGGER", logger)

    result = run_scan(
        session_manager,
        region="us-east-1",
        check_specs=(
            CheckSpec(
                control_id="CIS-1.3",
                title="CIS-1.3 test control",
                service="iam",
                required_services=("iam",),
                function=lambda _client, _paginator: [_finding("CIS-1.3")],
            ),
        ),
    )

    assert isinstance(result, ScanResult)
    assert logger.events == [
        (
            "scan_completed",
            {
                "account_id": "123456789012",
                "region": "us-east-1",
                "controls_evaluated": ("CIS-1.3",),
                "findings_count": 1,
                "summary": {
                    "CRITICAL": 0,
                    "ERROR": 0,
                    "FAIL": 0,
                    "HIGH": 0,
                    "MANUAL_CHECK": 0,
                    "MEDIUM": 0,
                    "NOT_APPLICABLE": 0,
                    "LOW": 0,
                    "PASS": 1,
                },
                "duration_ms": result.scan_metadata.duration_ms,
            },
        ),
    ]
