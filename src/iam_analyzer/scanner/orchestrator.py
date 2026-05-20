"""Registry-driven account scan orchestration."""

# mypy: disable-error-code=import-untyped

from __future__ import annotations

from datetime import UTC, datetime
from time import perf_counter
from typing import Any

import structlog

from iam_analyzer.checks.catalog import CHECK_SPECS, CheckSpec
from iam_analyzer.checks.logging import LoggingClientBundle
from iam_analyzer.models import (
    Finding,
    FindingStatus,
    ScanMetadata,
    ScanResult,
    ScanSummary,
    Severity,
)
from iam_analyzer.scanner.pagination import PaginatorUtil

_BENCHMARK = "CIS AWS Foundations Benchmark v5.0.0"
_LOGGER = structlog.get_logger(__name__)


def _summary(findings: list[Finding]) -> ScanSummary:
    severity_counted_statuses = {
        FindingStatus.FAIL,
        FindingStatus.MANUAL_CHECK,
        FindingStatus.ERROR,
    }

    def severity_count(severity: Severity) -> int:
        return sum(
            1
            for finding in findings
            if finding.status in severity_counted_statuses and finding.severity is severity
        )

    def status_count(status: FindingStatus) -> int:
        return sum(1 for finding in findings if finding.status is status)

    return ScanSummary(
        CRITICAL=severity_count(Severity.CRITICAL),
        HIGH=severity_count(Severity.HIGH),
        MEDIUM=severity_count(Severity.MEDIUM),
        LOW=severity_count(Severity.LOW),
        PASS=status_count(FindingStatus.PASS),
        FAIL=status_count(FindingStatus.FAIL),
        MANUAL_CHECK=status_count(FindingStatus.MANUAL_CHECK),
        ERROR=status_count(FindingStatus.ERROR),
        NOT_APPLICABLE=status_count(FindingStatus.NOT_APPLICABLE),
    )


def _client_for_spec(spec: CheckSpec, clients: dict[str, Any]) -> Any:  # noqa: ANN401
    if spec.service == "logging":
        return LoggingClientBundle(
            cloudtrail=clients["cloudtrail"],
            s3=clients.get("s3"),
        )
    return clients[spec.service]


def run_scan(
    session_manager: Any,  # noqa: ANN401
    *,
    region: str,
    check_specs: tuple[CheckSpec, ...] = CHECK_SPECS,
) -> ScanResult:
    """Execute enabled checks and aggregate a validated scan result."""
    started_at = datetime.now(UTC)
    start_counter = perf_counter()
    paginator_util = PaginatorUtil()
    clients: dict[str, Any] = {}
    findings: list[Finding] = []

    for spec in check_specs:
        for service_name in spec.required_services:
            if service_name not in clients:
                clients[service_name] = session_manager.client(service_name)
        findings.extend(spec.function(_client_for_spec(spec, clients), paginator_util))

    duration_ms = int((perf_counter() - start_counter) * 1000)
    controls_evaluated = tuple(spec.control_id for spec in check_specs)
    summary = _summary(findings)
    scan_result = ScanResult(
        scan_metadata=ScanMetadata(
            account_id=str(session_manager.account_id),
            scan_timestamp=started_at,
            benchmark=_BENCHMARK,
            controls_evaluated=controls_evaluated,
            duration_ms=duration_ms,
        ),
        summary=summary,
        findings=findings,
    )

    _LOGGER.info(
        "scan_completed",
        account_id=scan_result.scan_metadata.account_id,
        region=region,
        controls_evaluated=controls_evaluated,
        findings_count=len(findings),
        summary=summary.model_dump(mode="json"),
        duration_ms=duration_ms,
    )
    return scan_result
