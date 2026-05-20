"""CloudTrail trail metadata checks."""

# mypy: disable-error-code=import-untyped

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from botocore.exceptions import ClientError, EndpointConnectionError

from iam_analyzer.checks.cloudtrail.common import (
    AWS_DOCS_CLOUDTRAIL_URL,
    cloudtrail_client,
    describe_trails,
    logging_manual_check,
    trail_identifier,
)
from iam_analyzer.checks.cloudtrail.selectors import management_event_coverage
from iam_analyzer.checks.common import finding
from iam_analyzer.models import Finding, FindingStatus

if TYPE_CHECKING:
    from iam_analyzer.scanner.pagination import PaginatorUtil


def check_cis_3_1_cloudtrail_enabled_all_regions(
    client: Any,  # noqa: ANN401
    paginator_util: PaginatorUtil,  # noqa: ARG001
) -> list[Finding]:
    """CIS-3.1: Ensure a compliant multi-Region CloudTrail trail exists."""
    control_id = "CIS-3.1"
    try:
        evidence = _multi_region_trail_evidence(client)
    except (ClientError, EndpointConnectionError) as error:
        return logging_manual_check(control_id, error)
    return [
        finding(
            control_id=control_id,
            status=_cis_3_1_status(evidence),
            resource_id=None,
            remediation=(
                f"For {control_id}, configure a multi-Region CloudTrail trail that logs "
                f"global service events and both read and write management events. "
                f"AWS CloudTrail documentation: {AWS_DOCS_CLOUDTRAIL_URL}"
            ),
            raw_evidence=evidence,
        ),
    ]


def _multi_region_trail_evidence(client: Any) -> dict[str, Any]:  # noqa: ANN401
    cloudtrail = cloudtrail_client(client)
    compliant: list[dict[str, Any]] = []
    unknown: list[str] = []
    evaluated: list[dict[str, Any]] = []
    for trail in describe_trails(client):
        trail_evidence = _trail_logging_evidence(cloudtrail, trail)
        evaluated.append(trail_evidence)
        if trail_evidence["management_events"] is None:
            unknown.append(trail_identifier(trail))
        if _is_compliant_multi_region_trail(trail_evidence):
            compliant.append(trail_evidence)
    return {
        "evaluated_trails": evaluated,
        "unknown_selector_trails": unknown,
        "compliant_trails": compliant,
    }


def _trail_logging_evidence(cloudtrail: Any, trail: dict[str, Any]) -> dict[str, Any]:  # noqa: ANN401
    status = cloudtrail.get_trail_status(Name=trail_identifier(trail))
    return {
        "trail": trail,
        "is_logging": status.get("IsLogging") is True,
        "management_events": management_event_coverage(cloudtrail, trail),
    }


def _is_compliant_multi_region_trail(trail_evidence: dict[str, Any]) -> bool:
    trail = trail_evidence["trail"]
    return (
        trail.get("IsMultiRegionTrail") is True
        and trail.get("IncludeGlobalServiceEvents") is True
        and trail_evidence["is_logging"] is True
        and trail_evidence["management_events"] is True
    )


def _cis_3_1_status(evidence: dict[str, Any]) -> FindingStatus:
    if evidence["compliant_trails"]:
        return FindingStatus.PASS
    if evidence["unknown_selector_trails"]:
        return FindingStatus.MANUAL_CHECK
    return FindingStatus.FAIL


def check_cis_3_2_log_file_validation_enabled(
    client: Any,  # noqa: ANN401
    paginator_util: PaginatorUtil,  # noqa: ARG001
) -> list[Finding]:
    """CIS-3.2: Ensure CloudTrail log file validation is enabled."""
    control_id = "CIS-3.2"
    try:
        trails = describe_trails(client)
    except (ClientError, EndpointConnectionError) as error:
        return logging_manual_check(control_id, error)
    non_compliant = [
        trail_identifier(trail) for trail in trails if not trail.get("LogFileValidationEnabled")
    ]
    return _trail_metadata_finding(control_id, trails, non_compliant, "log file validation")


def check_cis_3_5_cloudtrail_kms_encryption_enabled(
    client: Any,  # noqa: ANN401
    paginator_util: PaginatorUtil,  # noqa: ARG001
) -> list[Finding]:
    """CIS-3.5: Ensure CloudTrail logs are encrypted with KMS."""
    control_id = "CIS-3.5"
    try:
        trails = describe_trails(client)
    except (ClientError, EndpointConnectionError) as error:
        return logging_manual_check(control_id, error)
    non_compliant = [
        trail_identifier(trail) for trail in trails if not str(trail.get("KmsKeyId", "")).strip()
    ]
    return _trail_metadata_finding(control_id, trails, non_compliant, "KMS encryption")


def check_ehc_ct_1_cloudwatch_logs_integration(
    client: Any,  # noqa: ANN401
    paginator_util: PaginatorUtil,  # noqa: ARG001
) -> list[Finding]:
    """EHC-CT-1: Ensure CloudTrail sends events to CloudWatch Logs."""
    control_id = "EHC-CT-1"
    try:
        trails = describe_trails(client)
    except (ClientError, EndpointConnectionError) as error:
        return logging_manual_check(control_id, error)
    missing = [
        trail_identifier(trail)
        for trail in trails
        if not str(trail.get("CloudWatchLogsLogGroupArn", "")).strip()
    ]
    return _trail_metadata_finding(control_id, trails, missing, "CloudWatch Logs integration")


def _trail_metadata_finding(
    control_id: str,
    trails: list[dict[str, Any]],
    non_compliant: list[str],
    label: str,
) -> list[Finding]:
    return [
        finding(
            control_id=control_id,
            status=FindingStatus.FAIL if not trails or non_compliant else FindingStatus.PASS,
            resource_id=None,
            remediation=(
                f"For {control_id}, configure CloudTrail {label}. "
                f"AWS CloudTrail documentation: {AWS_DOCS_CLOUDTRAIL_URL}"
            ),
            raw_evidence={"trails": trails, "non_compliant_trails": non_compliant},
        ),
    ]


def check_ehc_ct_3_management_event_coverage(
    client: Any,  # noqa: ANN401
    paginator_util: PaginatorUtil,  # noqa: ARG001
) -> list[Finding]:
    """EHC-CT-3: Ensure CloudTrail management event coverage is hardened."""
    control_id = "EHC-CT-3"
    try:
        evidence = _management_event_evidence(client)
    except (ClientError, EndpointConnectionError) as error:
        return logging_manual_check(control_id, error)
    return [
        finding(
            control_id=control_id,
            status=_management_event_status(evidence),
            resource_id=None,
            remediation=(
                f"For {control_id}, configure CloudTrail event selectors to include read "
                f"and write management events without excluded management event sources. "
                f"AWS CloudTrail documentation: {AWS_DOCS_CLOUDTRAIL_URL}"
            ),
            raw_evidence=evidence,
        ),
    ]


def _management_event_evidence(client: Any) -> dict[str, Any]:  # noqa: ANN401
    cloudtrail = cloudtrail_client(client)
    non_compliant: list[str] = []
    unknown: list[str] = []
    trails = describe_trails(client)
    for trail in trails:
        coverage = management_event_coverage(cloudtrail, trail)
        if coverage is None:
            unknown.append(trail_identifier(trail))
        elif coverage is False:
            non_compliant.append(trail_identifier(trail))
    return {
        "trails": trails,
        "non_compliant_trails": non_compliant,
        "unknown_selector_trails": unknown,
    }


def _management_event_status(evidence: dict[str, Any]) -> FindingStatus:
    if evidence["unknown_selector_trails"]:
        return FindingStatus.MANUAL_CHECK
    if not evidence["trails"] or evidence["non_compliant_trails"]:
        return FindingStatus.FAIL
    return FindingStatus.PASS
