"""CloudTrail checks for CIS AWS Foundations Benchmark v5.0.0 controls.

Each check accepts pre-initialized AWS clients through ``LoggingClientBundle``,
returns validated findings, and converts AWS access gaps into MANUAL_CHECK
findings instead of raising to the scanner layer.
"""

# mypy: disable-error-code=import-untyped

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, date, datetime
from typing import TYPE_CHECKING, Any

from botocore.exceptions import ClientError, EndpointConnectionError

from iam_analyzer.checks.registry import CONTROL_REGISTRY
from iam_analyzer.models import Finding, FindingStatus, Severity

if TYPE_CHECKING:
    from collections.abc import Mapping

    from iam_analyzer.scanner.pagination import PaginatorUtil

AWS_DOCS_CLOUDTRAIL_URL = "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/"
AWS_DOCS_S3_URL = "https://docs.aws.amazon.com/AmazonS3/latest/userguide/"
ALL_PUBLIC_ACCESS_BLOCK_KEYS = frozenset(
    {
        "BlockPublicAcls",
        "IgnorePublicAcls",
        "BlockPublicPolicy",
        "RestrictPublicBuckets",
    },
)


@dataclass(frozen=True, slots=True)
class LoggingClientBundle:
    """Pre-initialized AWS clients required by CloudTrail logging checks."""

    cloudtrail: Any
    s3: Any | None = None


def _title(control_id: str) -> str:
    return CONTROL_REGISTRY[control_id].title


def _finding(  # noqa: PLR0913
    *,
    control_id: str,
    severity: Severity,
    status: FindingStatus,
    resource_id: str | None,
    remediation: str,
    raw_evidence: Mapping[str, Any],
) -> Finding:
    return Finding(
        control_id=control_id,
        control_title=_title(control_id),
        severity=severity,
        status=status,
        resource_id=resource_id,
        remediation=remediation,
        raw_evidence=_json_safe(raw_evidence),
    )


def _manual_check(control_id: str, error: ClientError | EndpointConnectionError) -> list[Finding]:
    return [
        _finding(
            control_id=control_id,
            severity=Severity.MEDIUM,
            status=FindingStatus.MANUAL_CHECK,
            resource_id=None,
            remediation=(
                f"Review {control_id} manually because the scanner could not evaluate it. "
                f"Grant the documented read-only CloudTrail/S3 permissions and rerun the scan. "
                f"AWS CloudTrail documentation: {AWS_DOCS_CLOUDTRAIL_URL}"
            ),
            raw_evidence={"error": _error_evidence(error)},
        ),
    ]


def _error_evidence(error: ClientError | EndpointConnectionError) -> dict[str, str]:
    if isinstance(error, ClientError):
        error_data = error.response.get("Error", {})
        return {
            "code": str(error_data.get("Code", "ClientError")),
            "message": str(error_data.get("Message", "AWS client error")),
        }
    return {"code": "EndpointConnectionError", "message": str(error)}


def _missing_evidence_error(control_id: str, message: str) -> ClientError:
    return ClientError(
        {"Error": {"Code": "MissingEvidence", "Message": message}},
        control_id,
    )


def _json_safe(value: object) -> Any:  # noqa: ANN401
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_json_safe(item) for item in value]
    if isinstance(value, tuple):
        return [_json_safe(item) for item in value]
    return value


def _cloudtrail_client(client: Any) -> Any:  # noqa: ANN401
    return client.cloudtrail if isinstance(client, LoggingClientBundle) else client


def _s3_client(client: Any) -> Any:  # noqa: ANN401
    if isinstance(client, LoggingClientBundle) and client.s3 is not None:
        return client.s3
    control_id = "cloudtrail_s3"
    message = "S3 client missing from logging client bundle"
    raise _missing_evidence_error(control_id, message)


def _describe_trails(client: Any) -> list[dict[str, Any]]:  # noqa: ANN401
    response = _cloudtrail_client(client).describe_trails()
    trails = response.get("trailList", [])
    if isinstance(trails, list):
        return [trail for trail in trails if isinstance(trail, dict)]
    return []


def _trail_identifier(trail: Mapping[str, Any]) -> str:
    return str(trail.get("TrailARN") or trail.get("Name") or "unknown-trail")


def _trail_bucket_names(trails: list[dict[str, Any]]) -> list[str]:
    buckets: list[str] = []
    for trail in trails:
        bucket_name = trail.get("S3BucketName")
        if isinstance(bucket_name, str) and bucket_name and bucket_name not in buckets:
            buckets.append(bucket_name)
    return buckets


def _selector_covers_all_management_events(selector: Mapping[str, Any]) -> bool:
    return (
        selector.get("IncludeManagementEvents") is True
        and selector.get("ReadWriteType") == "All"
        and not selector.get("ExcludeManagementEventSources")
    )


def _string_values(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def _advanced_selector_management_coverage(selector: Mapping[str, Any]) -> tuple[set[str], bool]:
    field_selectors = selector.get("FieldSelectors", [])
    if not isinstance(field_selectors, list):
        return set(), False

    has_management_category = False
    read_only_values: list[str] | None = None
    excludes_management_sources = False
    for field_selector in field_selectors:
        if not isinstance(field_selector, dict):
            continue
        field_name = field_selector.get("Field")
        if field_name == "eventCategory":
            has_management_category = "Management" in _string_values(field_selector.get("Equals"))
        elif field_name == "readOnly":
            read_only_values = _string_values(field_selector.get("Equals"))
        elif field_name == "eventSource":
            excluded_sources = _string_values(field_selector.get("NotEquals"))
            excludes_management_sources = bool(excluded_sources)

    if not has_management_category:
        return set(), excludes_management_sources
    if read_only_values is None:
        return {"true", "false"}, excludes_management_sources
    return set(read_only_values).intersection({"true", "false"}), excludes_management_sources


def _advanced_selectors_cover_all_management_events(
    selectors: list[Mapping[str, Any]],
) -> bool:
    covered_read_only_values: set[str] = set()
    for selector in selectors:
        selector_coverage, excludes_management_sources = _advanced_selector_management_coverage(
            selector,
        )
        if selector_coverage and excludes_management_sources:
            return False
        covered_read_only_values.update(selector_coverage)
    return {"true", "false"}.issubset(covered_read_only_values)


def _management_event_coverage(
    cloudtrail: Any,  # noqa: ANN401
    trail: Mapping[str, Any],
) -> bool | None:
    response = cloudtrail.get_event_selectors(TrailName=_trail_identifier(trail))
    selectors = response.get("EventSelectors", [])
    if isinstance(selectors, list) and selectors:
        return any(
            _selector_covers_all_management_events(selector)
            for selector in selectors
            if isinstance(selector, dict)
        )

    advanced_selectors = response.get("AdvancedEventSelectors", [])
    if isinstance(advanced_selectors, list) and advanced_selectors:
        return _advanced_selectors_cover_all_management_events(
            [selector for selector in advanced_selectors if isinstance(selector, dict)],
        )
    return False


def _get_public_access_block(s3: Any, bucket_name: str) -> Mapping[str, Any]:  # noqa: ANN401
    try:
        response = s3.get_public_access_block(Bucket=bucket_name)
    except ClientError as error:
        error_code = error.response.get("Error", {}).get("Code")
        if error_code == "NoSuchPublicAccessBlockConfiguration":
            return {}
        raise
    config = response.get("PublicAccessBlockConfiguration", {})
    if isinstance(config, dict):
        return config
    return {}


def check_cis_3_1_cloudtrail_enabled_all_regions(
    client: Any,  # noqa: ANN401
    paginator_util: PaginatorUtil,  # noqa: ARG001
) -> list[Finding]:
    """CIS-3.1: Ensure CloudTrail is enabled in all regions.

    Audit procedure: verify at least one multi-Region trail is logging global
    service events and read/write management events.
    """
    control_id = "CIS-3.1"
    try:
        cloudtrail = _cloudtrail_client(client)
        trails = _describe_trails(client)
        compliant_trails: list[dict[str, Any]] = []
        unknown_selector_trails: list[str] = []
        evaluated_trails: list[dict[str, Any]] = []
        for trail in trails:
            trail_id = _trail_identifier(trail)
            status = cloudtrail.get_trail_status(Name=trail_id)
            selector_coverage = _management_event_coverage(cloudtrail, trail)
            if selector_coverage is None:
                unknown_selector_trails.append(trail_id)
            trail_evidence = {
                "trail": trail,
                "is_logging": status.get("IsLogging") is True,
                "management_events": selector_coverage,
            }
            evaluated_trails.append(trail_evidence)
            if (
                trail.get("IsMultiRegionTrail") is True
                and trail.get("IncludeGlobalServiceEvents") is True
                and status.get("IsLogging") is True
                and selector_coverage is True
            ):
                compliant_trails.append(trail_evidence)
    except (ClientError, EndpointConnectionError) as error:
        return _manual_check(control_id, error)

    if compliant_trails:
        status = FindingStatus.PASS
    elif unknown_selector_trails:
        status = FindingStatus.MANUAL_CHECK
    else:
        status = FindingStatus.FAIL

    return [
        _finding(
            control_id=control_id,
            severity=Severity.HIGH,
            status=status,
            resource_id=None,
            remediation=(
                f"For {control_id}, configure a multi-Region CloudTrail trail that logs "
                f"global service events and both read and write management events. "
                f"AWS CloudTrail documentation: {AWS_DOCS_CLOUDTRAIL_URL}"
            ),
            raw_evidence={
                "evaluated_trails": evaluated_trails,
                "unknown_selector_trails": unknown_selector_trails,
            },
        ),
    ]


def check_cis_3_2_log_file_validation_enabled(
    client: Any,  # noqa: ANN401
    paginator_util: PaginatorUtil,  # noqa: ARG001
) -> list[Finding]:
    """CIS-3.2: Ensure CloudTrail log file validation is enabled.

    Audit procedure: inspect CloudTrail trail metadata and verify every trail
    has LogFileValidationEnabled set to true.
    """
    control_id = "CIS-3.2"
    try:
        trails = _describe_trails(client)
    except (ClientError, EndpointConnectionError) as error:
        return _manual_check(control_id, error)

    non_compliant = [
        _trail_identifier(trail)
        for trail in trails
        if trail.get("LogFileValidationEnabled") is not True
    ]
    return [
        _finding(
            control_id=control_id,
            severity=Severity.MEDIUM,
            status=FindingStatus.FAIL if not trails or non_compliant else FindingStatus.PASS,
            resource_id=None,
            remediation=(
                f"For {control_id}, enable CloudTrail log file validation on every trail. "
                f"AWS CloudTrail documentation: "
                f"{AWS_DOCS_CLOUDTRAIL_URL}cloudtrail-log-file-validation-intro.html"
            ),
            raw_evidence={"trails": trails, "non_compliant_trails": non_compliant},
        ),
    ]


def check_cis_3_4_cloudtrail_bucket_access_logging_enabled(
    client: Any,  # noqa: ANN401
    paginator_util: PaginatorUtil,  # noqa: ARG001
) -> list[Finding]:
    """CIS-3.4: Ensure S3 access logging is enabled on the CloudTrail S3 bucket.

    Audit procedure: identify CloudTrail S3 buckets and verify each bucket has
    server access logging configured.
    """
    control_id = "CIS-3.4"
    try:
        trails = _describe_trails(client)
        s3 = _s3_client(client)
        buckets = _trail_bucket_names(trails)
        bucket_logging: dict[str, Mapping[str, Any]] = {}
        for bucket_name in buckets:
            response = s3.get_bucket_logging(Bucket=bucket_name)
            logging_config = response.get("LoggingEnabled", {})
            bucket_logging[bucket_name] = logging_config if isinstance(logging_config, dict) else {}
    except (ClientError, EndpointConnectionError) as error:
        return _manual_check(control_id, error)

    missing_logging = [
        bucket_name for bucket_name, logging_config in bucket_logging.items() if not logging_config
    ]
    return [
        _finding(
            control_id=control_id,
            severity=Severity.MEDIUM,
            status=FindingStatus.FAIL if not buckets or missing_logging else FindingStatus.PASS,
            resource_id=None,
            remediation=(
                f"For {control_id}, enable S3 server access logging on every bucket that "
                f"stores CloudTrail logs. AWS S3 documentation: "
                f"{AWS_DOCS_S3_URL}ServerLogs.html"
            ),
            raw_evidence={
                "cloudtrail_buckets": buckets,
                "bucket_logging": bucket_logging,
                "missing_logging": missing_logging,
            },
        ),
    ]


def check_cis_3_5_cloudtrail_kms_encryption_enabled(
    client: Any,  # noqa: ANN401
    paginator_util: PaginatorUtil,  # noqa: ARG001
) -> list[Finding]:
    """CIS-3.5: Ensure CloudTrail logs are encrypted at rest using KMS keys.

    Audit procedure: inspect CloudTrail trail metadata and verify every trail
    has a KmsKeyId configured.
    """
    control_id = "CIS-3.5"
    try:
        trails = _describe_trails(client)
    except (ClientError, EndpointConnectionError) as error:
        return _manual_check(control_id, error)

    unencrypted_trails = [
        _trail_identifier(trail) for trail in trails if not str(trail.get("KmsKeyId", "")).strip()
    ]
    return [
        _finding(
            control_id=control_id,
            severity=Severity.MEDIUM,
            status=FindingStatus.FAIL if not trails or unencrypted_trails else FindingStatus.PASS,
            resource_id=None,
            remediation=(
                f"For {control_id}, configure CloudTrail to encrypt log files with an AWS KMS key. "
                f"AWS CloudTrail documentation: "
                f"{AWS_DOCS_CLOUDTRAIL_URL}encrypting-cloudtrail-log-files-with-aws-kms.html"
            ),
            raw_evidence={"trails": trails, "unencrypted_trails": unencrypted_trails},
        ),
    ]


def check_ehc_ct_1_cloudwatch_logs_integration(
    client: Any,  # noqa: ANN401
    paginator_util: PaginatorUtil,  # noqa: ARG001
) -> list[Finding]:
    """EHC-CT-1: Ensure CloudTrail is integrated with CloudWatch Logs.

    Audit procedure: inspect CloudTrail trail metadata and verify every trail
    has CloudWatchLogsLogGroupArn configured.
    """
    control_id = "EHC-CT-1"
    try:
        trails = _describe_trails(client)
    except (ClientError, EndpointConnectionError) as error:
        return _manual_check(control_id, error)

    missing_integration = [
        _trail_identifier(trail)
        for trail in trails
        if not str(trail.get("CloudWatchLogsLogGroupArn", "")).strip()
    ]
    return [
        _finding(
            control_id=control_id,
            severity=Severity.LOW,
            status=FindingStatus.FAIL if not trails or missing_integration else FindingStatus.PASS,
            resource_id=None,
            remediation=(
                f"For {control_id}, send CloudTrail events to CloudWatch Logs for operational "
                f"monitoring. AWS CloudTrail documentation: "
                f"{AWS_DOCS_CLOUDTRAIL_URL}send-cloudtrail-events-to-cloudwatch-logs.html"
            ),
            raw_evidence={"trails": trails, "missing_integration": missing_integration},
        ),
    ]


def check_ehc_ct_2_cloudtrail_bucket_not_public(
    client: Any,  # noqa: ANN401
    paginator_util: PaginatorUtil,  # noqa: ARG001
) -> list[Finding]:
    """EHC-CT-2: Ensure the CloudTrail S3 bucket is not publicly accessible.

    Audit procedure: identify CloudTrail S3 buckets and verify S3 reports the
    bucket policy as non-public and public access block settings are enabled.
    """
    control_id = "EHC-CT-2"
    try:
        trails = _describe_trails(client)
        s3 = _s3_client(client)
        buckets = _trail_bucket_names(trails)
        bucket_evidence: dict[str, dict[str, Any]] = {}
        public_buckets: list[str] = []
        for bucket_name in buckets:
            policy_status = s3.get_bucket_policy_status(Bucket=bucket_name).get(
                "PolicyStatus",
                {},
            )
            public_access_block = _get_public_access_block(s3, bucket_name)
            is_public = (
                isinstance(policy_status, dict) and policy_status.get("IsPublic") is True
            )
            blocks_all_public_access = all(
                public_access_block.get(key) is True for key in ALL_PUBLIC_ACCESS_BLOCK_KEYS
            )
            bucket_evidence[bucket_name] = {
                "policy_status": policy_status,
                "public_access_block": public_access_block,
                "blocks_all_public_access": blocks_all_public_access,
            }
            if is_public or not blocks_all_public_access:
                public_buckets.append(bucket_name)
    except (ClientError, EndpointConnectionError) as error:
        return _manual_check(control_id, error)

    return [
        _finding(
            control_id=control_id,
            severity=Severity.HIGH,
            status=FindingStatus.FAIL if not buckets or public_buckets else FindingStatus.PASS,
            resource_id=None,
            remediation=(
                f"For {control_id}, remove public access from the CloudTrail log bucket "
                f"and enable S3 Block Public Access. AWS S3 documentation: "
                f"{AWS_DOCS_S3_URL}access-control-block-public-access.html"
            ),
            raw_evidence={
                "cloudtrail_buckets": buckets,
                "bucket_evidence": bucket_evidence,
                "public_or_unblocked_buckets": public_buckets,
            },
        ),
    ]


def check_ehc_ct_3_management_event_coverage(
    client: Any,  # noqa: ANN401
    paginator_util: PaginatorUtil,  # noqa: ARG001
) -> list[Finding]:
    """EHC-CT-3: Ensure CloudTrail management event coverage is hardened.

    Audit procedure: verify every trail logs read and write management events
    without excluded management event sources.
    """
    control_id = "EHC-CT-3"
    try:
        cloudtrail = _cloudtrail_client(client)
        trails = _describe_trails(client)
        non_compliant: list[str] = []
        unknown_selector_trails: list[str] = []
        for trail in trails:
            trail_id = _trail_identifier(trail)
            coverage = _management_event_coverage(cloudtrail, trail)
            if coverage is None:
                unknown_selector_trails.append(trail_id)
            elif coverage is False:
                non_compliant.append(trail_id)
    except (ClientError, EndpointConnectionError) as error:
        return _manual_check(control_id, error)

    if unknown_selector_trails:
        status = FindingStatus.MANUAL_CHECK
    elif not trails or non_compliant:
        status = FindingStatus.FAIL
    else:
        status = FindingStatus.PASS

    return [
        _finding(
            control_id=control_id,
            severity=Severity.MEDIUM,
            status=status,
            resource_id=None,
            remediation=(
                f"For {control_id}, configure CloudTrail event selectors to include read "
                f"and write management events without excluded management event sources. "
                f"AWS CloudTrail documentation: "
                f"{AWS_DOCS_CLOUDTRAIL_URL}logging-management-events-with-cloudtrail.html"
            ),
            raw_evidence={
                "trails": trails,
                "non_compliant_trails": non_compliant,
                "unknown_selector_trails": unknown_selector_trails,
            },
        ),
    ]
