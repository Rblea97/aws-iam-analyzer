"""Tests for CIS AWS Foundations Benchmark v5.0.0 CloudTrail checks."""

# ruff: noqa: D103, FBT001, INP001, S106

from __future__ import annotations

from typing import Any

import boto3
import pytest
from botocore.stub import Stubber

from iam_analyzer.checks.logging import (
    LoggingClientBundle,
    check_cis_3_1_cloudtrail_enabled_all_regions,
    check_cis_3_2_log_file_validation_enabled,
    check_cis_3_4_cloudtrail_bucket_access_logging_enabled,
    check_cis_3_5_cloudtrail_kms_encryption_enabled,
    check_ehc_ct_1_cloudwatch_logs_integration,
    check_ehc_ct_2_cloudtrail_bucket_not_public,
    check_ehc_ct_3_management_event_coverage,
)
from iam_analyzer.checks.registry import CONTROL_REGISTRY
from iam_analyzer.models import FindingStatus


class _UnusedPaginator:
    def paginate(
        self,
        _client: object,
        _operation_name: str,
        _result_key: str,
        **_kwargs: Any,  # noqa: ANN401
    ) -> list[Any]:
        msg = "CloudTrail checks should not use paginator utility yet"
        raise AssertionError(msg)


def _client(service_name: str) -> Any:  # noqa: ANN401
    return boto3.client(
        service_name,
        region_name="us-east-1",
        aws_access_key_id="test",
        aws_secret_access_key="test",
        aws_session_token="test",
    )


def _bundle() -> tuple[LoggingClientBundle, Stubber, Stubber]:
    cloudtrail = _client("cloudtrail")
    s3 = _client("s3")
    return LoggingClientBundle(cloudtrail=cloudtrail, s3=s3), Stubber(cloudtrail), Stubber(s3)


def _trail(**overrides: Any) -> dict[str, Any]:  # noqa: ANN401
    trail = {
        "Name": "org-management-trail",
        "TrailARN": "arn:aws:cloudtrail:us-east-1:123456789012:trail/org-management-trail",
        "S3BucketName": "org-cloudtrail-logs",
        "IncludeGlobalServiceEvents": True,
        "IsMultiRegionTrail": True,
        "LogFileValidationEnabled": True,
        "CloudWatchLogsLogGroupArn": (
            "arn:aws:logs:us-east-1:123456789012:log-group:/aws/cloudtrail/org"
        ),
        "KmsKeyId": "arn:aws:kms:us-east-1:123456789012:key/11111111-2222-3333-4444-555555555555",
    }
    trail.update(overrides)
    return trail


def _management_selector(**overrides: Any) -> dict[str, Any]:  # noqa: ANN401
    selector = {
        "ReadWriteType": "All",
        "IncludeManagementEvents": True,
        "DataResources": [],
        "ExcludeManagementEventSources": [],
    }
    selector.update(overrides)
    return selector


def _advanced_management_selector(
    *,
    read_only_values: list[str] | None = None,
    excluded_sources: list[str] | None = None,
) -> dict[str, Any]:
    selectors = [{"Field": "eventCategory", "Equals": ["Management"]}]
    if read_only_values is not None:
        selectors.append({"Field": "readOnly", "Equals": read_only_values})
    if excluded_sources is not None:
        selectors.append({"Field": "eventSource", "NotEquals": excluded_sources})
    return {"Name": "management-events", "FieldSelectors": selectors}


def _describe_trails(stubber: Stubber, trails: list[dict[str, Any]]) -> None:
    stubber.add_response("describe_trails", {"trailList": trails}, {})


def _trail_status(stubber: Stubber, trail: dict[str, Any], *, is_logging: bool = True) -> None:
    stubber.add_response(
        "get_trail_status",
        {"IsLogging": is_logging},
        {"Name": trail["TrailARN"]},
    )


def _event_selectors(
    stubber: Stubber,
    trail: dict[str, Any],
    selectors: list[dict[str, Any]] | None = None,
) -> None:
    stubber.add_response(
        "get_event_selectors",
        {"EventSelectors": selectors or [_management_selector()]},
        {"TrailName": trail["TrailARN"]},
    )


def _advanced_event_selectors(
    stubber: Stubber,
    trail: dict[str, Any],
    selectors: list[dict[str, Any]],
) -> None:
    stubber.add_response(
        "get_event_selectors",
        {"AdvancedEventSelectors": selectors},
        {"TrailName": trail["TrailARN"]},
    )


def _access_denied(stubber: Stubber, method_name: str) -> None:
    stubber.add_client_error(
        method_name,
        service_error_code="AccessDenied",
        service_message="not authorized",
        http_status_code=403,
    )


def test_registry_uses_authoritative_cis_v5_cloudtrail_titles() -> None:
    expected_titles = {
        "CIS-3.1": (
            "Ensure CloudTrail is enabled and configured with at least one multi-Region trail"
        ),
        "CIS-3.2": "Ensure CloudTrail log file validation is enabled",
        "CIS-3.4": "Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket",
        "CIS-3.5": "Ensure CloudTrail logs are encrypted at rest using KMS keys",
    }

    for control_id, title in expected_titles.items():
        assert CONTROL_REGISTRY[control_id].title == title


@pytest.mark.parametrize(
    ("trail", "is_logging", "selectors", "expected_status"),
    [
        (_trail(), True, [_management_selector()], FindingStatus.PASS),
        (
            _trail(IsMultiRegionTrail=False),
            False,
            [_management_selector(ReadWriteType="ReadOnly")],
            FindingStatus.FAIL,
        ),
    ],
)
def test_cis_3_1_cloudtrail_enabled_all_regions(
    trail: dict[str, Any],
    is_logging: bool,
    selectors: list[dict[str, Any]],
    expected_status: FindingStatus,
) -> None:
    bundle, cloudtrail_stub, _s3_stub = _bundle()
    _describe_trails(cloudtrail_stub, [trail])
    _trail_status(cloudtrail_stub, trail, is_logging=is_logging)
    _event_selectors(cloudtrail_stub, trail, selectors)

    with cloudtrail_stub:
        findings = check_cis_3_1_cloudtrail_enabled_all_regions(bundle, _UnusedPaginator())

    assert findings[0].status is expected_status


def test_cis_3_1_cloudtrail_enabled_all_regions_returns_manual_check_on_denied() -> None:
    bundle, cloudtrail_stub, _s3_stub = _bundle()
    _access_denied(cloudtrail_stub, "describe_trails")

    with cloudtrail_stub:
        findings = check_cis_3_1_cloudtrail_enabled_all_regions(bundle, _UnusedPaginator())

    assert findings[0].status is FindingStatus.MANUAL_CHECK


def test_cis_3_1_cloudtrail_enabled_all_regions_accepts_advanced_management_selectors() -> None:
    bundle, cloudtrail_stub, _s3_stub = _bundle()
    trail = _trail()
    _describe_trails(cloudtrail_stub, [trail])
    _trail_status(cloudtrail_stub, trail)
    _advanced_event_selectors(cloudtrail_stub, trail, [_advanced_management_selector()])

    with cloudtrail_stub:
        findings = check_cis_3_1_cloudtrail_enabled_all_regions(bundle, _UnusedPaginator())

    assert findings[0].status is FindingStatus.PASS


@pytest.mark.parametrize(
    ("trails", "expected_status"),
    [
        ([_trail(LogFileValidationEnabled=True)], FindingStatus.PASS),
        ([_trail(LogFileValidationEnabled=False)], FindingStatus.FAIL),
    ],
)
def test_cis_3_2_log_file_validation_enabled(
    trails: list[dict[str, Any]],
    expected_status: FindingStatus,
) -> None:
    bundle, cloudtrail_stub, _s3_stub = _bundle()
    _describe_trails(cloudtrail_stub, trails)

    with cloudtrail_stub:
        findings = check_cis_3_2_log_file_validation_enabled(bundle, _UnusedPaginator())

    assert findings[0].status is expected_status


def test_cis_3_2_log_file_validation_enabled_returns_manual_check_on_denied() -> None:
    bundle, cloudtrail_stub, _s3_stub = _bundle()
    _access_denied(cloudtrail_stub, "describe_trails")

    with cloudtrail_stub:
        findings = check_cis_3_2_log_file_validation_enabled(bundle, _UnusedPaginator())

    assert findings[0].status is FindingStatus.MANUAL_CHECK


@pytest.mark.parametrize(
    ("logging_response", "expected_status"),
    [
        (
            {"LoggingEnabled": {"TargetBucket": "s3-access-logs", "TargetPrefix": "cloudtrail/"}},
            FindingStatus.PASS,
        ),
        ({}, FindingStatus.FAIL),
    ],
)
def test_cis_3_4_cloudtrail_bucket_access_logging_enabled(
    logging_response: dict[str, Any],
    expected_status: FindingStatus,
) -> None:
    bundle, cloudtrail_stub, s3_stub = _bundle()
    trail = _trail()
    _describe_trails(cloudtrail_stub, [trail])
    s3_stub.add_response(
        "get_bucket_logging",
        logging_response,
        {"Bucket": trail["S3BucketName"]},
    )

    with cloudtrail_stub, s3_stub:
        findings = check_cis_3_4_cloudtrail_bucket_access_logging_enabled(
            bundle,
            _UnusedPaginator(),
        )

    assert findings[0].status is expected_status


def test_cis_3_4_cloudtrail_bucket_access_logging_returns_manual_check_on_s3_denied() -> None:
    bundle, cloudtrail_stub, s3_stub = _bundle()
    trail = _trail()
    _describe_trails(cloudtrail_stub, [trail])
    s3_stub.add_client_error(
        "get_bucket_logging",
        service_error_code="AccessDenied",
        service_message="not authorized",
        http_status_code=403,
        expected_params={"Bucket": trail["S3BucketName"]},
    )

    with cloudtrail_stub, s3_stub:
        findings = check_cis_3_4_cloudtrail_bucket_access_logging_enabled(
            bundle,
            _UnusedPaginator(),
        )

    assert findings[0].status is FindingStatus.MANUAL_CHECK


@pytest.mark.parametrize(
    ("trails", "expected_status"),
    [
        ([_trail()], FindingStatus.PASS),
        ([_trail(KmsKeyId="")], FindingStatus.FAIL),
    ],
)
def test_cis_3_5_cloudtrail_kms_encryption_enabled(
    trails: list[dict[str, Any]],
    expected_status: FindingStatus,
) -> None:
    bundle, cloudtrail_stub, _s3_stub = _bundle()
    _describe_trails(cloudtrail_stub, trails)

    with cloudtrail_stub:
        findings = check_cis_3_5_cloudtrail_kms_encryption_enabled(bundle, _UnusedPaginator())

    assert findings[0].status is expected_status


def test_cis_3_5_cloudtrail_kms_encryption_enabled_returns_manual_check_on_denied() -> None:
    bundle, cloudtrail_stub, _s3_stub = _bundle()
    _access_denied(cloudtrail_stub, "describe_trails")

    with cloudtrail_stub:
        findings = check_cis_3_5_cloudtrail_kms_encryption_enabled(bundle, _UnusedPaginator())

    assert findings[0].status is FindingStatus.MANUAL_CHECK


@pytest.mark.parametrize(
    ("trails", "expected_status"),
    [
        ([_trail()], FindingStatus.PASS),
        ([_trail(CloudWatchLogsLogGroupArn="")], FindingStatus.FAIL),
    ],
)
def test_ehc_ct_1_cloudwatch_logs_integration(
    trails: list[dict[str, Any]],
    expected_status: FindingStatus,
) -> None:
    bundle, cloudtrail_stub, _s3_stub = _bundle()
    _describe_trails(cloudtrail_stub, trails)

    with cloudtrail_stub:
        findings = check_ehc_ct_1_cloudwatch_logs_integration(bundle, _UnusedPaginator())

    assert findings[0].status is expected_status


def test_ehc_ct_1_cloudwatch_logs_integration_returns_manual_check_on_denied() -> None:
    bundle, cloudtrail_stub, _s3_stub = _bundle()
    _access_denied(cloudtrail_stub, "describe_trails")

    with cloudtrail_stub:
        findings = check_ehc_ct_1_cloudwatch_logs_integration(bundle, _UnusedPaginator())

    assert findings[0].status is FindingStatus.MANUAL_CHECK


@pytest.mark.parametrize(
    ("policy_status", "public_access_block", "expected_status"),
    [
        (
            {"PolicyStatus": {"IsPublic": False}},
            {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
            },
            FindingStatus.PASS,
        ),
        (
            {"PolicyStatus": {"IsPublic": True}},
            {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": False,
                    "IgnorePublicAcls": False,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": False,
                },
            },
            FindingStatus.FAIL,
        ),
    ],
)
def test_ehc_ct_2_cloudtrail_bucket_not_public(
    policy_status: dict[str, Any],
    public_access_block: dict[str, Any],
    expected_status: FindingStatus,
) -> None:
    bundle, cloudtrail_stub, s3_stub = _bundle()
    trail = _trail()
    _describe_trails(cloudtrail_stub, [trail])
    s3_stub.add_response(
        "get_bucket_policy_status",
        policy_status,
        {"Bucket": trail["S3BucketName"]},
    )
    s3_stub.add_response(
        "get_public_access_block",
        public_access_block,
        {"Bucket": trail["S3BucketName"]},
    )

    with cloudtrail_stub, s3_stub:
        findings = check_ehc_ct_2_cloudtrail_bucket_not_public(bundle, _UnusedPaginator())

    assert findings[0].status is expected_status


def test_ehc_ct_2_cloudtrail_bucket_not_public_returns_manual_check_on_s3_denied() -> None:
    bundle, cloudtrail_stub, s3_stub = _bundle()
    trail = _trail()
    _describe_trails(cloudtrail_stub, [trail])
    s3_stub.add_client_error(
        "get_bucket_policy_status",
        service_error_code="AccessDenied",
        service_message="not authorized",
        http_status_code=403,
        expected_params={"Bucket": trail["S3BucketName"]},
    )

    with cloudtrail_stub, s3_stub:
        findings = check_ehc_ct_2_cloudtrail_bucket_not_public(bundle, _UnusedPaginator())

    assert findings[0].status is FindingStatus.MANUAL_CHECK


@pytest.mark.parametrize(
    ("selectors", "expected_status"),
    [
        ([_management_selector()], FindingStatus.PASS),
        (
            [_management_selector(ExcludeManagementEventSources=["kms.amazonaws.com"])],
            FindingStatus.FAIL,
        ),
    ],
)
def test_ehc_ct_3_management_event_coverage(
    selectors: list[dict[str, Any]],
    expected_status: FindingStatus,
) -> None:
    bundle, cloudtrail_stub, _s3_stub = _bundle()
    trail = _trail()
    _describe_trails(cloudtrail_stub, [trail])
    _event_selectors(cloudtrail_stub, trail, selectors)

    with cloudtrail_stub:
        findings = check_ehc_ct_3_management_event_coverage(bundle, _UnusedPaginator())

    assert findings[0].status is expected_status


def test_ehc_ct_3_management_event_coverage_returns_manual_check_on_denied() -> None:
    bundle, cloudtrail_stub, _s3_stub = _bundle()
    trail = _trail()
    _describe_trails(cloudtrail_stub, [trail])
    cloudtrail_stub.add_client_error(
        "get_event_selectors",
        service_error_code="AccessDenied",
        service_message="not authorized",
        http_status_code=403,
        expected_params={"TrailName": trail["TrailARN"]},
    )

    with cloudtrail_stub:
        findings = check_ehc_ct_3_management_event_coverage(bundle, _UnusedPaginator())

    assert findings[0].status is FindingStatus.MANUAL_CHECK


@pytest.mark.parametrize(
    ("advanced_selectors", "expected_status"),
    [
        ([_advanced_management_selector()], FindingStatus.PASS),
        ([_advanced_management_selector(read_only_values=["true"])], FindingStatus.FAIL),
        (
            [
                _advanced_management_selector(read_only_values=["true"]),
                _advanced_management_selector(read_only_values=["false"]),
            ],
            FindingStatus.PASS,
        ),
        (
            [_advanced_management_selector(excluded_sources=["kms.amazonaws.com"])],
            FindingStatus.FAIL,
        ),
    ],
)
def test_ehc_ct_3_management_event_coverage_evaluates_advanced_selectors(
    advanced_selectors: list[dict[str, Any]],
    expected_status: FindingStatus,
) -> None:
    bundle, cloudtrail_stub, _s3_stub = _bundle()
    trail = _trail()
    _describe_trails(cloudtrail_stub, [trail])
    _advanced_event_selectors(cloudtrail_stub, trail, advanced_selectors)

    with cloudtrail_stub:
        findings = check_ehc_ct_3_management_event_coverage(bundle, _UnusedPaginator())

    assert findings[0].status is expected_status
