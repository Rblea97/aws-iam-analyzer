"""CloudTrail S3 bucket checks."""

# mypy: disable-error-code=import-untyped

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from botocore.exceptions import ClientError, EndpointConnectionError

from iam_analyzer.checks.cloudtrail.common import (
    AWS_DOCS_S3_URL,
    describe_trails,
    get_public_access_block,
    logging_manual_check,
    s3_client,
    trail_bucket_names,
)
from iam_analyzer.checks.common import finding
from iam_analyzer.models import Finding, FindingStatus

if TYPE_CHECKING:
    from collections.abc import Mapping

    from iam_analyzer.scanner.pagination import PaginatorUtil

ALL_PUBLIC_ACCESS_BLOCK_KEYS = frozenset(
    {
        "BlockPublicAcls",
        "IgnorePublicAcls",
        "BlockPublicPolicy",
        "RestrictPublicBuckets",
    },
)


def check_cis_3_4_cloudtrail_bucket_access_logging_enabled(
    client: Any,  # noqa: ANN401
    paginator_util: PaginatorUtil,  # noqa: ARG001
) -> list[Finding]:
    """CIS-3.4: Ensure CloudTrail S3 buckets have server access logging."""
    control_id = "CIS-3.4"
    try:
        buckets = trail_bucket_names(describe_trails(client))
        bucket_logging = _bucket_logging_evidence(s3_client(client), buckets)
    except (ClientError, EndpointConnectionError) as error:
        return logging_manual_check(control_id, error)
    missing_logging = [name for name, config in bucket_logging.items() if not config]
    return [
        finding(
            control_id=control_id,
            status=FindingStatus.FAIL if not buckets or missing_logging else FindingStatus.PASS,
            resource_id=None,
            remediation=(
                f"For {control_id}, enable S3 server access logging on every bucket that "
                f"stores CloudTrail logs. AWS S3 documentation: {AWS_DOCS_S3_URL}ServerLogs.html"
            ),
            raw_evidence={
                "cloudtrail_buckets": buckets,
                "bucket_logging": bucket_logging,
                "missing_logging": missing_logging,
            },
        ),
    ]


def _bucket_logging_evidence(s3: Any, buckets: list[str]) -> dict[str, Mapping[str, Any]]:  # noqa: ANN401
    evidence: dict[str, Mapping[str, Any]] = {}
    for bucket_name in buckets:
        response = s3.get_bucket_logging(Bucket=bucket_name)
        logging_config = response.get("LoggingEnabled", {})
        evidence[bucket_name] = logging_config if isinstance(logging_config, dict) else {}
    return evidence


def check_ehc_ct_2_cloudtrail_bucket_not_public(
    client: Any,  # noqa: ANN401
    paginator_util: PaginatorUtil,  # noqa: ARG001
) -> list[Finding]:
    """EHC-CT-2: Ensure CloudTrail S3 buckets are not public."""
    control_id = "EHC-CT-2"
    try:
        buckets = trail_bucket_names(describe_trails(client))
        bucket_evidence, public_buckets = _bucket_public_evidence(s3_client(client), buckets)
    except (ClientError, EndpointConnectionError) as error:
        return logging_manual_check(control_id, error)
    return [
        finding(
            control_id=control_id,
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


def _bucket_public_evidence(
    s3: Any,  # noqa: ANN401
    buckets: list[str],
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    evidence: dict[str, dict[str, Any]] = {}
    public_buckets: list[str] = []
    for bucket_name in buckets:
        bucket_evidence = _single_bucket_public_evidence(s3, bucket_name)
        evidence[bucket_name] = bucket_evidence
        if bucket_evidence["is_public"] or not bucket_evidence["blocks_all_public_access"]:
            public_buckets.append(bucket_name)
    return evidence, public_buckets


def _single_bucket_public_evidence(s3: Any, bucket_name: str) -> dict[str, Any]:  # noqa: ANN401
    policy_status = s3.get_bucket_policy_status(Bucket=bucket_name).get("PolicyStatus", {})
    public_access_block = get_public_access_block(s3, bucket_name)
    is_public = isinstance(policy_status, dict) and policy_status.get("IsPublic") is True
    blocks_all = all(public_access_block.get(key) is True for key in ALL_PUBLIC_ACCESS_BLOCK_KEYS)
    return {
        "policy_status": policy_status,
        "public_access_block": public_access_block,
        "blocks_all_public_access": blocks_all,
        "is_public": is_public,
    }
