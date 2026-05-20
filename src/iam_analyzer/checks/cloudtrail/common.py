"""Shared CloudTrail check helpers."""

# mypy: disable-error-code=import-untyped

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from botocore.exceptions import ClientError

from iam_analyzer.checks.common import evidence_error, manual_check

if TYPE_CHECKING:
    from iam_analyzer.models import Finding

AWS_DOCS_CLOUDTRAIL_URL = "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/"
AWS_DOCS_S3_URL = "https://docs.aws.amazon.com/AmazonS3/latest/userguide/"


@dataclass(frozen=True, slots=True)
class LoggingClientBundle:
    """Pre-initialized AWS clients required by CloudTrail logging checks."""

    cloudtrail: Any
    s3: Any | None = None


def cloudtrail_client(client: Any) -> Any:  # noqa: ANN401
    """Return a CloudTrail client from a client bundle or plain client."""
    return client.cloudtrail if isinstance(client, LoggingClientBundle) else client


def s3_client(client: Any) -> Any:  # noqa: ANN401
    """Return the S3 client required for CloudTrail bucket checks."""
    if isinstance(client, LoggingClientBundle) and client.s3 is not None:
        return client.s3
    control_id = "cloudtrail_s3"
    message = "S3 client missing"
    raise evidence_error(control_id, "MissingEvidence", message)


def logging_manual_check(control_id: str, error: Exception) -> list[Finding]:
    """Return a manual-check finding for CloudTrail/S3 evidence gaps."""
    return manual_check(
        control_id=control_id,
        error=error,
        service="CloudTrail/S3",
        docs_url=AWS_DOCS_CLOUDTRAIL_URL,
    )


def describe_trails(client: Any) -> list[dict[str, Any]]:  # noqa: ANN401
    """Load CloudTrail trail metadata."""
    response = cloudtrail_client(client).describe_trails()
    trails = response.get("trailList", [])
    if isinstance(trails, list):
        return [trail for trail in trails if isinstance(trail, dict)]
    return []


def trail_identifier(trail: dict[str, Any]) -> str:
    """Return the most stable identifier available for a CloudTrail trail."""
    return str(trail.get("TrailARN") or trail.get("Name") or "unknown-trail")


def trail_bucket_names(trails: list[dict[str, Any]]) -> list[str]:
    """Return unique nonempty CloudTrail S3 bucket names."""
    buckets: list[str] = []
    for trail in trails:
        bucket_name = trail.get("S3BucketName")
        if isinstance(bucket_name, str) and bucket_name and bucket_name not in buckets:
            buckets.append(bucket_name)
    return buckets


def get_public_access_block(s3: Any, bucket_name: str) -> dict[str, Any]:  # noqa: ANN401
    """Return S3 public access block config, treating absent config as empty."""
    try:
        response = s3.get_public_access_block(Bucket=bucket_name)
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == "NoSuchPublicAccessBlockConfiguration":
            return {}
        raise
    config = response.get("PublicAccessBlockConfiguration", {})
    return config if isinstance(config, dict) else {}
