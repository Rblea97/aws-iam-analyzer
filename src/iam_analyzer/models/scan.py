"""Validated scan result models."""

from __future__ import annotations

from datetime import UTC, datetime

from pydantic import BaseModel, ConfigDict, Field, field_serializer, field_validator

from iam_analyzer.models.finding import Finding  # noqa: TC001


def _serialize_utc_datetime(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


class ScanMetadata(BaseModel):
    """Metadata describing a single account scan."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    account_id: str = Field(min_length=1)
    scan_timestamp: datetime
    benchmark: str = Field(min_length=1)
    controls_evaluated: int = Field(ge=0)
    duration_ms: int = Field(ge=0)

    @field_validator("scan_timestamp")
    @classmethod
    def validate_scan_timestamp_is_utc(cls, value: datetime) -> datetime:
        """Require timezone-aware UTC scan timestamps."""
        if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
            msg = "scan_timestamp must be timezone-aware UTC"
            raise ValueError(msg)
        return value

    @field_serializer("scan_timestamp", when_used="json")
    def serialize_scan_timestamp(self, value: datetime) -> str:
        """Serialize UTC datetimes with a JSON-friendly Z suffix."""
        return _serialize_utc_datetime(value)


class ScanSummary(BaseModel):
    """Aggregated finding counts by required report bucket."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    CRITICAL: int = Field(ge=0)
    HIGH: int = Field(ge=0)
    MEDIUM: int = Field(ge=0)
    LOW: int = Field(ge=0)
    PASS: int = Field(ge=0)


class ScanResult(BaseModel):
    """Top-level JSON report shape for a scan."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    scan_metadata: ScanMetadata
    summary: ScanSummary
    findings: list[Finding]
