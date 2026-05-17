"""Validated finding model."""

from __future__ import annotations

from datetime import UTC, datetime
from math import isfinite
from typing import Any

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationInfo,
    field_serializer,
    field_validator,
    model_validator,
)

from iam_analyzer.checks.registry import CONTROL_REGISTRY, is_known_control_id
from iam_analyzer.models.severity import FindingStatus, Severity


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _serialize_utc_datetime(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _is_json_safe(value: object) -> bool:
    if value is None or isinstance(value, (str, bool, int)):
        return True
    if isinstance(value, float):
        return isfinite(value)
    if isinstance(value, list):
        return all(_is_json_safe(item) for item in value)
    if isinstance(value, dict):
        return all(isinstance(key, str) and _is_json_safe(item) for key, item in value.items())
    return False


class Finding(BaseModel):
    """Single validated control evaluation result."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    control_id: str
    control_title: str = Field(min_length=1)
    severity: Severity
    status: FindingStatus
    resource_id: str | None
    remediation: str = Field(min_length=1)
    raw_evidence: dict[str, Any]
    evaluated_at: datetime = Field(default_factory=_utc_now)

    @model_validator(mode="before")
    @classmethod
    def reject_caller_supplied_evaluated_at(cls, data: Any) -> Any:  # noqa: ANN401
        """Reject externally supplied timestamps so findings reflect evaluation time."""
        if isinstance(data, dict) and "evaluated_at" in data:
            msg = "evaluated_at is set automatically and must not be supplied"
            raise ValueError(msg)
        return data

    @field_validator("control_id")
    @classmethod
    def validate_known_control_id(cls, value: str) -> str:
        """Require every finding to reference a registered control."""
        if not is_known_control_id(value):
            msg = f"Unknown control_id: {value}"
            raise ValueError(msg)
        return value

    @field_validator("control_title")
    @classmethod
    def validate_control_title(cls, value: str, info: ValidationInfo) -> str:
        """Reject empty titles and titles that do not match registry metadata."""
        if not value.strip():
            msg = "Value must not be empty"
            raise ValueError(msg)

        control_id = info.data.get("control_id")
        if isinstance(control_id, str) and CONTROL_REGISTRY[control_id].title != value:
            msg = "control_title must match registry metadata for control_id"
            raise ValueError(msg)
        return value

    @field_validator("remediation")
    @classmethod
    def validate_non_empty_text(cls, value: str) -> str:
        """Reject empty or whitespace-only human-readable text."""
        if not value.strip():
            msg = "Value must not be empty"
            raise ValueError(msg)
        return value

    @field_validator("severity", mode="before")
    @classmethod
    def validate_severity(cls, value: object) -> object:
        """Allow exact severity strings while keeping strict model validation."""
        if isinstance(value, str):
            return Severity(value)
        return value

    @field_validator("status", mode="before")
    @classmethod
    def validate_status(cls, value: object) -> object:
        """Allow exact status strings while keeping strict model validation."""
        if isinstance(value, str):
            return FindingStatus(value)
        return value

    @field_validator("raw_evidence", mode="before")
    @classmethod
    def validate_raw_evidence_is_json_safe(cls, value: object) -> object:
        """Require raw evidence to be JSON-safe before serialization."""
        if not isinstance(value, dict) or not _is_json_safe(value):
            msg = "raw_evidence must be a JSON-safe object tree"
            raise ValueError(msg)
        return value

    @field_serializer("evaluated_at", when_used="json")
    def serialize_evaluated_at(self, value: datetime) -> str:
        """Serialize UTC datetimes with a JSON-friendly Z suffix."""
        return _serialize_utc_datetime(value)
