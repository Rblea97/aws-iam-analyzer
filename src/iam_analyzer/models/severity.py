"""Finding severity levels."""

from enum import StrEnum


class Severity(StrEnum):
    """Supported finding severity values."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class FindingStatus(StrEnum):
    """Supported finding status values."""

    PASS = "PASS"  # noqa: S105
    FAIL = "FAIL"
    MANUAL_CHECK = "MANUAL_CHECK"
    ERROR = "ERROR"
    NOT_APPLICABLE = "NOT_APPLICABLE"
