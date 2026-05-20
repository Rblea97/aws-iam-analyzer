"""Shared helpers for scanner checks."""

# mypy: disable-error-code=import-untyped

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Any

from botocore.exceptions import ClientError, EndpointConnectionError

from iam_analyzer.checks.registry import CONTROL_REGISTRY
from iam_analyzer.models import Finding, FindingStatus, Severity

CONTROL_SEVERITIES: dict[str, Severity] = {
    "CIS-1.3": Severity.HIGH,
    "CIS-1.4": Severity.HIGH,
    "CIS-1.5": Severity.HIGH,
    "CIS-1.6": Severity.HIGH,
    "CIS-1.7": Severity.MEDIUM,
    "CIS-1.8": Severity.MEDIUM,
    "CIS-1.9": Severity.HIGH,
    "CIS-1.10": Severity.MEDIUM,
    "CIS-1.11": Severity.MEDIUM,
    "CIS-1.12": Severity.MEDIUM,
    "CIS-1.13": Severity.HIGH,
    "CIS-1.14": Severity.MEDIUM,
    "CIS-1.15": Severity.HIGH,
    "CIS-1.16": Severity.LOW,
    "CIS-1.17": Severity.MEDIUM,
    "CIS-1.18": Severity.LOW,
    "CIS-1.19": Severity.MEDIUM,
    "CIS-1.20": Severity.MEDIUM,
    "CIS-1.21": Severity.MEDIUM,
    "CIS-3.1": Severity.HIGH,
    "CIS-3.2": Severity.MEDIUM,
    "CIS-3.4": Severity.MEDIUM,
    "CIS-3.5": Severity.MEDIUM,
    "EHC-CT-1": Severity.LOW,
    "EHC-CT-2": Severity.HIGH,
    "EHC-CT-3": Severity.MEDIUM,
}


def control_severity(control_id: str) -> Severity:
    """Return the default risk severity for a registered control."""
    return CONTROL_SEVERITIES.get(control_id, Severity.MEDIUM)


def finding(  # noqa: PLR0913
    *,
    control_id: str,
    status: FindingStatus,
    resource_id: str | None,
    remediation: str,
    raw_evidence: dict[str, Any],
    severity: Severity | None = None,
) -> Finding:
    """Build a validated finding using registry title metadata."""
    return Finding(
        control_id=control_id,
        control_title=CONTROL_REGISTRY[control_id].title,
        severity=severity or control_severity(control_id),
        status=status,
        resource_id=resource_id,
        remediation=remediation,
        raw_evidence=json_safe(raw_evidence),
    )


def manual_check(
    *,
    control_id: str,
    error: Exception,
    service: str,
    docs_url: str,
) -> list[Finding]:
    """Return a manual-check finding while preserving control severity."""
    return [
        finding(
            control_id=control_id,
            status=FindingStatus.MANUAL_CHECK,
            resource_id=None,
            remediation=(
                f"Review {control_id} manually because the scanner could not evaluate it. "
                f"Grant the documented read-only {service} permissions and rerun the scan. "
                f"AWS documentation: {docs_url}"
            ),
            raw_evidence={"error": error_evidence(error)},
        ),
    ]


def error_evidence(error: Exception) -> dict[str, str]:
    """Convert AWS or scanner exceptions into JSON-safe evidence."""
    if isinstance(error, ClientError):
        error_data = error.response.get("Error", {})
        return {
            "code": str(error_data.get("Code", "ClientError")),
            "message": str(error_data.get("Message", "AWS client error")),
        }
    if isinstance(error, EndpointConnectionError):
        return {"code": "EndpointConnectionError", "message": str(error)}
    return {"code": type(error).__name__, "message": str(error)}


def evidence_error(control_id: str, code: str, message: str) -> ClientError:
    """Create a ClientError for missing or malformed local evidence."""
    return ClientError({"Error": {"Code": code, "Message": message}}, control_id)


def json_safe(value: object) -> Any:  # noqa: ANN401
    """Normalize common AWS response values into JSON-safe values."""
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat().replace("+00:00", "Z")
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(key): json_safe(item) for key, item in value.items()}
    if isinstance(value, list):
        return [json_safe(item) for item in value]
    if isinstance(value, tuple):
        return [json_safe(item) for item in value]
    return value
