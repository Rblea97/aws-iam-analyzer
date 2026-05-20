"""IAM credential report collection and parsing."""

# mypy: disable-error-code=import-untyped

from __future__ import annotations

import csv
import time
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from botocore.exceptions import ClientError

from iam_analyzer.checks.common import evidence_error

if TYPE_CHECKING:
    from collections.abc import Callable

CREDENTIAL_REPORT_MAX_ATTEMPTS = 5
CREDENTIAL_REPORT_BACKOFF_SECONDS = 0.05
REPORT_CONTROL_ID = "credential_report"
MALFORMED_REPORT_CODE = "MalformedCredentialReport"
MISSING_EVIDENCE_CODE = "MissingEvidence"
CREDENTIAL_REPORT_PENDING_STATES = frozenset({"STARTED", "INPROGRESS"})
CREDENTIAL_REPORT_RETRYABLE_ERRORS = frozenset(
    {
        "ReportNotPresent",
        "CredentialReportNotPresent",
        "CredentialReportNotPresentException",
        "CredentialReportNotReady",
        "CredentialReportNotReadyException",
    },
)
REQUIRED_REPORT_FIELDS = frozenset(
    {
        "user",
        "arn",
        "user_creation_time",
        "password_enabled",
        "password_last_used",
        "password_last_changed",
        "mfa_active",
        "access_key_1_active",
        "access_key_1_last_rotated",
        "access_key_1_last_used_date",
        "access_key_2_active",
        "access_key_2_last_rotated",
        "access_key_2_last_used_date",
    },
)


def get_credential_report(
    client: Any,  # noqa: ANN401
    *,
    max_attempts: int = CREDENTIAL_REPORT_MAX_ATTEMPTS,
    sleep: Callable[[float], None] = time.sleep,
) -> list[dict[str, str]]:
    """Fetch an IAM credential report with bounded polling."""
    last_error: ClientError | None = None
    for attempt in range(1, max_attempts + 1):
        try:
            return _fetch_report(client)
        except ClientError as error:
            if not _is_retryable_report_error(error):
                raise
            last_error = error

        if not _poll_generation(client, attempt, max_attempts=max_attempts, sleep=sleep):
            break

    if last_error is not None:
        code = "CredentialReportTimeout"
        message = "Credential report did not become ready before the polling limit"
        raise evidence_error(REPORT_CONTROL_ID, code, message) from last_error
    message = "Credential report unavailable"
    raise evidence_error(REPORT_CONTROL_ID, MISSING_EVIDENCE_CODE, message)


def _fetch_report(client: Any) -> list[dict[str, str]]:  # noqa: ANN401
    response = client.get_credential_report()
    content = response.get("Content") if isinstance(response, dict) else None
    return _decode_report(content)


def _is_retryable_report_error(error: ClientError) -> bool:
    return _error_code(error) in CREDENTIAL_REPORT_RETRYABLE_ERRORS


def _poll_generation(
    client: Any,  # noqa: ANN401
    attempt: int,
    *,
    max_attempts: int,
    sleep: Callable[[float], None],
) -> bool:
    generation_state = str(client.generate_credential_report().get("State", ""))
    if generation_state == "COMPLETE":
        return True
    if generation_state not in CREDENTIAL_REPORT_PENDING_STATES:
        return False
    if attempt < max_attempts:
        sleep(CREDENTIAL_REPORT_BACKOFF_SECONDS * attempt)
    return True


def _error_code(error: ClientError) -> str:
    return str(error.response.get("Error", {}).get("Code", "ClientError"))


def _decode_report(content: object) -> list[dict[str, str]]:
    if not isinstance(content, bytes):
        message = "Content missing"
        raise evidence_error(REPORT_CONTROL_ID, MALFORMED_REPORT_CODE, message)
    rows = _read_csv_rows(content)
    missing = REQUIRED_REPORT_FIELDS.difference(rows.fieldnames or [])
    if missing:
        message = f"Credential report missing columns: {', '.join(sorted(missing))}"
        raise evidence_error(REPORT_CONTROL_ID, MALFORMED_REPORT_CODE, message)
    parsed_rows = list(rows)
    if any(None in row for row in parsed_rows):
        message = "Credential report has an unexpected column shape"
        raise evidence_error(REPORT_CONTROL_ID, MALFORMED_REPORT_CODE, message)
    return parsed_rows


def _read_csv_rows(content: bytes) -> csv.DictReader[str]:
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as error:
        message = "Credential report content is not valid UTF-8"
        raise evidence_error(REPORT_CONTROL_ID, MALFORMED_REPORT_CODE, message) from error
    return csv.DictReader(text.splitlines())


def parse_aws_datetime(value: str) -> datetime | None:
    """Parse an AWS credential-report datetime value."""
    if value in {"", "N/A", "no_information", "not_supported"}:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        message = f"Credential report contains invalid datetime value: {value}"
        raise evidence_error(REPORT_CONTROL_ID, MALFORMED_REPORT_CODE, message) from error
    return parsed.replace(tzinfo=parsed.tzinfo or UTC).astimezone(UTC)
