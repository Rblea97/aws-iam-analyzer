"""IAM credential report checks."""

# mypy: disable-error-code=import-untyped

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from botocore.exceptions import ClientError, EndpointConnectionError

from iam_analyzer.checks.common import evidence_error, finding
from iam_analyzer.checks.iam.common import AWS_DOCS_IAM_URL, iam_manual_check
from iam_analyzer.checks.iam.credential_report_source import (
    get_credential_report,
    parse_aws_datetime,
)
from iam_analyzer.models import Finding, FindingStatus

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from iam_analyzer.scanner.pagination import PaginatorUtil

UNUSED_CREDENTIAL_DAYS = 45


def _find_root_row(rows: Iterable[Mapping[str, str]]) -> Mapping[str, str] | None:
    return next((row for row in rows if row.get("user") == "<root_account>"), None)


def _is_true(value: str | None) -> bool:
    return value == "true"


def _days_old(value: str, *, now: datetime) -> int | None:
    parsed = parse_aws_datetime(value)
    return None if parsed is None else (now - parsed).days


def _best_available_age(
    row: Mapping[str, str],
    candidates: tuple[str, ...],
    *,
    now: datetime,
) -> int | None:
    for field in candidates:
        age = _days_old(row.get(field, "N/A"), now=now)
        if age is not None:
            return age
    return None


def _access_key_fields(index: int) -> tuple[str, str, str]:
    return (
        f"access_key_{index}_active",
        f"access_key_{index}_last_rotated",
        f"access_key_{index}_last_used_date",
    )


def check_cis_1_3_root_access_key_absent(
    client: Any,  # noqa: ANN401
    paginator_util: PaginatorUtil,  # noqa: ARG001
) -> list[Finding]:
    """CIS-1.3: Ensure no root user account access key exists."""
    control_id = "CIS-1.3"
    try:
        root_row = _find_root_row(get_credential_report(client))
    except (ClientError, EndpointConnectionError) as error:
        return iam_manual_check(control_id, error)

    if root_row is None:
        message = "Root row missing"
        return iam_manual_check(control_id, evidence_error(control_id, "MissingEvidence", message))

    active_keys = _root_active_key_fields(root_row)
    root_arn = root_row.get("arn") or None
    return [
        finding(
            control_id=control_id,
            status=FindingStatus.FAIL if active_keys else FindingStatus.PASS,
            resource_id=root_arn,
            remediation=(
                f"For {control_id}, delete root user access keys and use IAM roles or users "
                f"for operational access. AWS IAM documentation: {AWS_DOCS_IAM_URL}"
            ),
            raw_evidence={
                "root_access_keys_active": active_keys,
                "root_resource_id": root_arn or "unknown",
            },
        ),
    ]


def _root_active_key_fields(root_row: Mapping[str, str]) -> list[str]:
    return [
        key_name
        for key_name in ("access_key_1_active", "access_key_2_active")
        if _is_true(root_row.get(key_name))
    ]


def check_cis_1_9_console_users_have_mfa(
    client: Any,  # noqa: ANN401
    paginator_util: PaginatorUtil,  # noqa: ARG001
) -> list[Finding]:
    """CIS-1.9: Ensure MFA is enabled for all IAM console users."""
    control_id = "CIS-1.9"
    try:
        rows = get_credential_report(client)
    except (ClientError, EndpointConnectionError) as error:
        return iam_manual_check(control_id, error)
    non_compliant = [row for row in rows if _console_user_without_mfa(row)]
    return [
        finding(
            control_id=control_id,
            status=FindingStatus.FAIL if non_compliant else FindingStatus.PASS,
            resource_id=None,
            remediation=(
                f"For {control_id}, enable MFA for every IAM user with console access. "
                f"AWS IAM documentation: {AWS_DOCS_IAM_URL}id_credentials_mfa_enable.html"
            ),
            raw_evidence={"users_without_mfa": non_compliant},
        ),
    ]


def _console_user_without_mfa(row: Mapping[str, str]) -> bool:
    return (
        row.get("user") != "<root_account>"
        and _is_true(row.get("password_enabled"))
        and not _is_true(row.get("mfa_active"))
    )


def check_cis_1_11_unused_credentials_removed(
    client: Any,  # noqa: ANN401
    paginator_util: PaginatorUtil,  # noqa: ARG001
) -> list[Finding]:
    """CIS-1.11: Ensure credentials unused for 45 days or more are removed."""
    control_id = "CIS-1.11"
    try:
        rows = get_credential_report(client)
        stale_credentials = _stale_credentials(rows, now=datetime.now(UTC))
    except (ClientError, EndpointConnectionError) as error:
        return iam_manual_check(control_id, error)
    return [
        finding(
            control_id=control_id,
            status=FindingStatus.FAIL if stale_credentials else FindingStatus.PASS,
            resource_id=None,
            remediation=(
                f"For {control_id}, remove or disable IAM credentials unused for 45 days or more. "
                f"AWS IAM documentation: {AWS_DOCS_IAM_URL}id_credentials_finding-unused.html"
            ),
            raw_evidence={"stale_credentials": stale_credentials},
        ),
    ]


def _stale_credentials(rows: Iterable[Mapping[str, str]], *, now: datetime) -> list[dict[str, Any]]:
    stale: list[dict[str, Any]] = []
    for row in rows:
        if row.get("user") == "<root_account>":
            continue
        _append_stale_password(stale, row, now=now)
        for index in (1, 2):
            _append_stale_access_key(stale, row, index=index, now=now)
    return stale


def _append_stale_password(
    stale: list[dict[str, Any]],
    row: Mapping[str, str],
    *,
    now: datetime,
) -> None:
    age = _best_available_age(
        row,
        ("password_last_used", "password_last_changed", "user_creation_time"),
        now=now,
    )
    if _is_true(row.get("password_enabled")) and _credential_is_stale(age):
        stale.append({"user": row.get("user"), "credential": "password", "age_days": age})


def _append_stale_access_key(
    stale: list[dict[str, Any]],
    row: Mapping[str, str],
    *,
    index: int,
    now: datetime,
) -> None:
    active_field, rotated_field, last_used_field = _access_key_fields(index)
    age = _best_available_age(row, (last_used_field, rotated_field, "user_creation_time"), now=now)
    if _is_true(row.get(active_field)) and _credential_is_stale(age):
        stale.append(
            {"user": row.get("user"), "credential": f"access_key_{index}", "age_days": age},
        )


def _credential_is_stale(age_days: int | None) -> bool:
    return age_days is None or age_days >= UNUSED_CREDENTIAL_DAYS
