"""IAM checks for CIS AWS Foundations Benchmark v5.0.0 controls.

Each check accepts a pre-initialized IAM client and shared paginator utility,
returns validated findings, and converts AWS access gaps into MANUAL_CHECK
findings instead of raising to the scanner layer.
"""

# mypy: disable-error-code=import-untyped

from __future__ import annotations

import csv
import json
from datetime import UTC, date, datetime
from typing import TYPE_CHECKING, Any
from urllib.parse import unquote

from botocore.exceptions import ClientError, EndpointConnectionError

from iam_analyzer.checks.registry import CONTROL_REGISTRY
from iam_analyzer.models import Finding, FindingStatus, Severity

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

    from iam_analyzer.scanner.pagination import PaginatorUtil

ROOT_ARN = "arn:aws:iam::123456789012:root"
SUPPORT_POLICY_ARN = "arn:aws:iam::aws:policy/AWSSupportAccess"
CLOUDSHELL_POLICY_ARN = "arn:aws:iam::aws:policy/AWSCloudShellFullAccess"
AWS_DOCS_IAM_URL = "https://docs.aws.amazon.com/IAM/latest/UserGuide/"
ROTATION_DAYS = 90
UNUSED_CREDENTIAL_DAYS = 45
MINIMUM_PASSWORD_LENGTH = 14
PASSWORD_REUSE_PREVENTION = 24
CREDENTIAL_REPORT_GENERATION_ATTEMPTS = 3
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
                f"Grant the documented read-only IAM permissions and rerun the scan. "
                f"AWS IAM documentation: {AWS_DOCS_IAM_URL}"
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


def _get_credential_report(client: Any) -> list[dict[str, str]]:  # noqa: ANN401
    last_error: ClientError | None = None
    generation_complete = False
    for attempt in range(CREDENTIAL_REPORT_GENERATION_ATTEMPTS + 1):
        try:
            response = client.get_credential_report()
            content = response["Content"].decode("utf-8")
            return list(csv.DictReader(content.splitlines()))
        except ClientError as error:
            error_code = error.response.get("Error", {}).get("Code")
            if error_code not in CREDENTIAL_REPORT_RETRYABLE_ERRORS:
                raise
            last_error = error

        if generation_complete or attempt == CREDENTIAL_REPORT_GENERATION_ATTEMPTS:
            break

        generation = client.generate_credential_report()
        generation_complete = generation.get("State") == "COMPLETE"
        generation_pending = generation.get("State") in CREDENTIAL_REPORT_PENDING_STATES
        if not generation_complete and not generation_pending:
            break

    if last_error is not None:
        raise last_error

    operation_name = "credential_report"
    message = "Credential report did not become ready"
    raise _missing_evidence_error(operation_name, message)


def _find_root_row(rows: Iterable[Mapping[str, str]]) -> Mapping[str, str] | None:
    return next((row for row in rows if row.get("user") == "<root_account>"), None)


def _parse_aws_datetime(value: str) -> datetime | None:
    if value in {"", "N/A", "no_information", "not_supported"}:
        return None
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _is_true(value: str | None) -> bool:
    return value == "true"


def _days_old(value: str, *, now: datetime) -> int | None:
    parsed = _parse_aws_datetime(value)
    if parsed is None:
        return None
    return (now - parsed).days


def _access_key_fields(index: int) -> tuple[str, str, str]:
    return (
        f"access_key_{index}_active",
        f"access_key_{index}_last_rotated",
        f"access_key_{index}_last_used_date",
    )


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


def _policy_statement_list(document: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        return [statements]
    if isinstance(statements, list):
        return [statement for statement in statements if isinstance(statement, dict)]
    return []


def _normalize_policy_document(document: object) -> Mapping[str, Any]:
    if isinstance(document, dict):
        return document
    if isinstance(document, str):
        decoded = unquote(document)
        loaded = json.loads(decoded)
        if isinstance(loaded, dict):
            return loaded
    return {}


def _as_string_list(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def _statement_allows_admin(statement: Mapping[str, Any]) -> bool:
    if statement.get("Effect") != "Allow":
        return False
    resources = _as_string_list(statement.get("Resource"))
    actions = _as_string_list(statement.get("Action"))
    return "*" in actions and "*" in resources


def check_cis_1_3_root_access_key_absent(
    client: Any,  # noqa: ANN401
    paginator_util: PaginatorUtil,  # noqa: ARG001
) -> list[Finding]:
    """CIS-1.3: Ensure no root user account access key exists.

    Audit procedure: review the IAM credential report and verify both root
    access key columns are inactive.
    """
    control_id = "CIS-1.3"
    try:
        root_row = _find_root_row(_get_credential_report(client))
    except (ClientError, EndpointConnectionError) as error:
        return _manual_check(control_id, error)

    if root_row is None:
        return _manual_check(
            control_id,
            _missing_evidence_error(control_id, "Root row missing"),
        )

    active_keys = [
        key_name
        for key_name in ("access_key_1_active", "access_key_2_active")
        if _is_true(root_row.get(key_name))
    ]
    status = FindingStatus.FAIL if active_keys else FindingStatus.PASS
    return [
        _finding(
            control_id=control_id,
            severity=Severity.HIGH,
            status=status,
            resource_id=root_row.get("arn") or ROOT_ARN,
            remediation=(
                f"For {control_id}, delete root user access keys and use IAM roles or users "
                f"for operational access. AWS IAM documentation: {AWS_DOCS_IAM_URL}"
            ),
            raw_evidence={"root_access_keys_active": active_keys, "root_row": dict(root_row)},
        ),
    ]


def check_cis_1_5_root_hardware_mfa_enabled(
    client: Any,  # noqa: ANN401
    paginator_util: PaginatorUtil,
) -> list[Finding]:
    """CIS-1.5: Ensure hardware MFA is enabled for the root user account.

    Audit procedure: verify root MFA is enabled and no root virtual MFA device
    is assigned, indicating the account uses hardware MFA.
    """
    control_id = "CIS-1.5"
    try:
        summary = client.get_account_summary()
        virtual_devices = paginator_util.paginate(
            client,
            "list_virtual_mfa_devices",
            "VirtualMFADevices",
            AssignmentStatus="Assigned",
        )
    except (ClientError, EndpointConnectionError) as error:
        return _manual_check(control_id, error)

    root_virtual_devices = [
        device
        for device in virtual_devices
        if str(device.get("SerialNumber", "")).endswith("root-account-mfa-device")
    ]
    mfa_enabled = summary.get("SummaryMap", {}).get("AccountMFAEnabled") == 1
    status = FindingStatus.PASS if mfa_enabled and not root_virtual_devices else FindingStatus.FAIL
    return [
        _finding(
            control_id=control_id,
            severity=Severity.HIGH,
            status=status,
            resource_id=None,
            remediation=(
                f"For {control_id}, enable a hardware MFA device for the root user account. "
                f"AWS IAM documentation: {AWS_DOCS_IAM_URL}id_credentials_mfa_enable_physical.html"
            ),
            raw_evidence={
                "account_mfa_enabled": mfa_enabled,
                "root_virtual_mfa_devices": root_virtual_devices,
            },
        ),
    ]


def _password_policy_check(
    *,
    control_id: str,
    evidence_key: str,
    compliant: bool,
    remediation: str,
    raw_policy: Mapping[str, Any],
) -> list[Finding]:
    return [
        _finding(
            control_id=control_id,
            severity=Severity.MEDIUM,
            status=FindingStatus.PASS if compliant else FindingStatus.FAIL,
            resource_id=None,
            remediation=remediation,
            raw_evidence={"password_policy": raw_policy, "evaluated_key": evidence_key},
        ),
    ]


def _get_password_policy(client: Any) -> Mapping[str, Any]:  # noqa: ANN401
    try:
        response = client.get_account_password_policy()
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == "NoSuchEntity":
            return {}
        raise
    policy = response.get("PasswordPolicy", {})
    if isinstance(policy, dict):
        return policy
    return {}


def check_cis_1_7_password_min_length_14(
    client: Any,  # noqa: ANN401
    paginator_util: PaginatorUtil,  # noqa: ARG001
) -> list[Finding]:
    """CIS-1.7: Ensure IAM password policy requires minimum length of 14 or greater.

    Audit procedure: inspect the account password policy MinimumPasswordLength value.
    """
    control_id = "CIS-1.7"
    try:
        policy = _get_password_policy(client)
    except (ClientError, EndpointConnectionError) as error:
        return _manual_check(control_id, error)
    return _password_policy_check(
        control_id=control_id,
        evidence_key="MinimumPasswordLength",
        compliant=int(policy.get("MinimumPasswordLength", 0)) >= MINIMUM_PASSWORD_LENGTH,
        remediation=(
            f"For {control_id}, set the IAM password policy minimum password length to "
            f"14 or greater. AWS IAM documentation: "
            f"{AWS_DOCS_IAM_URL}id_credentials_passwords_account-policy.html"
        ),
        raw_policy=policy,
    )


def check_cis_1_8_password_reuse_prevention(
    client: Any,  # noqa: ANN401
    paginator_util: PaginatorUtil,  # noqa: ARG001
) -> list[Finding]:
    """CIS-1.8: Ensure IAM password policy prevents password reuse.

    Audit procedure: inspect PasswordReusePrevention and verify it is 24 or greater.
    """
    control_id = "CIS-1.8"
    try:
        policy = _get_password_policy(client)
    except (ClientError, EndpointConnectionError) as error:
        return _manual_check(control_id, error)
    return _password_policy_check(
        control_id=control_id,
        evidence_key="PasswordReusePrevention",
        compliant=int(policy.get("PasswordReusePrevention", 0)) >= PASSWORD_REUSE_PREVENTION,
        remediation=(
            f"For {control_id}, set IAM password reuse prevention to 24 remembered passwords. "
            f"AWS IAM documentation: {AWS_DOCS_IAM_URL}id_credentials_passwords_account-policy.html"
        ),
        raw_policy=policy,
    )


def check_cis_1_9_console_users_have_mfa(
    client: Any,  # noqa: ANN401
    paginator_util: PaginatorUtil,  # noqa: ARG001
) -> list[Finding]:
    """CIS-1.9: Ensure MFA is enabled for all IAM users that have a console password.

    Audit procedure: review the credential report for password-enabled IAM users
    with mfa_active set to false.
    """
    control_id = "CIS-1.9"
    try:
        rows = _get_credential_report(client)
    except (ClientError, EndpointConnectionError) as error:
        return _manual_check(control_id, error)
    non_compliant = [
        row
        for row in rows
        if row.get("user") != "<root_account>"
        and _is_true(row.get("password_enabled"))
        and not _is_true(row.get("mfa_active"))
    ]
    return [
        _finding(
            control_id=control_id,
            severity=Severity.HIGH,
            status=FindingStatus.FAIL if non_compliant else FindingStatus.PASS,
            resource_id=None,
            remediation=(
                f"For {control_id}, enable MFA for every IAM user with console access. "
                f"AWS IAM documentation: {AWS_DOCS_IAM_URL}id_credentials_mfa_enable.html"
            ),
            raw_evidence={"users_without_mfa": non_compliant},
        ),
    ]


def check_cis_1_11_unused_credentials_removed(
    client: Any,  # noqa: ANN401
    paginator_util: PaginatorUtil,  # noqa: ARG001
) -> list[Finding]:
    """CIS-1.11: Ensure credentials unused for 45 days or more are removed.

    Audit procedure: review credential report password and access key last-used
    dates and flag active credentials unused for at least 45 days.
    """
    control_id = "CIS-1.11"
    now = datetime.now(UTC)
    try:
        rows = _get_credential_report(client)
    except (ClientError, EndpointConnectionError) as error:
        return _manual_check(control_id, error)

    stale_credentials: list[dict[str, Any]] = []
    for row in rows:
        if row.get("user") == "<root_account>":
            continue
        password_age = _best_available_age(
            row,
            ("password_last_used", "password_last_changed", "user_creation_time"),
            now=now,
        )
        if _is_true(row.get("password_enabled")) and (
            password_age is None or password_age >= UNUSED_CREDENTIAL_DAYS
        ):
            stale_credentials.append(
                {
                    "user": row.get("user"),
                    "credential": "password",
                    "age_days": password_age,
                },
            )
        for index in (1, 2):
            active_field, rotated_field, last_used_field = _access_key_fields(index)
            key_age = _best_available_age(
                row,
                (last_used_field, rotated_field, "user_creation_time"),
                now=now,
            )
            if _is_true(row.get(active_field)) and (
                key_age is None or key_age >= UNUSED_CREDENTIAL_DAYS
            ):
                stale_credentials.append(
                    {
                        "user": row.get("user"),
                        "credential": f"access_key_{index}",
                        "age_days": key_age,
                    },
                )

    return [
        _finding(
            control_id=control_id,
            severity=Severity.MEDIUM,
            status=FindingStatus.FAIL if stale_credentials else FindingStatus.PASS,
            resource_id=None,
            remediation=(
                f"For {control_id}, remove or disable IAM credentials unused for 45 days or more. "
                f"AWS IAM documentation: {AWS_DOCS_IAM_URL}id_credentials_finding-unused.html"
            ),
            raw_evidence={"stale_credentials": stale_credentials},
        ),
    ]


def check_cis_1_13_access_keys_rotated(
    client: Any,  # noqa: ANN401
    paginator_util: PaginatorUtil,
) -> list[Finding]:
    """CIS-1.13: Ensure access keys are rotated every 90 days or less.

    Audit procedure: list IAM users and access keys, then flag active keys with
    creation dates older than 90 days.
    """
    control_id = "CIS-1.13"
    now = datetime.now(UTC)
    try:
        users = paginator_util.paginate(client, "list_users", "Users")
        stale_keys: list[dict[str, Any]] = []
        for user in users:
            user_name = str(user["UserName"])
            access_keys = paginator_util.paginate(
                client,
                "list_access_keys",
                "AccessKeyMetadata",
                UserName=user_name,
            )
            stale_keys.extend(
                {
                    "user": user_name,
                    "access_key_id": key.get("AccessKeyId"),
                    "age_days": (now - key["CreateDate"].astimezone(UTC)).days,
                }
                for key in access_keys
                if key.get("Status", "Active") == "Active"
                and (now - key["CreateDate"].astimezone(UTC)).days > ROTATION_DAYS
            )
    except (ClientError, EndpointConnectionError, KeyError) as error:
        if isinstance(error, KeyError):
            return _manual_check(
                control_id,
                _missing_evidence_error(control_id, str(error)),
            )
        return _manual_check(control_id, error)

    return [
        _finding(
            control_id=control_id,
            severity=Severity.HIGH,
            status=FindingStatus.FAIL if stale_keys else FindingStatus.PASS,
            resource_id=None,
            remediation=(
                f"For {control_id}, rotate IAM access keys that are older than 90 days. "
                f"AWS IAM documentation: {AWS_DOCS_IAM_URL}id_credentials_access-keys.html"
            ),
            raw_evidence={"stale_access_keys": stale_keys},
        ),
    ]


def check_cis_1_14_no_direct_user_policy_attachments(
    client: Any,  # noqa: ANN401
    paginator_util: PaginatorUtil,
) -> list[Finding]:
    """CIS-1.14: Ensure IAM users receive permissions only through groups.

    Audit procedure: list each IAM user's inline and attached policies and flag
    users with direct policy grants.
    """
    control_id = "CIS-1.14"
    try:
        users = paginator_util.paginate(client, "list_users", "Users")
        users_with_direct_policies: list[dict[str, Any]] = []
        for user in users:
            user_name = str(user["UserName"])
            inline_policies = paginator_util.paginate(
                client,
                "list_user_policies",
                "PolicyNames",
                UserName=user_name,
            )
            attached_policies = paginator_util.paginate(
                client,
                "list_attached_user_policies",
                "AttachedPolicies",
                UserName=user_name,
            )
            if inline_policies or attached_policies:
                users_with_direct_policies.append(
                    {
                        "user": user_name,
                        "inline_policies": inline_policies,
                        "attached_policies": attached_policies,
                    },
                )
    except (ClientError, EndpointConnectionError, KeyError) as error:
        if isinstance(error, KeyError):
            return _manual_check(
                control_id,
                _missing_evidence_error(control_id, str(error)),
            )
        return _manual_check(control_id, error)

    return [
        _finding(
            control_id=control_id,
            severity=Severity.MEDIUM,
            status=FindingStatus.FAIL if users_with_direct_policies else FindingStatus.PASS,
            resource_id=None,
            remediation=(
                f"For {control_id}, remove direct user policies and grant permissions "
                f"through groups. AWS IAM documentation: "
                f"{AWS_DOCS_IAM_URL}access_policies_manage-attach-detach.html"
            ),
            raw_evidence={"users_with_direct_policies": users_with_direct_policies},
        ),
    ]


def check_cis_1_15_no_admin_wildcard_policies(
    client: Any,  # noqa: ANN401
    paginator_util: PaginatorUtil,
) -> list[Finding]:
    """CIS-1.15: Ensure IAM policies that allow full admin privileges are not attached.

    Audit procedure: review attached customer managed policies and flag Allow
    statements granting wildcard actions over wildcard resources.
    """
    control_id = "CIS-1.15"
    try:
        policies = paginator_util.paginate(
            client,
            "list_policies",
            "Policies",
            OnlyAttached=True,
        )
        admin_policies: list[dict[str, Any]] = []
        for policy in policies:
            policy_arn = str(policy["Arn"])
            metadata = client.get_policy(PolicyArn=policy_arn)["Policy"]
            version_id = str(metadata["DefaultVersionId"])
            version = client.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
            document = _normalize_policy_document(version["PolicyVersion"]["Document"])
            if any(
                _statement_allows_admin(statement) for statement in _policy_statement_list(document)
            ):
                admin_policies.append({"policy_arn": policy_arn, "default_version_id": version_id})
    except (ClientError, EndpointConnectionError, KeyError, json.JSONDecodeError) as error:
        if isinstance(error, (KeyError, json.JSONDecodeError)):
            return _manual_check(
                control_id,
                _missing_evidence_error(control_id, str(error)),
            )
        return _manual_check(control_id, error)

    return [
        _finding(
            control_id=control_id,
            severity=Severity.HIGH,
            status=FindingStatus.FAIL if admin_policies else FindingStatus.PASS,
            resource_id=None,
            remediation=(
                f"For {control_id}, detach or replace policies that allow Action '*' "
                f"on Resource '*'. "
                f"AWS IAM documentation: {AWS_DOCS_IAM_URL}access_policies.html"
            ),
            raw_evidence={"admin_policies": admin_policies},
        ),
    ]


def check_cis_1_16_support_role_exists(
    client: Any,  # noqa: ANN401
    paginator_util: PaginatorUtil,
) -> list[Finding]:
    """CIS-1.16: Ensure a support role has been created for AWS Support incidents.

    Audit procedure: verify the AWS managed AWSSupportAccess policy is attached
    to at least one IAM role.
    """
    control_id = "CIS-1.16"
    try:
        support_roles = paginator_util.paginate(
            client,
            "list_entities_for_policy",
            "PolicyRoles",
            PolicyArn=SUPPORT_POLICY_ARN,
        )
    except (ClientError, EndpointConnectionError) as error:
        return _manual_check(control_id, error)
    return [
        _finding(
            control_id=control_id,
            severity=Severity.LOW,
            status=FindingStatus.PASS if support_roles else FindingStatus.FAIL,
            resource_id=None,
            remediation=(
                f"For {control_id}, create an incident response role with the "
                f"AWSSupportAccess policy. "
                f"AWS IAM documentation: {AWS_DOCS_IAM_URL}id_roles.html"
            ),
            raw_evidence={"support_roles": support_roles},
        ),
    ]


def check_cis_1_21_cloudshell_full_access_restricted(
    client: Any,  # noqa: ANN401
    paginator_util: PaginatorUtil,
) -> list[Finding]:
    """CIS-1.21: Ensure access to AWSCloudShellFullAccess is restricted.

    Audit procedure: verify AWSCloudShellFullAccess is not attached to IAM users,
    roles, or groups unless explicitly justified.
    """
    control_id = "CIS-1.21"
    try:
        users = paginator_util.paginate(
            client,
            "list_entities_for_policy",
            "PolicyUsers",
            PolicyArn=CLOUDSHELL_POLICY_ARN,
        )
        roles = paginator_util.paginate(
            client,
            "list_entities_for_policy",
            "PolicyRoles",
            PolicyArn=CLOUDSHELL_POLICY_ARN,
        )
        groups = paginator_util.paginate(
            client,
            "list_entities_for_policy",
            "PolicyGroups",
            PolicyArn=CLOUDSHELL_POLICY_ARN,
        )
    except (ClientError, EndpointConnectionError) as error:
        return _manual_check(control_id, error)

    attached_entities = {"users": users, "roles": roles, "groups": groups}
    has_attachments = any(attached_entities.values())
    return [
        _finding(
            control_id=control_id,
            severity=Severity.MEDIUM,
            status=FindingStatus.FAIL if has_attachments else FindingStatus.PASS,
            resource_id=None,
            remediation=(
                f"For {control_id}, detach AWSCloudShellFullAccess from identities that "
                f"do not require it. AWS IAM documentation: "
                f"{AWS_DOCS_IAM_URL}access_policies_managed-vs-inline.html"
            ),
            raw_evidence=attached_entities,
        ),
    ]
