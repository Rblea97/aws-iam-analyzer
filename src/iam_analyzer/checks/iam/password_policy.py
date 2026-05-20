"""IAM root MFA and password policy checks."""

# mypy: disable-error-code=import-untyped

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from botocore.exceptions import ClientError, EndpointConnectionError

from iam_analyzer.checks.common import finding
from iam_analyzer.checks.iam.common import AWS_DOCS_IAM_URL, iam_manual_check
from iam_analyzer.models import Finding, FindingStatus

if TYPE_CHECKING:
    from collections.abc import Mapping

    from iam_analyzer.scanner.pagination import PaginatorUtil

MINIMUM_PASSWORD_LENGTH = 14
PASSWORD_REUSE_PREVENTION = 24


def check_cis_1_5_root_hardware_mfa_enabled(
    client: Any,  # noqa: ANN401
    paginator_util: PaginatorUtil,
) -> list[Finding]:
    """CIS-1.5: Ensure hardware MFA is enabled for the root account."""
    control_id = "CIS-1.5"
    try:
        summary = client.get_account_summary()
        devices = paginator_util.paginate(
            client,
            "list_virtual_mfa_devices",
            "VirtualMFADevices",
            AssignmentStatus="Assigned",
        )
    except (ClientError, EndpointConnectionError) as error:
        return iam_manual_check(control_id, error)

    root_virtual_devices = [device for device in devices if _is_root_virtual_mfa(device)]
    mfa_enabled = summary.get("SummaryMap", {}).get("AccountMFAEnabled") == 1
    return [
        finding(
            control_id=control_id,
            status=(
                FindingStatus.PASS
                if mfa_enabled and not root_virtual_devices
                else FindingStatus.FAIL
            ),
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


def _is_root_virtual_mfa(device: object) -> bool:
    if not isinstance(device, dict):
        return False
    return str(device.get("SerialNumber", "")).endswith("root-account-mfa-device")


def _get_password_policy(client: Any) -> Mapping[str, Any]:  # noqa: ANN401
    try:
        response = client.get_account_password_policy()
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") == "NoSuchEntity":
            return {}
        raise
    policy = response.get("PasswordPolicy", {})
    return policy if isinstance(policy, dict) else {}


def _password_policy_check(
    *,
    control_id: str,
    evidence_key: str,
    compliant: bool,
    remediation: str,
    raw_policy: Mapping[str, Any],
) -> list[Finding]:
    return [
        finding(
            control_id=control_id,
            status=FindingStatus.PASS if compliant else FindingStatus.FAIL,
            resource_id=None,
            remediation=remediation,
            raw_evidence={"password_policy": dict(raw_policy), "evaluated_key": evidence_key},
        ),
    ]


def check_cis_1_7_password_min_length_14(
    client: Any,  # noqa: ANN401
    paginator_util: PaginatorUtil,  # noqa: ARG001
) -> list[Finding]:
    """CIS-1.7: Ensure IAM password policy minimum length is at least 14."""
    control_id = "CIS-1.7"
    try:
        policy = _get_password_policy(client)
    except (ClientError, EndpointConnectionError) as error:
        return iam_manual_check(control_id, error)
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
    """CIS-1.8: Ensure IAM password policy prevents reuse."""
    control_id = "CIS-1.8"
    try:
        policy = _get_password_policy(client)
    except (ClientError, EndpointConnectionError) as error:
        return iam_manual_check(control_id, error)
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
