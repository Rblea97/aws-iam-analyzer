"""IAM access key, user-policy, and support-role checks."""

# mypy: disable-error-code=import-untyped

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from botocore.exceptions import ClientError, EndpointConnectionError

from iam_analyzer.checks.common import finding
from iam_analyzer.checks.iam.common import (
    AWS_DOCS_IAM_URL,
    iam_manual_check,
    normalize_iam_error,
)
from iam_analyzer.models import Finding, FindingStatus

if TYPE_CHECKING:
    from iam_analyzer.scanner.pagination import PaginatorUtil

SUPPORT_POLICY_ARN = "arn:aws:iam::aws:policy/AWSSupportAccess"
ROTATION_DAYS = 90


def check_cis_1_13_access_keys_rotated(
    client: Any,  # noqa: ANN401
    paginator_util: PaginatorUtil,
) -> list[Finding]:
    """CIS-1.13: Ensure active IAM access keys are rotated."""
    control_id = "CIS-1.13"
    try:
        stale_keys = _stale_access_keys(client, paginator_util, now=datetime.now(UTC))
    except (ClientError, EndpointConnectionError, KeyError) as error:
        return iam_manual_check(control_id, normalize_iam_error(control_id, error))
    return [
        finding(
            control_id=control_id,
            status=FindingStatus.FAIL if stale_keys else FindingStatus.PASS,
            resource_id=None,
            remediation=(
                f"For {control_id}, rotate IAM access keys that are older than 90 days. "
                f"AWS IAM documentation: {AWS_DOCS_IAM_URL}id_credentials_access-keys.html"
            ),
            raw_evidence={"stale_access_keys": stale_keys},
        ),
    ]


def _stale_access_keys(
    client: Any,  # noqa: ANN401
    paginator_util: PaginatorUtil,
    *,
    now: datetime,
) -> list[dict[str, Any]]:
    stale_keys: list[dict[str, Any]] = []
    for user in paginator_util.paginate(client, "list_users", "Users"):
        user_name = str(user["UserName"])
        access_keys = paginator_util.paginate(
            client,
            "list_access_keys",
            "AccessKeyMetadata",
            UserName=user_name,
        )
        stale_keys.extend(_stale_keys_for_user(user_name, access_keys, now=now))
    return stale_keys


def _stale_keys_for_user(
    user_name: str,
    access_keys: list[Any],
    *,
    now: datetime,
) -> list[dict[str, Any]]:
    return [
        {
            "user": user_name,
            "access_key_id": key.get("AccessKeyId"),
            "age_days": (now - key["CreateDate"].astimezone(UTC)).days,
        }
        for key in access_keys
        if key.get("Status", "Active") == "Active"
        and (now - key["CreateDate"].astimezone(UTC)).days > ROTATION_DAYS
    ]


def check_cis_1_14_no_direct_user_policy_attachments(
    client: Any,  # noqa: ANN401
    paginator_util: PaginatorUtil,
) -> list[Finding]:
    """CIS-1.14: Ensure IAM users receive permissions only through groups."""
    control_id = "CIS-1.14"
    try:
        direct_policies = _users_with_direct_policies(client, paginator_util)
    except (ClientError, EndpointConnectionError, KeyError) as error:
        return iam_manual_check(control_id, normalize_iam_error(control_id, error))
    return [
        finding(
            control_id=control_id,
            status=FindingStatus.FAIL if direct_policies else FindingStatus.PASS,
            resource_id=None,
            remediation=(
                f"For {control_id}, remove direct user policies and grant permissions "
                f"through groups. AWS IAM documentation: "
                f"{AWS_DOCS_IAM_URL}access_policies_manage-attach-detach.html"
            ),
            raw_evidence={"users_with_direct_policies": direct_policies},
        ),
    ]


def _users_with_direct_policies(client: Any, paginator_util: PaginatorUtil) -> list[dict[str, Any]]:  # noqa: ANN401
    direct_policies: list[dict[str, Any]] = []
    for user in paginator_util.paginate(client, "list_users", "Users"):
        user_name = str(user["UserName"])
        inline = paginator_util.paginate(
            client,
            "list_user_policies",
            "PolicyNames",
            UserName=user_name,
        )
        attached = paginator_util.paginate(
            client,
            "list_attached_user_policies",
            "AttachedPolicies",
            UserName=user_name,
        )
        if inline or attached:
            direct_policies.append(
                {
                    "user": user_name,
                    "inline_policies": inline,
                    "attached_policies": attached,
                },
            )
    return direct_policies


def check_cis_1_16_support_role_exists(
    client: Any,  # noqa: ANN401
    paginator_util: PaginatorUtil,
) -> list[Finding]:
    """CIS-1.16: Ensure a support role exists."""
    control_id = "CIS-1.16"
    try:
        roles = paginator_util.paginate(
            client,
            "list_entities_for_policy",
            "PolicyRoles",
            PolicyArn=SUPPORT_POLICY_ARN,
        )
    except (ClientError, EndpointConnectionError) as error:
        return iam_manual_check(control_id, error)
    return [
        finding(
            control_id=control_id,
            status=FindingStatus.PASS if roles else FindingStatus.FAIL,
            resource_id=None,
            remediation=(
                f"For {control_id}, create an incident response role with the AWSSupportAccess "
                f"policy. AWS IAM documentation: {AWS_DOCS_IAM_URL}id_roles.html"
            ),
            raw_evidence={"support_roles": roles},
        ),
    ]
