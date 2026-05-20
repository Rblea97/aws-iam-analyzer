"""IAM policy document evaluation for administrative privilege checks."""

# mypy: disable-error-code=import-untyped

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any
from urllib.parse import unquote

from botocore.exceptions import ClientError, EndpointConnectionError

from iam_analyzer.checks.common import evidence_error, finding
from iam_analyzer.checks.iam.common import (
    AWS_DOCS_IAM_URL,
    iam_manual_check,
    normalize_iam_error,
)
from iam_analyzer.models import Finding, FindingStatus

if TYPE_CHECKING:
    from collections.abc import Mapping

    from iam_analyzer.scanner.pagination import PaginatorUtil


@dataclass(frozen=True, slots=True)
class PolicyDocumentEvaluation:
    """Pure policy-document evaluation result."""

    has_admin_privileges: bool
    malformed: bool = False
    matches: tuple[dict[str, Any], ...] = ()
    malformed_reason: str | None = None


def evaluate_policy_document(document: object) -> PolicyDocumentEvaluation:
    """Evaluate obvious admin-equivalent allow statements in a policy document."""
    normalized, malformed_reason = _normalize_policy_document(document)
    if malformed_reason is not None:
        return PolicyDocumentEvaluation(
            has_admin_privileges=False,
            malformed=True,
            malformed_reason=malformed_reason,
        )
    matches = tuple(
        match
        for statement in _policy_statement_list(normalized)
        for match in [_admin_statement_match(statement)]
        if match is not None
    )
    return PolicyDocumentEvaluation(has_admin_privileges=bool(matches), matches=matches)


def _normalize_policy_document(document: object) -> tuple[Mapping[str, Any], str | None]:
    if isinstance(document, dict):
        return document, None
    if isinstance(document, str):
        return _load_json_document(unquote(document))
    return {}, f"Unsupported policy document type: {type(document).__name__}"


def _load_json_document(document: str) -> tuple[Mapping[str, Any], str | None]:
    try:
        loaded = json.loads(document)
    except json.JSONDecodeError as error:
        return {}, f"Invalid JSON policy document: {error.msg}"
    if isinstance(loaded, dict):
        return loaded, None
    return {}, "Policy document JSON root is not an object"


def _policy_statement_list(document: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    statements = document.get("Statement", [])
    if isinstance(statements, dict):
        return [statements]
    if isinstance(statements, list):
        return [statement for statement in statements if isinstance(statement, dict)]
    return []


def _admin_statement_match(statement: Mapping[str, Any]) -> dict[str, Any] | None:
    if statement.get("Effect") != "Allow" or not _resource_is_wildcard(statement):
        return None
    if _value_has_wildcard(statement.get("Action")):
        return {"reason": "wildcard_action_resource", "statement": dict(statement)}
    if statement.get("NotAction") is not None:
        return {"reason": "broad_not_action_resource", "statement": dict(statement)}
    return None


def _resource_is_wildcard(statement: Mapping[str, Any]) -> bool:
    return _value_has_wildcard(statement.get("Resource"))


def _value_has_wildcard(value: object) -> bool:
    if isinstance(value, str):
        return value == "*"
    if isinstance(value, list):
        return any(item == "*" for item in value if isinstance(item, str))
    return False


def check_cis_1_15_no_admin_wildcard_policies(
    client: Any,  # noqa: ANN401
    paginator_util: PaginatorUtil,
) -> list[Finding]:
    """CIS-1.15: Ensure full-admin IAM policies are not attached."""
    control_id = "CIS-1.15"
    try:
        admin_policies = [
            *_attached_admin_policies(client, paginator_util),
            *_inline_user_admin_policies(client, paginator_util),
            *_inline_group_admin_policies(client, paginator_util),
            *_inline_role_admin_policies(client, paginator_util),
        ]
    except (ClientError, EndpointConnectionError, KeyError) as error:
        return iam_manual_check(control_id, normalize_iam_error(control_id, error))
    return [
        finding(
            control_id=control_id,
            status=FindingStatus.FAIL if admin_policies else FindingStatus.PASS,
            resource_id=None,
            remediation=(
                f"For {control_id}, detach or replace policies that allow broad "
                f"administrative access. AWS IAM documentation: "
                f"{AWS_DOCS_IAM_URL}access_policies.html"
            ),
            raw_evidence={"admin_policies": admin_policies},
        ),
    ]


def _attached_admin_policies(client: Any, paginator_util: PaginatorUtil) -> list[dict[str, Any]]:  # noqa: ANN401
    admin_policies: list[dict[str, Any]] = []
    for policy in paginator_util.paginate(client, "list_policies", "Policies", OnlyAttached=True):
        policy_arn = str(policy["Arn"])
        metadata = client.get_policy(PolicyArn=policy_arn)["Policy"]
        version_id = str(metadata["DefaultVersionId"])
        document = client.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
        evaluation = _evaluate_or_raise(document["PolicyVersion"]["Document"])
        if evaluation.has_admin_privileges:
            admin_policies.append(_managed_policy_result(policy_arn, version_id, evaluation))
    return admin_policies


def _managed_policy_result(
    policy_arn: str,
    version_id: str,
    evaluation: PolicyDocumentEvaluation,
) -> dict[str, Any]:
    return {
        "policy_type": "managed",
        "policy_arn": policy_arn,
        "default_version_id": version_id,
        "matches": list(evaluation.matches),
    }


def _inline_user_admin_policies(client: Any, paginator_util: PaginatorUtil) -> list[dict[str, Any]]:  # noqa: ANN401
    results: list[dict[str, Any]] = []
    for user in paginator_util.paginate(client, "list_users", "Users"):
        user_name = str(user["UserName"])
        policy_names = paginator_util.paginate(
            client,
            "list_user_policies",
            "PolicyNames",
            UserName=user_name,
        )
        results.extend(_inline_user_policy_results(client, user_name, policy_names))
    return results


def _inline_user_policy_results(
    client: Any,  # noqa: ANN401
    user_name: str,
    policy_names: list[Any],
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for policy_name in policy_names:
        policy = client.get_user_policy(UserName=user_name, PolicyName=str(policy_name))
        results.extend(
            _inline_result("user", user_name, str(policy_name), policy["PolicyDocument"]),
        )
    return results


def _inline_group_admin_policies(
    client: Any,  # noqa: ANN401
    paginator_util: PaginatorUtil,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for group in paginator_util.paginate(client, "list_groups", "Groups"):
        group_name = str(group["GroupName"])
        policy_names = paginator_util.paginate(
            client,
            "list_group_policies",
            "PolicyNames",
            GroupName=group_name,
        )
        results.extend(_inline_group_policy_results(client, group_name, policy_names))
    return results


def _inline_group_policy_results(
    client: Any,  # noqa: ANN401
    group_name: str,
    policy_names: list[Any],
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for policy_name in policy_names:
        policy = client.get_group_policy(GroupName=group_name, PolicyName=str(policy_name))
        results.extend(
            _inline_result("group", group_name, str(policy_name), policy["PolicyDocument"]),
        )
    return results


def _inline_role_admin_policies(client: Any, paginator_util: PaginatorUtil) -> list[dict[str, Any]]:  # noqa: ANN401
    results: list[dict[str, Any]] = []
    for role in paginator_util.paginate(client, "list_roles", "Roles"):
        role_name = str(role["RoleName"])
        policy_names = paginator_util.paginate(
            client,
            "list_role_policies",
            "PolicyNames",
            RoleName=role_name,
        )
        results.extend(_inline_role_policy_results(client, role_name, policy_names))
    return results


def _inline_role_policy_results(
    client: Any,  # noqa: ANN401
    role_name: str,
    policy_names: list[Any],
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for policy_name in policy_names:
        policy = client.get_role_policy(RoleName=role_name, PolicyName=str(policy_name))
        results.extend(
            _inline_result("role", role_name, str(policy_name), policy["PolicyDocument"]),
        )
    return results


def _inline_result(
    owner_type: str,
    owner_name: str,
    policy_name: str,
    document: object,
) -> list[dict[str, Any]]:
    evaluation = _evaluate_or_raise(document)
    if not evaluation.has_admin_privileges:
        return []
    return [
        {
            "policy_type": f"inline_{owner_type}",
            "owner_name": owner_name,
            "policy_name": policy_name,
            "matches": list(evaluation.matches),
        },
    ]


def _evaluate_or_raise(document: object) -> PolicyDocumentEvaluation:
    evaluation = evaluate_policy_document(document)
    if evaluation.malformed:
        control_id = "CIS-1.15"
        message = evaluation.malformed_reason or "Malformed IAM policy document"
        raise evidence_error(control_id, "MalformedPolicyDocument", message)
    return evaluation
