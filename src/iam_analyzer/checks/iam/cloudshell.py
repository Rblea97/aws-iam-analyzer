"""IAM CloudShell access checks."""

# mypy: disable-error-code=import-untyped

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from botocore.exceptions import ClientError, EndpointConnectionError

from iam_analyzer.checks.common import finding
from iam_analyzer.checks.iam.common import AWS_DOCS_IAM_URL, iam_manual_check
from iam_analyzer.models import Finding, FindingStatus

if TYPE_CHECKING:
    from iam_analyzer.scanner.pagination import PaginatorUtil

CLOUDSHELL_POLICY_ARN = "arn:aws:iam::aws:policy/AWSCloudShellFullAccess"


def check_cis_1_21_cloudshell_full_access_restricted(
    client: Any,  # noqa: ANN401
    paginator_util: PaginatorUtil,
) -> list[Finding]:
    """CIS-1.21: Ensure AWSCloudShellFullAccess is restricted."""
    control_id = "CIS-1.21"
    try:
        attached_entities = _attached_cloudshell_entities(client, paginator_util)
    except (ClientError, EndpointConnectionError) as error:
        return iam_manual_check(control_id, error)
    return [
        finding(
            control_id=control_id,
            status=FindingStatus.FAIL if any(attached_entities.values()) else FindingStatus.PASS,
            resource_id=None,
            remediation=(
                f"For {control_id}, detach AWSCloudShellFullAccess from identities that "
                f"do not require it. AWS IAM documentation: "
                f"{AWS_DOCS_IAM_URL}access_policies_managed-vs-inline.html"
            ),
            raw_evidence=attached_entities,
        ),
    ]


def _attached_cloudshell_entities(
    client: Any,  # noqa: ANN401
    paginator_util: PaginatorUtil,
) -> dict[str, list[Any]]:
    return {
        "users": paginator_util.paginate(
            client,
            "list_entities_for_policy",
            "PolicyUsers",
            PolicyArn=CLOUDSHELL_POLICY_ARN,
        ),
        "roles": paginator_util.paginate(
            client,
            "list_entities_for_policy",
            "PolicyRoles",
            PolicyArn=CLOUDSHELL_POLICY_ARN,
        ),
        "groups": paginator_util.paginate(
            client,
            "list_entities_for_policy",
            "PolicyGroups",
            PolicyArn=CLOUDSHELL_POLICY_ARN,
        ),
    }
