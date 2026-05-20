"""Tests for CIS AWS Foundations Benchmark v5.0.0 IAM checks."""

# ruff: noqa: D103, INP001, N803, S106

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from botocore.exceptions import ClientError

from iam_analyzer.checks.iam import (
    check_cis_1_3_root_access_key_absent,
    check_cis_1_5_root_hardware_mfa_enabled,
    check_cis_1_7_password_min_length_14,
    check_cis_1_8_password_reuse_prevention,
    check_cis_1_9_console_users_have_mfa,
    check_cis_1_11_unused_credentials_removed,
    check_cis_1_13_access_keys_rotated,
    check_cis_1_14_no_direct_user_policy_attachments,
    check_cis_1_15_no_admin_wildcard_policies,
    check_cis_1_16_support_role_exists,
    check_cis_1_21_cloudshell_full_access_restricted,
)
from iam_analyzer.checks.iam.policy_documents import evaluate_policy_document
from iam_analyzer.checks.registry import CONTROL_REGISTRY
from iam_analyzer.models import FindingStatus, Severity


class _FakeIamClient:
    def __init__(self, **responses: Any) -> None:  # noqa: ANN401
        self.responses = responses
        self.credential_report_errors: list[ClientError] = list(
            responses.get("credential_report_errors", []),
        )
        self.generate_credential_report_states: list[str] = list(
            responses.get("generate_credential_report_states", []),
        )

    def get_account_summary(self) -> dict[str, Any]:
        return _response_or_raise(self.responses["get_account_summary"])

    def get_account_password_policy(self) -> dict[str, Any]:
        return _response_or_raise(self.responses["get_account_password_policy"])

    def get_credential_report(self) -> dict[str, Any]:
        if self.credential_report_errors:
            raise self.credential_report_errors.pop(0)
        if "credential_report_response" in self.responses:
            return _response_or_raise(self.responses["credential_report_response"])
        if "credential_report_content" in self.responses:
            return {"Content": self.responses["credential_report_content"]}
        rows = _response_or_raise(self.responses["credential_report_rows"])
        return {"Content": _credential_report(rows)}

    def generate_credential_report(self) -> dict[str, str]:
        if self.generate_credential_report_states:
            return {"State": self.generate_credential_report_states.pop(0)}
        return {"State": "COMPLETE"}

    def get_policy(self, *, PolicyArn: str) -> dict[str, Any]:
        policies = self.responses["policies"]
        return _response_or_raise(policies[PolicyArn]["metadata"])

    def get_policy_version(self, *, PolicyArn: str, VersionId: str) -> dict[str, Any]:
        policies = self.responses["policies"]
        return _response_or_raise(policies[PolicyArn]["versions"][VersionId])

    def get_user_policy(self, *, UserName: str, PolicyName: str) -> dict[str, Any]:
        return _response_or_raise(
            self.responses["inline_user_policies"][(UserName, PolicyName)],
        )

    def get_group_policy(self, *, GroupName: str, PolicyName: str) -> dict[str, Any]:
        return _response_or_raise(
            self.responses["inline_group_policies"][(GroupName, PolicyName)],
        )

    def get_role_policy(self, *, RoleName: str, PolicyName: str) -> dict[str, Any]:
        return _response_or_raise(
            self.responses["inline_role_policies"][(RoleName, PolicyName)],
        )


class _FakePaginatorUtil:
    def __init__(self, pages: dict[tuple[str, str], list[Any] | ClientError]) -> None:
        self.pages = pages
        self.calls: list[dict[str, Any]] = []

    def paginate(
        self,
        _client: object,
        operation_name: str,
        result_key: str,
        **kwargs: Any,  # noqa: ANN401
    ) -> list[Any]:
        self.calls.append(
            {
                "operation_name": operation_name,
                "result_key": result_key,
                "kwargs": kwargs,
            },
        )
        response = self.pages[(operation_name, result_key)]
        if isinstance(response, ClientError):
            raise response
        return response


def _access_denied(operation_name: str = "iam:Read") -> ClientError:
    return ClientError(
        {
            "Error": {"Code": "AccessDenied", "Message": "not authorized"},
            "ResponseMetadata": {"HTTPStatusCode": 403},
        },
        operation_name,
    )


def _report_not_present() -> ClientError:
    return ClientError(
        {
            "Error": {"Code": "ReportNotPresent", "Message": "credential report missing"},
            "ResponseMetadata": {"HTTPStatusCode": 404},
        },
        "GetCredentialReport",
    )


def _response_or_raise(response: Any) -> Any:  # noqa: ANN401
    if isinstance(response, ClientError):
        raise response
    return response


def _credential_report(rows: list[dict[str, str]]) -> bytes:
    fields = [
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
    ]
    lines = [",".join(fields)]
    lines.extend(",".join(row.get(field, "N/A") for field in fields) for row in rows)
    return ("\n".join(lines) + "\n").encode()


def _root_row(**overrides: str) -> dict[str, str]:
    row = {
        "user": "<root_account>",
        "arn": "arn:aws:iam::123456789012:root",
        "user_creation_time": "2026-01-01T00:00:00+00:00",
        "password_enabled": "not_supported",
        "password_last_used": "N/A",
        "password_last_changed": "not_supported",
        "mfa_active": "true",
        "access_key_1_active": "false",
        "access_key_1_last_rotated": "N/A",
        "access_key_1_last_used_date": "N/A",
        "access_key_2_active": "false",
        "access_key_2_last_rotated": "N/A",
        "access_key_2_last_used_date": "N/A",
    }
    row.update(overrides)
    return row


def _user_row(username: str, **overrides: str) -> dict[str, str]:
    row = {
        "user": username,
        "arn": f"arn:aws:iam::123456789012:user/{username}",
        "user_creation_time": "2026-01-01T00:00:00+00:00",
        "password_enabled": "false",
        "password_last_used": "N/A",
        "password_last_changed": "N/A",
        "mfa_active": "false",
        "access_key_1_active": "false",
        "access_key_1_last_rotated": "N/A",
        "access_key_1_last_used_date": "N/A",
        "access_key_2_active": "false",
        "access_key_2_last_rotated": "N/A",
        "access_key_2_last_used_date": "N/A",
    }
    row.update(overrides)
    return row


def _iam_client_with_report(rows: list[dict[str, str]]) -> _FakeIamClient:
    return _FakeIamClient(credential_report_rows=rows)


def _empty_paginator() -> _FakePaginatorUtil:
    return _FakePaginatorUtil({})


def test_registry_uses_authoritative_cis_v5_iam_titles() -> None:
    expected_titles = {
        "CIS-1.3": "Ensure no root user account access key exists",
        "CIS-1.5": "Ensure hardware MFA is enabled for the root user account",
        "CIS-1.7": "Ensure IAM password policy requires minimum length of 14 or greater",
        "CIS-1.8": "Ensure IAM password policy prevents password reuse",
        "CIS-1.9": "Ensure MFA is enabled for all IAM users that have a console password",
        "CIS-1.11": "Ensure credentials unused for 45 days or more are removed",
        "CIS-1.13": "Ensure access keys are rotated every 90 days or less",
        "CIS-1.14": "Ensure IAM users receive permissions only through groups",
        "CIS-1.15": (
            "Ensure IAM policies that allow full administrative privileges are not attached"
        ),
        "CIS-1.16": "Ensure a support role has been created to manage incidents with AWS Support",
        "CIS-1.21": "Ensure access to AWSCloudShellFullAccess is restricted",
    }

    for control_id, title in expected_titles.items():
        assert CONTROL_REGISTRY[control_id].title == title


@pytest.mark.parametrize(
    ("rows", "expected_status"),
    [
        ([_root_row()], FindingStatus.PASS),
        ([_root_row(access_key_1_active="true")], FindingStatus.FAIL),
    ],
)
def test_cis_1_3_root_access_key_absent(
    rows: list[dict[str, str]],
    expected_status: FindingStatus,
) -> None:
    findings = check_cis_1_3_root_access_key_absent(
        _iam_client_with_report(rows),
        _empty_paginator(),
    )

    assert [finding.status for finding in findings] == [expected_status]


def test_cis_1_3_root_access_key_permission_denied_returns_manual_check() -> None:
    client = _FakeIamClient(credential_report_rows=_access_denied())

    findings = check_cis_1_3_root_access_key_absent(client, _empty_paginator())

    assert findings[0].status is FindingStatus.MANUAL_CHECK


def test_cis_1_3_missing_root_arn_does_not_emit_fictional_root_identifier() -> None:
    findings = check_cis_1_3_root_access_key_absent(
        _iam_client_with_report([_root_row(arn="")]),
        _empty_paginator(),
    )

    dumped = findings[0].model_dump(mode="json")
    assert findings[0].resource_id is None
    assert "arn:aws:iam::123456789012:root" not in json.dumps(dumped)


def test_cis_1_3_root_arn_uses_credential_report_identity_when_present() -> None:
    root_arn = "arn:aws:iam::999999999999:root"

    findings = check_cis_1_3_root_access_key_absent(
        _iam_client_with_report([_root_row(arn=root_arn)]),
        _empty_paginator(),
    )

    assert findings[0].resource_id == root_arn


def test_credential_report_checks_poll_until_generation_completes() -> None:
    client = _FakeIamClient(
        credential_report_errors=[_report_not_present(), _report_not_present()],
        credential_report_rows=[_root_row()],
        generate_credential_report_states=["STARTED", "COMPLETE"],
    )

    findings = check_cis_1_3_root_access_key_absent(client, _empty_paginator())

    assert findings[0].status is FindingStatus.PASS


def test_credential_report_checks_fetch_after_final_generation_completion() -> None:
    client = _FakeIamClient(
        credential_report_errors=[
            _report_not_present(),
            _report_not_present(),
            _report_not_present(),
        ],
        credential_report_rows=[_root_row()],
        generate_credential_report_states=["STARTED", "INPROGRESS", "COMPLETE"],
    )

    findings = check_cis_1_3_root_access_key_absent(client, _empty_paginator())

    assert findings[0].status is FindingStatus.PASS


def test_credential_report_timeout_returns_explicit_manual_check() -> None:
    client = _FakeIamClient(
        credential_report_errors=[_report_not_present()] * 8,
        credential_report_rows=[_root_row()],
        generate_credential_report_states=["INPROGRESS"] * 8,
    )

    findings = check_cis_1_3_root_access_key_absent(client, _empty_paginator())

    assert findings[0].status is FindingStatus.MANUAL_CHECK
    assert findings[0].severity is Severity.HIGH
    assert findings[0].raw_evidence["error"]["code"] == "CredentialReportTimeout"


def test_credential_report_access_denied_returns_explicit_manual_check() -> None:
    client = _FakeIamClient(
        credential_report_rows=_access_denied("GetCredentialReport"),
    )

    findings = check_cis_1_3_root_access_key_absent(client, _empty_paginator())

    assert findings[0].status is FindingStatus.MANUAL_CHECK
    assert findings[0].severity is Severity.HIGH
    assert findings[0].raw_evidence["error"]["code"] == "AccessDenied"


def test_credential_report_malformed_content_returns_explicit_manual_check() -> None:
    client = _FakeIamClient(
        credential_report_content=b"user,access_key_1_active\n<root_account>,false\n",
    )

    findings = check_cis_1_3_root_access_key_absent(client, _empty_paginator())

    assert findings[0].status is FindingStatus.MANUAL_CHECK
    assert findings[0].raw_evidence["error"]["code"] == "MalformedCredentialReport"


def test_credential_report_missing_content_returns_explicit_manual_check() -> None:
    client = _FakeIamClient(credential_report_response={})

    findings = check_cis_1_3_root_access_key_absent(client, _empty_paginator())

    assert findings[0].status is FindingStatus.MANUAL_CHECK
    assert findings[0].raw_evidence["error"]["code"] == "MalformedCredentialReport"


def test_credential_report_malformed_date_returns_explicit_manual_check() -> None:
    client = _FakeIamClient(
        credential_report_rows=[
            _root_row(),
            _user_row(
                "alice",
                password_enabled="true",
                password_last_changed="not-a-date",
            ),
        ],
    )

    findings = check_cis_1_11_unused_credentials_removed(client, _empty_paginator())

    assert findings[0].status is FindingStatus.MANUAL_CHECK
    assert findings[0].raw_evidence["error"]["code"] == "MalformedCredentialReport"


@pytest.mark.parametrize(
    ("summary", "virtual_devices", "expected_status"),
    [
        ({"SummaryMap": {"AccountMFAEnabled": 1}}, [], FindingStatus.PASS),
        (
            {"SummaryMap": {"AccountMFAEnabled": 1}},
            [{"SerialNumber": "arn:aws:iam::123456789012:mfa/root-account-mfa-device"}],
            FindingStatus.FAIL,
        ),
    ],
)
def test_cis_1_5_root_hardware_mfa_enabled(
    summary: dict[str, Any],
    virtual_devices: list[dict[str, str]],
    expected_status: FindingStatus,
) -> None:
    findings = check_cis_1_5_root_hardware_mfa_enabled(
        _FakeIamClient(get_account_summary=summary),
        _FakePaginatorUtil({("list_virtual_mfa_devices", "VirtualMFADevices"): virtual_devices}),
    )

    assert findings[0].status is expected_status


def test_cis_1_5_root_hardware_mfa_permission_denied_returns_manual_check() -> None:
    findings = check_cis_1_5_root_hardware_mfa_enabled(
        _FakeIamClient(get_account_summary=_access_denied("GetAccountSummary")),
        _FakePaginatorUtil({}),
    )

    assert findings[0].status is FindingStatus.MANUAL_CHECK
    assert findings[0].severity is Severity.HIGH


@pytest.mark.parametrize(
    ("policy", "expected_status"),
    [
        ({"PasswordPolicy": {"MinimumPasswordLength": 14}}, FindingStatus.PASS),
        ({"PasswordPolicy": {"MinimumPasswordLength": 12}}, FindingStatus.FAIL),
    ],
)
def test_cis_1_7_password_min_length(
    policy: dict[str, Any],
    expected_status: FindingStatus,
) -> None:
    findings = check_cis_1_7_password_min_length_14(
        _FakeIamClient(get_account_password_policy=policy),
        _empty_paginator(),
    )

    assert findings[0].status is expected_status


def test_cis_1_7_password_min_length_permission_denied_returns_manual_check() -> None:
    findings = check_cis_1_7_password_min_length_14(
        _FakeIamClient(get_account_password_policy=_access_denied("GetAccountPasswordPolicy")),
        _empty_paginator(),
    )

    assert findings[0].status is FindingStatus.MANUAL_CHECK


@pytest.mark.parametrize(
    ("policy", "expected_status"),
    [
        ({"PasswordPolicy": {"PasswordReusePrevention": 24}}, FindingStatus.PASS),
        ({"PasswordPolicy": {"PasswordReusePrevention": 12}}, FindingStatus.FAIL),
    ],
)
def test_cis_1_8_password_reuse_prevention(
    policy: dict[str, Any],
    expected_status: FindingStatus,
) -> None:
    findings = check_cis_1_8_password_reuse_prevention(
        _FakeIamClient(get_account_password_policy=policy),
        _empty_paginator(),
    )

    assert findings[0].status is expected_status


def test_cis_1_8_password_reuse_permission_denied_returns_manual_check() -> None:
    findings = check_cis_1_8_password_reuse_prevention(
        _FakeIamClient(get_account_password_policy=_access_denied("GetAccountPasswordPolicy")),
        _empty_paginator(),
    )

    assert findings[0].status is FindingStatus.MANUAL_CHECK


@pytest.mark.parametrize(
    ("rows", "expected_status"),
    [
        (
            [_root_row(), _user_row("alice", password_enabled="true", mfa_active="true")],
            FindingStatus.PASS,
        ),
        (
            [_root_row(), _user_row("alice", password_enabled="true", mfa_active="false")],
            FindingStatus.FAIL,
        ),
    ],
)
def test_cis_1_9_console_users_have_mfa(
    rows: list[dict[str, str]],
    expected_status: FindingStatus,
) -> None:
    findings = check_cis_1_9_console_users_have_mfa(
        _iam_client_with_report(rows),
        _empty_paginator(),
    )

    assert findings[0].status is expected_status


def test_cis_1_9_console_users_mfa_permission_denied_returns_manual_check() -> None:
    findings = check_cis_1_9_console_users_have_mfa(
        _FakeIamClient(credential_report_rows=_access_denied("GetCredentialReport")),
        _empty_paginator(),
    )

    assert findings[0].status is FindingStatus.MANUAL_CHECK


@pytest.mark.parametrize(
    ("rows", "expected_status"),
    [
        ([_root_row(), _user_row("alice")], FindingStatus.PASS),
        (
            [
                _root_row(),
                _user_row(
                    "alice",
                    access_key_1_active="true",
                    access_key_1_last_used_date=(datetime.now(UTC) - timedelta(days=50))
                    .date()
                    .isoformat(),
                ),
            ],
            FindingStatus.FAIL,
        ),
    ],
)
def test_cis_1_11_unused_credentials_removed(
    rows: list[dict[str, str]],
    expected_status: FindingStatus,
) -> None:
    findings = check_cis_1_11_unused_credentials_removed(
        _iam_client_with_report(rows),
        _empty_paginator(),
    )

    assert findings[0].status is expected_status


def test_cis_1_11_unused_credentials_permission_denied_returns_manual_check() -> None:
    findings = check_cis_1_11_unused_credentials_removed(
        _FakeIamClient(credential_report_rows=_access_denied("GetCredentialReport")),
        _empty_paginator(),
    )

    assert findings[0].status is FindingStatus.MANUAL_CHECK


@pytest.mark.parametrize(
    ("row", "expected_status"),
    [
        (
            _user_row(
                "alice",
                user_creation_time=(datetime.now(UTC) - timedelta(days=10)).isoformat(),
                password_enabled="true",
                password_last_used="no_information",
                password_last_changed=(datetime.now(UTC) - timedelta(days=10)).isoformat(),
            ),
            FindingStatus.PASS,
        ),
        (
            _user_row(
                "alice",
                user_creation_time=(datetime.now(UTC) - timedelta(days=60)).isoformat(),
                password_enabled="true",
                password_last_used="no_information",
                password_last_changed=(datetime.now(UTC) - timedelta(days=60)).isoformat(),
            ),
            FindingStatus.FAIL,
        ),
        (
            _user_row(
                "alice",
                user_creation_time=(datetime.now(UTC) - timedelta(days=10)).isoformat(),
                access_key_1_active="true",
                access_key_1_last_rotated=(datetime.now(UTC) - timedelta(days=10)).isoformat(),
                access_key_1_last_used_date="N/A",
            ),
            FindingStatus.PASS,
        ),
        (
            _user_row(
                "alice",
                user_creation_time=(datetime.now(UTC) - timedelta(days=60)).isoformat(),
                access_key_1_active="true",
                access_key_1_last_rotated=(datetime.now(UTC) - timedelta(days=60)).isoformat(),
                access_key_1_last_used_date="N/A",
            ),
            FindingStatus.FAIL,
        ),
    ],
)
def test_cis_1_11_uses_creation_dates_for_never_used_credentials(
    row: dict[str, str],
    expected_status: FindingStatus,
) -> None:
    findings = check_cis_1_11_unused_credentials_removed(
        _iam_client_with_report([_root_row(), row]),
        _empty_paginator(),
    )

    assert findings[0].status is expected_status


@pytest.mark.parametrize(
    ("access_keys", "expected_status"),
    [
        (
            [{"UserName": "alice", "CreateDate": datetime.now(UTC) - timedelta(days=30)}],
            FindingStatus.PASS,
        ),
        (
            [{"UserName": "alice", "CreateDate": datetime.now(UTC) - timedelta(days=120)}],
            FindingStatus.FAIL,
        ),
    ],
)
def test_cis_1_13_access_keys_rotated(
    access_keys: list[dict[str, Any]],
    expected_status: FindingStatus,
) -> None:
    findings = check_cis_1_13_access_keys_rotated(
        object(),
        _FakePaginatorUtil(
            {
                ("list_users", "Users"): [
                    {"UserName": "alice", "Arn": "arn:aws:iam::123456789012:user/alice"},
                ],
                ("list_access_keys", "AccessKeyMetadata"): access_keys,
            },
        ),
    )

    assert findings[0].status is expected_status


def test_cis_1_13_access_key_rotation_permission_denied_returns_manual_check() -> None:
    findings = check_cis_1_13_access_keys_rotated(
        object(),
        _FakePaginatorUtil({("list_users", "Users"): _access_denied("ListUsers")}),
    )

    assert findings[0].status is FindingStatus.MANUAL_CHECK


@pytest.mark.parametrize(
    ("inline_policies", "attached_policies", "expected_status"),
    [
        ([], [], FindingStatus.PASS),
        (["DangerPolicy"], [], FindingStatus.FAIL),
    ],
)
def test_cis_1_14_no_direct_user_policy_attachments(
    inline_policies: list[str],
    attached_policies: list[dict[str, str]],
    expected_status: FindingStatus,
) -> None:
    findings = check_cis_1_14_no_direct_user_policy_attachments(
        object(),
        _FakePaginatorUtil(
            {
                ("list_users", "Users"): [
                    {"UserName": "alice", "Arn": "arn:aws:iam::123456789012:user/alice"},
                ],
                ("list_user_policies", "PolicyNames"): inline_policies,
                ("list_attached_user_policies", "AttachedPolicies"): attached_policies,
            },
        ),
    )

    assert findings[0].status is expected_status


def test_cis_1_14_direct_user_policy_permission_denied_returns_manual_check() -> None:
    findings = check_cis_1_14_no_direct_user_policy_attachments(
        object(),
        _FakePaginatorUtil({("list_users", "Users"): _access_denied("ListUsers")}),
    )

    assert findings[0].status is FindingStatus.MANUAL_CHECK


@pytest.mark.parametrize(
    ("policy_document", "expected_status"),
    [
        (
            {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]},
            FindingStatus.PASS,
        ),
        ({"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}, FindingStatus.FAIL),
        (
            {"Statement": [{"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}]},
            FindingStatus.FAIL,
        ),
        (
            {"Statement": [{"Effect": "Allow", "Action": "*", "NotResource": "*"}]},
            FindingStatus.PASS,
        ),
    ],
)
def test_cis_1_15_no_admin_wildcard_policies(
    policy_document: dict[str, Any],
    expected_status: FindingStatus,
) -> None:
    policy_arn = "arn:aws:iam::123456789012:policy/AdminLike"
    findings = check_cis_1_15_no_admin_wildcard_policies(
        _FakeIamClient(
            policies={
                policy_arn: {
                    "metadata": {"Policy": {"Arn": policy_arn, "DefaultVersionId": "v1"}},
                    "versions": {"v1": {"PolicyVersion": {"Document": policy_document}}},
                },
            },
        ),
        _FakePaginatorUtil(
            {
                ("list_policies", "Policies"): [{"Arn": policy_arn, "DefaultVersionId": "v1"}],
                ("list_users", "Users"): [],
                ("list_groups", "Groups"): [],
                ("list_roles", "Roles"): [],
            },
        ),
    )

    assert findings[0].status is expected_status


def test_cis_1_15_admin_policy_permission_denied_returns_manual_check() -> None:
    findings = check_cis_1_15_no_admin_wildcard_policies(
        object(),
        _FakePaginatorUtil({("list_policies", "Policies"): _access_denied("ListPolicies")}),
    )

    assert findings[0].status is FindingStatus.MANUAL_CHECK


def test_cis_1_15_evaluates_attached_aws_managed_admin_policies() -> None:
    policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    paginator_util = _FakePaginatorUtil(
        {
            ("list_policies", "Policies"): [{"Arn": policy_arn, "DefaultVersionId": "v1"}],
            ("list_users", "Users"): [],
            ("list_groups", "Groups"): [],
            ("list_roles", "Roles"): [],
        },
    )

    findings = check_cis_1_15_no_admin_wildcard_policies(
        _FakeIamClient(
            policies={
                policy_arn: {
                    "metadata": {"Policy": {"Arn": policy_arn, "DefaultVersionId": "v1"}},
                    "versions": {
                        "v1": {
                            "PolicyVersion": {
                                "Document": {
                                    "Statement": [
                                        {"Effect": "Allow", "Action": "*", "Resource": "*"},
                                    ],
                                },
                            },
                        },
                    },
                },
            },
        ),
        paginator_util,
    )

    assert findings[0].status is FindingStatus.FAIL
    assert paginator_util.calls[0]["kwargs"] == {"OnlyAttached": True}


def test_cis_1_15_evaluates_attached_customer_managed_admin_policies() -> None:
    policy_arn = "arn:aws:iam::123456789012:policy/AdminLike"

    findings = check_cis_1_15_no_admin_wildcard_policies(
        _FakeIamClient(
            policies={
                policy_arn: {
                    "metadata": {"Policy": {"Arn": policy_arn, "DefaultVersionId": "v3"}},
                    "versions": {
                        "v3": {
                            "PolicyVersion": {
                                "Document": {
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Action": ["*"],
                                            "Resource": ["*"],
                                        },
                                    ],
                                },
                            },
                        },
                    },
                },
            },
        ),
        _FakePaginatorUtil(
            {
                ("list_policies", "Policies"): [{"Arn": policy_arn}],
                ("list_users", "Users"): [],
                ("list_groups", "Groups"): [],
                ("list_roles", "Roles"): [],
            },
        ),
    )

    assert findings[0].status is FindingStatus.FAIL


def test_cis_1_15_evaluates_inline_user_admin_policy() -> None:
    findings = check_cis_1_15_no_admin_wildcard_policies(
        _FakeIamClient(
            policies={},
            inline_user_policies={
                ("alice", "InlineAdmin"): {
                    "PolicyDocument": {
                        "Statement": [
                            {"Effect": "Allow", "Action": "*", "Resource": "*"},
                        ],
                    },
                },
            },
            inline_group_policies={},
            inline_role_policies={},
        ),
        _FakePaginatorUtil(
            {
                ("list_policies", "Policies"): [],
                ("list_users", "Users"): [{"UserName": "alice"}],
                ("list_user_policies", "PolicyNames"): ["InlineAdmin"],
                ("list_groups", "Groups"): [],
                ("list_roles", "Roles"): [],
            },
        ),
    )

    assert findings[0].status is FindingStatus.FAIL


def test_cis_1_15_evaluates_inline_group_admin_policy() -> None:
    findings = check_cis_1_15_no_admin_wildcard_policies(
        _FakeIamClient(
            policies={},
            inline_user_policies={},
            inline_group_policies={
                ("admins", "InlineAdmin"): {
                    "PolicyDocument": {
                        "Statement": [
                            {"Effect": "Allow", "Action": "*", "Resource": "*"},
                        ],
                    },
                },
            },
            inline_role_policies={},
        ),
        _FakePaginatorUtil(
            {
                ("list_policies", "Policies"): [],
                ("list_users", "Users"): [],
                ("list_groups", "Groups"): [{"GroupName": "admins"}],
                ("list_group_policies", "PolicyNames"): ["InlineAdmin"],
                ("list_roles", "Roles"): [],
            },
        ),
    )

    assert findings[0].status is FindingStatus.FAIL


def test_cis_1_15_evaluates_inline_role_admin_policy() -> None:
    findings = check_cis_1_15_no_admin_wildcard_policies(
        _FakeIamClient(
            policies={},
            inline_user_policies={},
            inline_group_policies={},
            inline_role_policies={
                ("BreakGlass", "InlineAdmin"): {
                    "PolicyDocument": {
                        "Statement": [
                            {"Effect": "Allow", "Action": "*", "Resource": "*"},
                        ],
                    },
                },
            },
        ),
        _FakePaginatorUtil(
            {
                ("list_policies", "Policies"): [],
                ("list_users", "Users"): [],
                ("list_groups", "Groups"): [],
                ("list_roles", "Roles"): [{"RoleName": "BreakGlass"}],
                ("list_role_policies", "PolicyNames"): ["InlineAdmin"],
            },
        ),
    )

    assert findings[0].status is FindingStatus.FAIL


@pytest.mark.parametrize(
    ("document", "expected_admin"),
    [
        (
            {"Statement": [{"Effect": "Allow", "Action": ["*"], "Resource": ["*"]}]},
            True,
        ),
        (
            {"Statement": [{"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}]},
            True,
        ),
        (
            {"Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}]},
            False,
        ),
        ("%7B%22Statement%22%3A%20%5B%5D%7D", False),
    ],
)
def test_policy_document_evaluator_detects_admin_equivalent_statements(
    document: object,
    expected_admin: object,
) -> None:
    evaluation = evaluate_policy_document(document)

    assert evaluation.has_admin_privileges is expected_admin


def test_policy_document_evaluator_marks_malformed_documents() -> None:
    evaluation = evaluate_policy_document("%7Bnot-json")

    assert evaluation.malformed is True


@pytest.mark.parametrize(
    ("roles", "expected_status"),
    [
        (
            [{"RoleName": "SupportRole", "Arn": "arn:aws:iam::123456789012:role/SupportRole"}],
            FindingStatus.PASS,
        ),
        ([], FindingStatus.FAIL),
    ],
)
def test_cis_1_16_support_role_exists(
    roles: list[dict[str, str]],
    expected_status: FindingStatus,
) -> None:
    findings = check_cis_1_16_support_role_exists(
        object(),
        _FakePaginatorUtil({("list_entities_for_policy", "PolicyRoles"): roles}),
    )

    assert findings[0].status is expected_status


def test_cis_1_16_support_role_permission_denied_returns_manual_check() -> None:
    findings = check_cis_1_16_support_role_exists(
        object(),
        _FakePaginatorUtil(
            {("list_entities_for_policy", "PolicyRoles"): _access_denied("ListEntitiesForPolicy")},
        ),
    )

    assert findings[0].status is FindingStatus.MANUAL_CHECK


@pytest.mark.parametrize(
    ("users", "roles", "groups", "expected_status"),
    [
        ([], [], [], FindingStatus.PASS),
        (
            [{"UserName": "alice", "Arn": "arn:aws:iam::123456789012:user/alice"}],
            [],
            [],
            FindingStatus.FAIL,
        ),
    ],
)
def test_cis_1_21_cloudshell_full_access_restricted(
    users: list[dict[str, str]],
    roles: list[dict[str, str]],
    groups: list[dict[str, str]],
    expected_status: FindingStatus,
) -> None:
    findings = check_cis_1_21_cloudshell_full_access_restricted(
        object(),
        _FakePaginatorUtil(
            {
                ("list_entities_for_policy", "PolicyUsers"): users,
                ("list_entities_for_policy", "PolicyRoles"): roles,
                ("list_entities_for_policy", "PolicyGroups"): groups,
            },
        ),
    )

    assert findings[0].status is expected_status


def test_cis_1_21_cloudshell_permission_denied_returns_manual_check() -> None:
    findings = check_cis_1_21_cloudshell_full_access_restricted(
        object(),
        _FakePaginatorUtil(
            {("list_entities_for_policy", "PolicyUsers"): _access_denied("ListEntitiesForPolicy")},
        ),
    )

    assert findings[0].status is FindingStatus.MANUAL_CHECK
