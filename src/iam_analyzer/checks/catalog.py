"""Explicit executable check catalog for supported controls."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

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
from iam_analyzer.checks.logging import (
    check_cis_3_1_cloudtrail_enabled_all_regions,
    check_cis_3_2_log_file_validation_enabled,
    check_cis_3_4_cloudtrail_bucket_access_logging_enabled,
    check_cis_3_5_cloudtrail_kms_encryption_enabled,
    check_ehc_ct_1_cloudwatch_logs_integration,
    check_ehc_ct_2_cloudtrail_bucket_not_public,
    check_ehc_ct_3_management_event_coverage,
)
from iam_analyzer.checks.registry import CONTROL_REGISTRY

if TYPE_CHECKING:
    from iam_analyzer.models import Finding
    from iam_analyzer.scanner.pagination import PaginatorUtil

type CheckFunction = Callable[[Any, "PaginatorUtil"], list["Finding"]]


@dataclass(frozen=True, slots=True)
class CheckSpec:
    """Executable check metadata used by the scanner orchestrator."""

    control_id: str
    title: str
    service: str
    required_services: tuple[str, ...]
    function: CheckFunction


_IAM_SERVICES = ("iam",)
_LOGGING_SERVICES = ("cloudtrail", "s3")

CHECK_SPECS: tuple[CheckSpec, ...] = (
    CheckSpec(
        control_id="CIS-1.3",
        title=CONTROL_REGISTRY["CIS-1.3"].title,
        service="iam",
        required_services=_IAM_SERVICES,
        function=check_cis_1_3_root_access_key_absent,
    ),
    CheckSpec(
        control_id="CIS-1.5",
        title=CONTROL_REGISTRY["CIS-1.5"].title,
        service="iam",
        required_services=_IAM_SERVICES,
        function=check_cis_1_5_root_hardware_mfa_enabled,
    ),
    CheckSpec(
        control_id="CIS-1.7",
        title=CONTROL_REGISTRY["CIS-1.7"].title,
        service="iam",
        required_services=_IAM_SERVICES,
        function=check_cis_1_7_password_min_length_14,
    ),
    CheckSpec(
        control_id="CIS-1.8",
        title=CONTROL_REGISTRY["CIS-1.8"].title,
        service="iam",
        required_services=_IAM_SERVICES,
        function=check_cis_1_8_password_reuse_prevention,
    ),
    CheckSpec(
        control_id="CIS-1.9",
        title=CONTROL_REGISTRY["CIS-1.9"].title,
        service="iam",
        required_services=_IAM_SERVICES,
        function=check_cis_1_9_console_users_have_mfa,
    ),
    CheckSpec(
        control_id="CIS-1.11",
        title=CONTROL_REGISTRY["CIS-1.11"].title,
        service="iam",
        required_services=_IAM_SERVICES,
        function=check_cis_1_11_unused_credentials_removed,
    ),
    CheckSpec(
        control_id="CIS-1.13",
        title=CONTROL_REGISTRY["CIS-1.13"].title,
        service="iam",
        required_services=_IAM_SERVICES,
        function=check_cis_1_13_access_keys_rotated,
    ),
    CheckSpec(
        control_id="CIS-1.14",
        title=CONTROL_REGISTRY["CIS-1.14"].title,
        service="iam",
        required_services=_IAM_SERVICES,
        function=check_cis_1_14_no_direct_user_policy_attachments,
    ),
    CheckSpec(
        control_id="CIS-1.15",
        title=CONTROL_REGISTRY["CIS-1.15"].title,
        service="iam",
        required_services=_IAM_SERVICES,
        function=check_cis_1_15_no_admin_wildcard_policies,
    ),
    CheckSpec(
        control_id="CIS-1.16",
        title=CONTROL_REGISTRY["CIS-1.16"].title,
        service="iam",
        required_services=_IAM_SERVICES,
        function=check_cis_1_16_support_role_exists,
    ),
    CheckSpec(
        control_id="CIS-1.21",
        title=CONTROL_REGISTRY["CIS-1.21"].title,
        service="iam",
        required_services=_IAM_SERVICES,
        function=check_cis_1_21_cloudshell_full_access_restricted,
    ),
    CheckSpec(
        control_id="CIS-3.1",
        title=CONTROL_REGISTRY["CIS-3.1"].title,
        service="logging",
        required_services=_LOGGING_SERVICES,
        function=check_cis_3_1_cloudtrail_enabled_all_regions,
    ),
    CheckSpec(
        control_id="CIS-3.2",
        title=CONTROL_REGISTRY["CIS-3.2"].title,
        service="logging",
        required_services=_LOGGING_SERVICES,
        function=check_cis_3_2_log_file_validation_enabled,
    ),
    CheckSpec(
        control_id="CIS-3.4",
        title=CONTROL_REGISTRY["CIS-3.4"].title,
        service="logging",
        required_services=_LOGGING_SERVICES,
        function=check_cis_3_4_cloudtrail_bucket_access_logging_enabled,
    ),
    CheckSpec(
        control_id="CIS-3.5",
        title=CONTROL_REGISTRY["CIS-3.5"].title,
        service="logging",
        required_services=_LOGGING_SERVICES,
        function=check_cis_3_5_cloudtrail_kms_encryption_enabled,
    ),
    CheckSpec(
        control_id="EHC-CT-1",
        title=CONTROL_REGISTRY["EHC-CT-1"].title,
        service="logging",
        required_services=_LOGGING_SERVICES,
        function=check_ehc_ct_1_cloudwatch_logs_integration,
    ),
    CheckSpec(
        control_id="EHC-CT-2",
        title=CONTROL_REGISTRY["EHC-CT-2"].title,
        service="logging",
        required_services=_LOGGING_SERVICES,
        function=check_ehc_ct_2_cloudtrail_bucket_not_public,
    ),
    CheckSpec(
        control_id="EHC-CT-3",
        title=CONTROL_REGISTRY["EHC-CT-3"].title,
        service="logging",
        required_services=_LOGGING_SERVICES,
        function=check_ehc_ct_3_management_event_coverage,
    ),
)
