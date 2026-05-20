"""IAM check exports."""

from iam_analyzer.checks.iam.cloudshell import check_cis_1_21_cloudshell_full_access_restricted
from iam_analyzer.checks.iam.credential_report import (
    check_cis_1_3_root_access_key_absent,
    check_cis_1_9_console_users_have_mfa,
    check_cis_1_11_unused_credentials_removed,
)
from iam_analyzer.checks.iam.password_policy import (
    check_cis_1_5_root_hardware_mfa_enabled,
    check_cis_1_7_password_min_length_14,
    check_cis_1_8_password_reuse_prevention,
)
from iam_analyzer.checks.iam.policy_documents import check_cis_1_15_no_admin_wildcard_policies
from iam_analyzer.checks.iam.support import (
    check_cis_1_13_access_keys_rotated,
    check_cis_1_14_no_direct_user_policy_attachments,
    check_cis_1_16_support_role_exists,
)

__all__ = [
    "check_cis_1_3_root_access_key_absent",
    "check_cis_1_5_root_hardware_mfa_enabled",
    "check_cis_1_7_password_min_length_14",
    "check_cis_1_8_password_reuse_prevention",
    "check_cis_1_9_console_users_have_mfa",
    "check_cis_1_11_unused_credentials_removed",
    "check_cis_1_13_access_keys_rotated",
    "check_cis_1_14_no_direct_user_policy_attachments",
    "check_cis_1_15_no_admin_wildcard_policies",
    "check_cis_1_16_support_role_exists",
    "check_cis_1_21_cloudshell_full_access_restricted",
]
