"""CloudTrail check exports."""

from iam_analyzer.checks.cloudtrail.buckets import (
    check_cis_3_4_cloudtrail_bucket_access_logging_enabled,
    check_ehc_ct_2_cloudtrail_bucket_not_public,
)
from iam_analyzer.checks.cloudtrail.common import LoggingClientBundle
from iam_analyzer.checks.cloudtrail.trails import (
    check_cis_3_1_cloudtrail_enabled_all_regions,
    check_cis_3_2_log_file_validation_enabled,
    check_cis_3_5_cloudtrail_kms_encryption_enabled,
    check_ehc_ct_1_cloudwatch_logs_integration,
    check_ehc_ct_3_management_event_coverage,
)

__all__ = [
    "LoggingClientBundle",
    "check_cis_3_1_cloudtrail_enabled_all_regions",
    "check_cis_3_2_log_file_validation_enabled",
    "check_cis_3_4_cloudtrail_bucket_access_logging_enabled",
    "check_cis_3_5_cloudtrail_kms_encryption_enabled",
    "check_ehc_ct_1_cloudwatch_logs_integration",
    "check_ehc_ct_2_cloudtrail_bucket_not_public",
    "check_ehc_ct_3_management_event_coverage",
]
