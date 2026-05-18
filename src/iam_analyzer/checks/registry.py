"""Control metadata registry for supported IAM and CloudTrail checks."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from collections.abc import Mapping

type ControlCategory = Literal["strict_cis", "candidate", "enterprise_hardening"]


@dataclass(frozen=True, slots=True)
class ControlMetadata:
    """Static metadata for a supported control."""

    control_id: str
    title: str
    category: ControlCategory


STRICT_CIS_CONTROL_IDS = (
    "CIS-1.3",
    "CIS-1.4",
    "CIS-1.5",
    "CIS-1.6",
    "CIS-1.7",
    "CIS-1.8",
    "CIS-1.9",
    "CIS-1.10",
    "CIS-1.11",
    "CIS-1.12",
    "CIS-1.13",
    "CIS-1.14",
    "CIS-1.15",
    "CIS-1.16",
    "CIS-1.17",
    "CIS-1.18",
    "CIS-1.19",
    "CIS-1.20",
    "CIS-1.21",
    "CIS-3.1",
    "CIS-3.2",
    "CIS-3.4",
    "CIS-3.5",
)

CANDIDATE_CONTROL_IDS: tuple[str, ...] = ()

ENTERPRISE_HARDENING_CONTROL_IDS = (
    "EHC-CT-1",
    "EHC-CT-2",
    "EHC-CT-3",
)

_CONTROL_TITLES: dict[str, str] = {
    "CIS-1.3": "Ensure no root user account access key exists",
    "CIS-1.4": "Ensure MFA is enabled for the root user account",
    "CIS-1.5": "Ensure hardware MFA is enabled for the root user account",
    "CIS-1.6": "Eliminate use of the root user for administrative and daily tasks",
    "CIS-1.7": "Ensure IAM password policy requires minimum length of 14 or greater",
    "CIS-1.8": "Ensure IAM password policy prevents password reuse",
    "CIS-1.9": "Ensure MFA is enabled for all IAM users that have a console password",
    "CIS-1.10": (
        "Do not create access keys during initial setup for IAM users with a console password"
    ),
    "CIS-1.11": "Ensure credentials unused for 45 days or more are removed",
    "CIS-1.12": "Ensure there is only one active access key for any single IAM user",
    "CIS-1.13": "Ensure access keys are rotated every 90 days or less",
    "CIS-1.14": "Ensure IAM users receive permissions only through groups",
    "CIS-1.15": "Ensure IAM policies that allow full administrative privileges are not attached",
    "CIS-1.16": "Ensure a support role has been created to manage incidents with AWS Support",
    "CIS-1.17": "Ensure IAM instance roles are used for AWS resource access from instances",
    "CIS-1.18": "Ensure that all expired SSL/TLS certificates stored in IAM are removed",
    "CIS-1.19": "Ensure that IAM External Access Analyzer is enabled for all regions",
    "CIS-1.20": (
        "Ensure IAM users are managed centrally via identity federation or AWS Organizations"
    ),
    "CIS-1.21": "Ensure access to AWSCloudShellFullAccess is restricted",
    "CIS-3.1": "Ensure CloudTrail is enabled and configured with at least one multi-Region trail",
    "CIS-3.2": "Ensure CloudTrail log file validation is enabled",
    "CIS-3.4": "Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket",
    "CIS-3.5": "Ensure CloudTrail logs are encrypted at rest using KMS keys",
    "CIS-1.8-CANDIDATE": "Candidate IAM password policy control",
    "CIS-1.11-CANDIDATE": "Candidate IAM credential usage control",
    "CIS-1.12-CANDIDATE": "Candidate IAM credential rotation control",
    "EHC-CT-1": "Ensure CloudTrail is integrated with CloudWatch Logs",
    "EHC-CT-2": "Ensure the CloudTrail S3 bucket is not publicly accessible",
    "EHC-CT-3": "Ensure CloudTrail management event coverage is hardened",
}


def _metadata_for(control_id: str, category: ControlCategory) -> ControlMetadata:
    return ControlMetadata(
        control_id=control_id,
        title=_CONTROL_TITLES[control_id],
        category=category,
    )


_CONTROL_REGISTRY: dict[str, ControlMetadata] = {
    **{
        control_id: _metadata_for(control_id, "strict_cis") for control_id in STRICT_CIS_CONTROL_IDS
    },
    **{control_id: _metadata_for(control_id, "candidate") for control_id in CANDIDATE_CONTROL_IDS},
    **{
        control_id: _metadata_for(control_id, "enterprise_hardening")
        for control_id in ENTERPRISE_HARDENING_CONTROL_IDS
    },
}

CONTROL_REGISTRY: Mapping[str, ControlMetadata] = MappingProxyType(_CONTROL_REGISTRY)


def is_known_control_id(control_id: str) -> bool:
    """Return whether a control ID is supported by the registry."""
    return control_id in CONTROL_REGISTRY
