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
    "CIS-1.5",
    "CIS-1.6",
    "CIS-1.7",
    "CIS-1.10",
    "CIS-1.14",
    "CIS-1.15",
    "CIS-1.16",
    "CIS-1.19",
    "CIS-1.21",
    "CIS-3.1",
    "CIS-3.2",
    "CIS-3.4",
)

CANDIDATE_CONTROL_IDS = (
    "CIS-1.8-CANDIDATE",
    "CIS-1.11-CANDIDATE",
    "CIS-1.12-CANDIDATE",
)

ENTERPRISE_HARDENING_CONTROL_IDS = (
    "EHC-CT-1",
    "EHC-CT-2",
    "EHC-CT-3",
)

_CONTROL_TITLES: dict[str, str] = {
    "CIS-1.5": "Ensure MFA is enabled for the root user",
    "CIS-1.6": "Ensure hardware MFA is enabled for the root user",
    "CIS-1.7": "Eliminate use of the root user for administrative and daily tasks",
    "CIS-1.10": "Ensure IAM password policy prevents password reuse",
    "CIS-1.14": "Ensure access keys are rotated within the allowed period",
    "CIS-1.15": "Ensure IAM users receive permissions only through groups",
    "CIS-1.16": "Ensure no IAM policies allow full administrative privileges",
    "CIS-1.19": "Ensure expired SSL/TLS certificates stored in IAM are removed",
    "CIS-1.21": "Ensure IAM instance roles are used for AWS resource access",
    "CIS-3.1": "Ensure CloudTrail is enabled in all regions",
    "CIS-3.2": "Ensure CloudTrail log file validation is enabled",
    "CIS-3.4": "Ensure CloudTrail trails are integrated with CloudWatch Logs",
    "CIS-1.8-CANDIDATE": "Candidate IAM password policy control",
    "CIS-1.11-CANDIDATE": "Candidate IAM credential usage control",
    "CIS-1.12-CANDIDATE": "Candidate IAM credential rotation control",
    "EHC-CT-1": "Ensure CloudTrail uses a dedicated S3 bucket",
    "EHC-CT-2": "Ensure CloudTrail logs are encrypted with a customer managed KMS key",
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
        control_id: _metadata_for(control_id, "strict_cis")
        for control_id in STRICT_CIS_CONTROL_IDS
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
