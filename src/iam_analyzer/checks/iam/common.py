"""Shared IAM check helpers."""

# mypy: disable-error-code=import-untyped

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from iam_analyzer.checks.common import evidence_error, manual_check

if TYPE_CHECKING:
    from iam_analyzer.models import Finding

AWS_DOCS_IAM_URL = "https://docs.aws.amazon.com/IAM/latest/UserGuide/"


def iam_manual_check(control_id: str, error: Exception) -> list[Finding]:
    """Return a standardized IAM manual-check finding."""
    return manual_check(
        control_id=control_id,
        error=error,
        service="IAM",
        docs_url=AWS_DOCS_IAM_URL,
    )


def normalize_iam_error(
    control_id: str,
    error: Exception,
) -> Exception:
    """Convert local missing-field errors into explicit scanner evidence errors."""
    if isinstance(error, KeyError):
        return cast("Exception", evidence_error(control_id, "MissingEvidence", str(error)))
    return error
