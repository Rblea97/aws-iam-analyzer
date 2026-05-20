"""CloudTrail event selector normalization and evaluation."""

# mypy: disable-error-code=import-untyped

from __future__ import annotations

from typing import Any

from iam_analyzer.checks.cloudtrail.common import trail_identifier


def management_event_coverage(cloudtrail: Any, trail: dict[str, Any]) -> bool | None:  # noqa: ANN401
    """Return whether a trail logs read and write management events."""
    response = cloudtrail.get_event_selectors(TrailName=trail_identifier(trail))
    selectors = response.get("EventSelectors", [])
    if isinstance(selectors, list) and selectors:
        return any(
            _selector_covers_all(selector) for selector in selectors if isinstance(selector, dict)
        )

    advanced = response.get("AdvancedEventSelectors", [])
    if isinstance(advanced, list) and advanced:
        return advanced_selectors_cover_all(
            [selector for selector in advanced if isinstance(selector, dict)],
        )
    return False


def _selector_covers_all(selector: dict[str, Any]) -> bool:
    return (
        selector.get("IncludeManagementEvents") is True
        and selector.get("ReadWriteType") == "All"
        and not selector.get("ExcludeManagementEventSources")
    )


def _string_values(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [item for item in value if isinstance(item, str)]
    return []


def advanced_selectors_cover_all(selectors: list[dict[str, Any]]) -> bool:
    """Return whether advanced selectors cover both read/write management events."""
    covered_read_only_values: set[str] = set()
    for selector in selectors:
        selector_coverage, excludes_sources = _advanced_selector_coverage(selector)
        if selector_coverage and excludes_sources:
            return False
        covered_read_only_values.update(selector_coverage)
    return {"true", "false"}.issubset(covered_read_only_values)


def _advanced_selector_coverage(selector: dict[str, Any]) -> tuple[set[str], bool]:
    field_selectors = selector.get("FieldSelectors", [])
    if not isinstance(field_selectors, list):
        return set(), False

    has_management_category = False
    read_only_values: list[str] | None = None
    excludes_sources = False
    for field_selector in field_selectors:
        has_management_category, read_only_values, excludes_sources = _apply_field_selector(
            field_selector,
            has_management_category=has_management_category,
            read_only_values=read_only_values,
            excludes_sources=excludes_sources,
        )
    return _read_only_coverage(
        has_management_category=has_management_category,
        read_only_values=read_only_values,
    ), excludes_sources


def _apply_field_selector(
    field_selector: object,
    *,
    has_management_category: bool,
    read_only_values: list[str] | None,
    excludes_sources: bool,
) -> tuple[bool, list[str] | None, bool]:
    if not isinstance(field_selector, dict):
        return has_management_category, read_only_values, excludes_sources
    if field_selector.get("Field") == "eventCategory":
        has_management_category = "Management" in _string_values(field_selector.get("Equals"))
    elif field_selector.get("Field") == "readOnly":
        read_only_values = _string_values(field_selector.get("Equals"))
    elif field_selector.get("Field") == "eventSource":
        excludes_sources = bool(_string_values(field_selector.get("NotEquals")))
    return has_management_category, read_only_values, excludes_sources


def _read_only_coverage(
    *,
    has_management_category: bool,
    read_only_values: list[str] | None,
) -> set[str]:
    if not has_management_category:
        return set()
    if read_only_values is None:
        return {"true", "false"}
    return set(read_only_values).intersection({"true", "false"})
