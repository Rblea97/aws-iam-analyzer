"""Documentation consistency checks."""

# ruff: noqa: D103, INP001

from __future__ import annotations

from pathlib import Path

from iam_analyzer.checks.catalog import CHECK_SPECS


def test_control_traceability_lists_every_executable_check() -> None:
    traceability = Path("docs/control-traceability.md").read_text(encoding="utf-8")

    for spec in CHECK_SPECS:
        assert f"| `{spec.control_id}` |" in traceability
