"""Tests for production code-shape guardrails."""

# ruff: noqa: D103

from __future__ import annotations

import subprocess
import sys


def test_production_code_shape_gate_passes() -> None:
    result = subprocess.run(
        [sys.executable, "tools/code_shape.py", "src"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stdout + result.stderr
