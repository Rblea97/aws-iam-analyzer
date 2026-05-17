"""Report rendering and writing helpers."""

from iam_analyzer.reporter.json import write_json_report
from iam_analyzer.reporter.terminal import render_terminal_report

__all__ = [
    "render_terminal_report",
    "write_json_report",
]
