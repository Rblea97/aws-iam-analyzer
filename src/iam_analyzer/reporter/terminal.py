"""Rich terminal report renderer."""

from __future__ import annotations

import sys

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table

from iam_analyzer.models import Finding, FindingStatus, ScanResult, Severity

_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}

_SEVERITY_MARKUP = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "orange1",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
}


def _timestamp(scan_result: ScanResult) -> str:
    dumped = scan_result.scan_metadata.model_dump(mode="json")
    return str(dumped["scan_timestamp"])


def _non_passing_findings(scan_result: ScanResult) -> list[Finding]:
    findings = [
        finding
        for finding in scan_result.findings
        if finding.status is not FindingStatus.PASS
    ]
    return sorted(findings, key=lambda finding: _SEVERITY_ORDER[finding.severity])


def _passing_count(scan_result: ScanResult) -> int:
    return sum(1 for finding in scan_result.findings if finding.status is FindingStatus.PASS)


def _summary_panel(scan_result: ScanResult) -> Panel:
    summary = scan_result.summary
    total = summary.CRITICAL + summary.HIGH + summary.MEDIUM + summary.LOW + summary.PASS
    table = Table(title="Scan summary", show_header=True, header_style="bold")
    table.add_column("Account ID")
    table.add_column("Timestamp")
    table.add_column("Total findings", justify="right")
    table.add_column("CRITICAL", justify="right")
    table.add_column("HIGH", justify="right")
    table.add_column("MEDIUM", justify="right")
    table.add_column("LOW", justify="right")
    table.add_column("PASS", justify="right")
    table.add_row(
        escape(scan_result.scan_metadata.account_id),
        escape(_timestamp(scan_result)),
        str(total),
        str(summary.CRITICAL),
        str(summary.HIGH),
        str(summary.MEDIUM),
        str(summary.LOW),
        str(summary.PASS),
    )
    return Panel(table, title="CIS AWS Foundations Benchmark v5.0.0", border_style="cyan")


def _severity_cell(severity: Severity) -> str:
    return f"[{_SEVERITY_MARKUP[severity]}]{severity.value}[/]"


def _findings_table(findings: list[Finding]) -> Table:
    table = Table(title="Findings requiring attention", show_header=True, header_style="bold")
    table.add_column("Control ID")
    table.add_column("Severity")
    table.add_column("Status")
    table.add_column("Resource")
    table.add_column("Title")
    table.add_column("Remediation")

    for finding in findings:
        table.add_row(
            escape(finding.control_id),
            _severity_cell(finding.severity),
            escape(finding.status.value),
            escape(finding.resource_id or "-"),
            escape(finding.control_title),
            escape(finding.remediation),
        )
    return table


def _passing_panel(scan_result: ScanResult) -> Panel | None:
    pass_count = _passing_count(scan_result)
    if pass_count == 0:
        return None
    return Panel(
        f"[dim]PASS findings: {pass_count} (collapsed)[/dim]",
        title="Passing Controls",
        border_style="green",
    )


def _summary_failure_count(scan_result: ScanResult) -> int:
    return (
        scan_result.summary.CRITICAL
        + scan_result.summary.HIGH
        + scan_result.summary.MEDIUM
        + scan_result.summary.LOW
    )


def render_terminal_report(scan_result: ScanResult, *, console: Console | None = None) -> None:
    """Render a scan result to stdout using Rich."""
    output = console or Console(file=sys.stdout)
    failing_findings = _non_passing_findings(scan_result)

    output.print(_summary_panel(scan_result))
    if not failing_findings:
        if _summary_failure_count(scan_result) > 0:
            output.print(
                Panel(
                    "[bold yellow]No findings matched the selected severity filter[/bold yellow]",
                    border_style="yellow",
                ),
            )
            passing_panel = _passing_panel(scan_result)
            if passing_panel is not None:
                output.print(passing_panel)
            return
        output.print(
            Panel(
                "[bold green]✓ All evaluated controls passed[/bold green]",
                border_style="green",
            ),
        )
        passing_panel = _passing_panel(scan_result)
        if passing_panel is not None:
            output.print(passing_panel)
        return

    output.print(_findings_table(failing_findings))
    passing_panel = _passing_panel(scan_result)
    if passing_panel is not None:
        output.print(passing_panel)
