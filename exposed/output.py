from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from exposed.models import CheckResult, Finding, Severity

console = Console()

BANNER = r"""
  ███████╗██╗  ██╗██████╗  ██████╗ ███████╗███████╗██████╗
  ██╔════╝╚██╗██╔╝██╔══██╗██╔═══██╗██╔════╝██╔════╝██╔══██╗
  █████╗   ╚███╔╝ ██████╔╝██║   ██║███████╗█████╗  ██║  ██║
  ██╔══╝   ██╔██╗ ██╔═══╝ ██║   ██║╚════██║██╔══╝  ██║  ██║
  ███████╗██╔╝ ██╗██║     ╚██████╔╝███████║███████╗██████╔╝
  ╚══════╝╚═╝  ╚═╝╚═╝      ╚═════╝ ╚══════╝╚══════╝╚═════╝"""


def print_banner() -> None:
    console.print(Text(BANNER, style="bold cyan"))
    console.print("  [dim]Find what you forgot to hide.[/dim]\n")


def print_scanning() -> None:
    console.print("[bold]Scanning your development environment...[/bold]\n")


def print_result(cr: CheckResult) -> None:
    header = Text(f" {cr.icon}  {cr.name} ", style="bold")

    if not cr.findings:
        console.print(Panel(Text("No checks performed", style="dim"), title=header.__str__()))
        return

    lines = Text()
    for i, f in enumerate(cr.findings):
        icon = f.severity.icon
        style = f.severity.color
        lines.append(f"  {icon} ", style=style)
        lines.append(f"{f.title}\n", style=style)
        if f.detail:
            lines.append(f"      {f.detail}\n", style="dim")
        if f.remediation:
            lines.append(f"      fix: ", style="dim italic")
            lines.append(f"{f.remediation}\n", style="dim italic")
        if i < len(cr.findings) - 1:
            lines.append("\n")

    console.print(Panel(lines, title=str(header), border_style=_border_color(cr), padding=(0, 1)))
    console.print()


def print_score(results: list[CheckResult]) -> None:
    total_deductions = sum(cr.deductions for cr in results)
    score = max(0.0, 10.0 - total_deductions)
    score = round(score, 1)

    crits = sum(1 for cr in results for f in cr.findings if f.severity == Severity.CRITICAL)
    warns = sum(1 for cr in results for f in cr.findings if f.severity == Severity.WARNING)
    passes = sum(1 for cr in results for f in cr.findings if f.severity == Severity.PASS)

    if score >= 9.0:
        grade, color = "Excellent", "green bold"
    elif score >= 7.0:
        grade, color = "Good", "green"
    elif score >= 5.0:
        grade, color = "Fair", "yellow"
    elif score >= 3.0:
        grade, color = "Poor", "red"
    else:
        grade, color = "Critical", "red bold"

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="bold")
    table.add_column()
    table.add_row("Score", Text(f"{score}/10", style=color))
    table.add_row("Rating", Text(grade, style=color))
    table.add_row("", "")
    table.add_row(Text("✗ Critical", style="red"), str(crits))
    table.add_row(Text("⚠ Warnings", style="yellow"), str(warns))
    table.add_row(Text("✓ Passed", style="green"), str(passes))

    console.print(Panel(table, title="[bold] Security Score [/bold]", border_style=color, padding=(1, 2)))


def _border_color(cr: CheckResult) -> str:
    worst = cr.worst
    if worst == Severity.CRITICAL:
        return "red"
    if worst == Severity.WARNING:
        return "yellow"
    return "green"
