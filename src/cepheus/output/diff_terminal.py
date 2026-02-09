"""Rich terminal output for posture diff results."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from cepheus.engine.differ import DiffResult

console = Console()

SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "yellow",
    "medium": "blue",
    "low": "green",
}


def _severity_text(severity_value: str) -> Text:
    color = SEVERITY_COLORS.get(severity_value, "white")
    return Text(severity_value.upper(), style=color)


def _status_text(status: str) -> Text:
    if status == "remediated":
        return Text("REMEDIATED", style="green")
    elif status == "new":
        return Text("NEW", style="red")
    elif status == "changed":
        return Text("CHANGED", style="yellow")
    return Text(status.upper(), style="white")


def print_diff_result(diff: DiffResult, output_console: Console | None = None) -> None:
    """Print the posture diff result using Rich formatting."""
    global console
    if output_console is not None:
        console = output_console
    # Summary panel
    verdict = Text("IMPROVED", style="bold green") if diff.improved else Text("REGRESSED", style="bold red")

    summary_lines = [
        f"                   BEFORE    AFTER",
        f"  Total chains:    {diff.before_summary.total_chains:<10}{diff.after_summary.total_chains}",
        f"  Critical chains: {diff.before_summary.critical_chains:<10}{diff.after_summary.critical_chains}",
        f"  High chains:     {diff.before_summary.high_chains:<10}{diff.after_summary.high_chains}",
        f"  Max score:       {diff.before_summary.max_score:<10.4f}{diff.after_summary.max_score:.4f}",
        f"  Avg score:       {diff.before_summary.avg_score:<10.4f}{diff.after_summary.avg_score:.4f}",
    ]

    summary_text = Text("\n".join(summary_lines))
    summary_text.append("\n\n  Verdict: ")
    summary_text.append(verdict)

    console.print(Panel(summary_text, title="[bold]Posture Diff Summary[/bold]", border_style="cyan"))

    # Posture changes table
    if diff.posture_deltas:
        posture_table = Table(title="Posture Changes", show_lines=True)
        posture_table.add_column("Field", min_width=30)
        posture_table.add_column("Before", min_width=20)
        posture_table.add_column("After", min_width=20)

        for delta in diff.posture_deltas:
            posture_table.add_row(
                delta.field_name,
                str(delta.before_value) if delta.before_value is not None else "",
                str(delta.after_value) if delta.after_value is not None else "",
            )

        console.print(posture_table)

    # Technique deltas table
    if diff.technique_deltas:
        tech_table = Table(title="Technique Deltas", show_lines=True)
        tech_table.add_column("Status", width=12)
        tech_table.add_column("Technique ID", min_width=25)
        tech_table.add_column("Name", min_width=30)
        tech_table.add_column("Severity", width=10)

        for td in diff.technique_deltas:
            tech_table.add_row(
                _status_text(td.status),
                td.technique_id,
                td.name,
                _severity_text(td.severity.value),
            )

        console.print(tech_table)

    # Chain deltas table
    if diff.chain_deltas:
        chain_table = Table(title="Chain Deltas", show_lines=True)
        chain_table.add_column("Status", width=12)
        chain_table.add_column("Chain ID", min_width=20)
        chain_table.add_column("Description", min_width=30)
        chain_table.add_column("Severity", width=10)
        chain_table.add_column("Score Before", justify="right", width=12)
        chain_table.add_column("Score After", justify="right", width=12)

        for cd in diff.chain_deltas:
            chain_table.add_row(
                _status_text(cd.status),
                cd.chain_id,
                cd.description,
                _severity_text(cd.severity.value),
                f"{cd.score_before:.4f}" if cd.score_before is not None else "-",
                f"{cd.score_after:.4f}" if cd.score_after is not None else "-",
            )

        console.print(chain_table)

    # No changes at all
    if not diff.posture_deltas and not diff.technique_deltas and not diff.chain_deltas:
        console.print("[green]No changes detected.[/green]")
