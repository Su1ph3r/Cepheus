"""Rich terminal output for Cepheus analysis results."""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

if TYPE_CHECKING:
    from cepheus.models.chain import EscapeChain
    from cepheus.models.result import AnalysisResult
    from cepheus.models.technique import EscapeTechnique, Severity

console = Console()

SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "yellow",
    "medium": "blue",
    "low": "green",
}

# Confirmation status -> (display label, style). CONFIRMED is the only verdict
# that represents a demonstrated finding; everything else is shown demoted so a
# reader never mistakes an unproven static match for a real escape.
CONFIRMATION_DISPLAY = {
    "confirmed": ("CONFIRMED", "bold red"),
    "refuted": ("refuted", "dim green"),
    "potential": ("potential", "yellow"),
    "unverifiable": ("unverifiable", "dim"),
    "error": ("verify-error", "magenta"),
}


def _severity_text(severity: Severity) -> Text:
    color = SEVERITY_COLORS.get(severity.value, "white")
    return Text(severity.value.upper(), style=color)


def _confirmation_text(status) -> Text:
    """Render a chain's ConfirmationStatus as a colored badge."""
    if status is None:
        return Text("-", style="dim")
    label, style = CONFIRMATION_DISPLAY.get(status.value, (status.value, "white"))
    return Text(label, style=style)


def print_analysis_result(result: AnalysisResult) -> None:
    """Print the full analysis result with summary, chains, and remediations."""
    # Summary panel
    summary_lines = [
        f"Hostname:            {result.posture.hostname or 'unknown'}",
        f"Kernel:              {result.posture.kernel.version or 'unknown'}",
        f"Runtime:             {result.posture.runtime.runtime}",
        f"Privileged:          {result.posture.runtime.privileged}",
        f"Seccomp:             {result.posture.security.seccomp}",
        f"Techniques checked:  {result.total_techniques_checked}",
        f"Techniques matched:  {result.techniques_matched}",
        f"Escape chains:       {len(result.chains)}",
    ]
    console.print(Panel("\n".join(summary_lines), title="[bold]Cepheus Analysis Summary[/bold]", border_style="cyan"))

    # Whether any chain carries a confirmation verdict. When present we add a
    # Confirmation column; when every chain is unproven (offline analysis) we
    # also print a banner so the reader treats them as hypotheses, not findings.
    has_confirmation = any(getattr(c, "confirmation", None) is not None for c in result.chains)
    all_unconfirmed = bool(result.chains) and all(
        getattr(c, "confirmation", None) is not None and c.confirmation.value in ("potential", "unverifiable")
        for c in result.chains
    )

    # Escape chains table
    if result.chains:
        if all_unconfirmed:
            console.print(
                Panel(
                    "These are UNCONFIRMED static matches — hypotheses based on the "
                    "captured posture, not demonstrated escapes. Re-run with "
                    "[bold]cepheus scan -c <container>[/bold] (or "
                    "[bold]analyze -c <container>[/bold]) to live-verify them and "
                    "surface only what is actually exploitable.",
                    title="[bold yellow]Unconfirmed — verification not run[/bold yellow]",
                    border_style="yellow",
                )
            )
        table = Table(title="Escape Chains (ranked by score)", show_lines=True)
        table.add_column("#", style="dim", width=4)
        table.add_column("Score", justify="right", width=6)
        table.add_column("Severity", width=10)
        if has_confirmation:
            table.add_column("Confirmation", width=13)
        table.add_column("Chain", min_width=40)
        table.add_column("Steps", justify="center", width=6)
        table.add_column("Reliability", justify="right", width=11)
        table.add_column("Stealth", justify="right", width=8)

        for i, chain in enumerate(result.chains, 1):
            sev_text = _severity_text(chain.severity)
            row = [
                str(i),
                f"{chain.composite_score:.2f}",
                sev_text,
            ]
            if has_confirmation:
                row.append(_confirmation_text(getattr(chain, "confirmation", None)))
            row.extend(
                [
                    chain.description,
                    str(len(chain.steps)),
                    f"{chain.reliability_score:.2f}",
                    f"{chain.stealth_score:.2f}",
                ]
            )
            table.add_row(*row)

        console.print(table)
    else:
        console.print("[green]No escape chains found — container appears well-configured.[/green]")

    # Remediations
    if result.remediations:
        rem_table = Table(title="Remediations", show_lines=True)
        rem_table.add_column("Severity", width=10)
        rem_table.add_column("Technique", width=30)
        rem_table.add_column("Issue", min_width=30)
        rem_table.add_column("Fix", min_width=30)
        rem_table.add_column("Flag", width=25)

        for rem in result.remediations:
            sev_text = _severity_text(rem.severity)
            rem_table.add_row(
                sev_text,
                rem.technique_id,
                rem.current_state,
                rem.recommended_fix,
                rem.runtime_flag or "",
            )

        console.print(rem_table)

    # LLM analysis
    if result.llm_analysis:
        console.print(Panel(result.llm_analysis, title="[bold]LLM Analysis[/bold]", border_style="magenta"))

    if result.executive_summary:
        summary_panel = Panel(
            result.executive_summary,
            title="Executive Summary",
            border_style="cyan",
            padding=(1, 2),
        )
        console.print(summary_panel)


def print_chain(chain: EscapeChain) -> None:
    """Print detailed view of a single escape chain."""
    console.print(
        Panel(
            f"[bold]Chain ID:[/bold] {chain.id}\n"
            f"[bold]Score:[/bold]    {chain.composite_score:.4f}\n"
            f"[bold]Severity:[/bold] {chain.severity.value.upper()}",
            title=f"[bold]{chain.description}[/bold]",
            border_style=SEVERITY_COLORS.get(chain.severity.value, "white"),
        )
    )

    for i, step in enumerate(chain.steps, 1):
        console.print(f"\n  [bold]Step {i}:[/bold] {step.technique.name}")
        console.print(f"  [dim]Confidence: {step.prerequisite_confidence:.2f}[/dim]")
        if step.poc_command:
            console.print(Panel(step.poc_command, title="PoC", border_style="dim"))


def print_techniques(techniques: list[EscapeTechnique]) -> None:
    """Print a table of techniques."""
    table = Table(title=f"Known Escape Techniques ({len(techniques)})", show_lines=True)
    table.add_column("ID", width=30)
    table.add_column("Category", width=16)
    table.add_column("Severity", width=10)
    table.add_column("Name", min_width=30)
    table.add_column("CVE", width=16)
    table.add_column("Reliability", justify="right", width=11)
    table.add_column("Stealth", justify="right", width=8)

    for tech in techniques:
        sev_text = _severity_text(tech.severity)
        table.add_row(
            tech.id,
            tech.category.value,
            sev_text,
            tech.name,
            tech.cve or "",
            f"{tech.reliability:.2f}",
            f"{tech.stealth:.2f}",
        )

    console.print(table)
