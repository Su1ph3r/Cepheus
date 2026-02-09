"""Cepheus CLI — Container Escape Scenario Modeler."""

from __future__ import annotations

import json
import re
import subprocess
from enum import Enum
from pathlib import Path

import typer
from rich.console import Console

from cepheus.config import CepheusConfig

app = typer.Typer(
    name="cepheus",
    help="Container Escape Scenario Modeler — enumerate security posture and model escape paths.",
    no_args_is_help=True,
)
console = Console()

_CONTAINER_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.\-]*$")


class OutputFormat(str, Enum):
    terminal = "terminal"
    json = "json"
    mitre = "mitre"
    html = "html"


class DiffFormat(str, Enum):
    terminal = "terminal"
    json = "json"


class SeverityFilter(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class ContainerRuntime(str, Enum):
    docker = "docker"
    podman = "podman"


SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def _load_posture(posture_file: Path):
    """Load and validate a posture JSON file, exiting on errors."""
    if not posture_file.exists():
        console.print(f"[red]Error: File not found: {posture_file}[/red]")
        raise typer.Exit(1)

    try:
        data = json.loads(posture_file.read_text())
    except json.JSONDecodeError as e:
        console.print(f"[red]Error: Invalid JSON: {e}[/red]")
        raise typer.Exit(1)

    from cepheus.models.posture import ContainerPosture

    try:
        return ContainerPosture.model_validate(data)
    except Exception as e:
        console.print(f"[red]Error: Invalid posture data: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def analyze(
    posture_file: Path = typer.Argument(..., help="Path to posture JSON from enumerator"),
    format: OutputFormat = typer.Option(OutputFormat.terminal, "--format", "-f", help="Output format"),
    min_severity: SeverityFilter = typer.Option(SeverityFilter.low, "--min-severity", "-s", help="Minimum severity to show"),
    llm: bool = typer.Option(False, "--llm", help="Enable LLM enrichment"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write report to file"),
) -> None:
    """Analyze a container posture JSON file and identify escape paths."""
    posture = _load_posture(posture_file)
    config = CepheusConfig()

    from cepheus.engine.analyzer import analyze as run_analysis

    result = run_analysis(posture, config)

    # LLM enrichment
    if llm:
        try:
            from cepheus.llm.client import LLMClient

            client = LLMClient(config)
            result.llm_analysis = client.analyze_posture_sync(posture, result.chains)
        except ImportError:
            console.print("[yellow]Warning: LLM extra not installed. Run: pip install cepheus[llm][/yellow]")
        except Exception:
            console.print("[yellow]Warning: LLM analysis failed[/yellow]")

    # Filter by severity
    min_rank = SEVERITY_RANK[min_severity.value]
    result.chains = [c for c in result.chains if SEVERITY_RANK.get(c.severity.value, 0) >= min_rank]
    result.remediations = [r for r in result.remediations if SEVERITY_RANK.get(r.severity.value, 0) >= min_rank]

    # Write report file if requested (for non-stdout formats)
    if output and format not in (OutputFormat.mitre, OutputFormat.html):
        from cepheus.output.json_report import write_report

        write_report(result, output)
        console.print(f"[green]Report written to {output}[/green]")

    # Render output
    if format == OutputFormat.json:
        from cepheus.output.json_report import generate_report

        report = generate_report(result)
        console.print_json(json.dumps(report))
    elif format == OutputFormat.mitre:
        from cepheus.output.mitre_layer import generate_layer, write_layer

        if output:
            write_layer(result, output)
            console.print(f"[green]MITRE ATT&CK Navigator layer written to {output}[/green]")
        else:
            layer = generate_layer(result)
            console.print_json(json.dumps(layer))
    elif format == OutputFormat.html:
        try:
            from cepheus.output.html_report import generate_html, write_html

            if output:
                write_html(result, output)
                console.print(f"[green]HTML report written to {output}[/green]")
            else:
                console.print(generate_html(result))
        except ImportError:
            console.print("[red]Error: jinja2 is required for HTML reports. Run: pip install cepheus[html][/red]")
            raise typer.Exit(1)
    else:
        from cepheus.output.terminal import print_analysis_result

        print_analysis_result(result)


@app.command()
def diff(
    before_file: Path = typer.Argument(..., help="Path to 'before' posture JSON"),
    after_file: Path = typer.Argument(..., help="Path to 'after' posture JSON"),
    format: DiffFormat = typer.Option(DiffFormat.terminal, "--format", "-f", help="Output format"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write diff report to file"),
) -> None:
    """Compare two posture files and show security changes."""
    before = _load_posture(before_file)
    after = _load_posture(after_file)

    from cepheus.engine.differ import diff_postures

    diff_result = diff_postures(before, after)

    if format == DiffFormat.json:
        report = diff_result.model_dump(mode="json")
        if output:
            Path(output).write_text(json.dumps(report, indent=2))
            console.print(f"[green]Diff report written to {output}[/green]")
        else:
            console.print_json(json.dumps(report))
    else:
        from cepheus.output.diff_terminal import print_diff_result

        print_diff_result(diff_result)


@app.command()
def enumerate(
    container_id: str = typer.Option(..., "--container-id", "-c", help="Container ID or name"),
    runtime: ContainerRuntime = typer.Option(ContainerRuntime.docker, "--runtime", "-r", help="Container runtime"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Save posture JSON to file"),
) -> None:
    """Run the enumerator script inside a container and retrieve the posture JSON."""
    # Validate container ID
    if not _CONTAINER_ID_RE.match(container_id):
        console.print("[red]Error: Invalid container ID. Must match [a-zA-Z0-9][a-zA-Z0-9_.-]*[/red]")
        raise typer.Exit(1)

    # Find the enumerator script
    script_path = Path(__file__).parent.parent.parent / "enumerator" / "cepheus-enum.sh"
    if not script_path.exists():
        script_path = Path("enumerator/cepheus-enum.sh")
    if not script_path.exists():
        console.print("[red]Error: Cannot find cepheus-enum.sh[/red]")
        raise typer.Exit(1)

    rt = runtime.value
    try:
        subprocess.run(
            [rt, "cp", str(script_path), "--", f"{container_id}:/tmp/cepheus-enum.sh"],
            check=True,
            capture_output=True,
        )
        result = subprocess.run(
            [rt, "exec", "--", container_id, "sh", "/tmp/cepheus-enum.sh"],
            check=True,
            capture_output=True,
            text=True,
        )
        posture_json = result.stdout
    except subprocess.CalledProcessError as e:
        console.print(f"[red]Error running enumerator: {e.stderr}[/red]")
        raise typer.Exit(1)
    except FileNotFoundError:
        console.print(f"[red]Error: '{rt}' not found in PATH[/red]")
        raise typer.Exit(1)

    # Validate JSON
    try:
        json.loads(posture_json)
    except json.JSONDecodeError:
        console.print("[red]Error: Enumerator did not produce valid JSON[/red]")
        console.print(posture_json[:500])
        raise typer.Exit(1)

    if output:
        output.write_text(posture_json)
        console.print(f"[green]Posture saved to {output}[/green]")
    else:
        console.print(posture_json)


@app.command()
def techniques(
    category: str | None = typer.Option(None, "--category", "-c", help="Filter by category"),
    severity: str | None = typer.Option(None, "--severity", "-s", help="Filter by severity"),
    search: str | None = typer.Option(None, "--search", "-q", help="Search name/description"),
) -> None:
    """List all known escape techniques."""
    from cepheus.engine.technique_db import get_all_techniques

    techs = get_all_techniques()

    if category:
        techs = [t for t in techs if t.category.value == category.lower()]

    if severity:
        techs = [t for t in techs if t.severity.value == severity.lower()]

    if search:
        search_lower = search.lower()
        techs = [
            t
            for t in techs
            if search_lower in t.name.lower()
            or search_lower in t.description.lower()
            or search_lower in t.id.lower()
        ]

    if not techs:
        console.print("[yellow]No techniques matched your filters.[/yellow]")
        raise typer.Exit(0)

    from cepheus.output.terminal import print_techniques

    print_techniques(techs)
