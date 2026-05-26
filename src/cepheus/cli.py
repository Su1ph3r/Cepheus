"""Cepheus CLI — Container Escape Scenario Modeler."""

from __future__ import annotations

import json
import re
import subprocess
from enum import Enum
from pathlib import Path
from typing import Any

import typer
from pydantic import ValidationError
from rich.console import Console
from rich.markup import escape as rich_escape

from cepheus import __version__
from cepheus.config import CepheusConfig


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"cepheus {__version__}")
        raise typer.Exit()


app = typer.Typer(
    name="cepheus",
    help="Container Escape Scenario Modeler — enumerate security posture and model escape paths.",
    no_args_is_help=True,
)


@app.callback()
def main(
    version: bool = typer.Option(
        None,
        "--version",
        "-V",
        callback=_version_callback,
        is_eager=True,
        help="Print version and exit.",
    ),
) -> None:
    pass


console = Console()

_CONTAINER_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.\-]*$")


class OutputFormat(str, Enum):
    terminal = "terminal"
    json = "json"
    mitre = "mitre"
    html = "html"
    sarif = "sarif"


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


def _validate_output_path(output: Path) -> None:
    """Reject obvious user mistakes on ``--output`` before we try to
    write. A directory path, or a nonexistent parent directory, would
    otherwise leak as an uncaught ``IsADirectoryError`` / ``FileNotFoundError``
    traceback to the user. Centralise the check so every caller gets
    consistent messaging."""
    if output.is_dir():
        console.print(f"[red]Error: --output is a directory, not a file: {output}[/red]")
        raise typer.Exit(2)
    parent = output.parent
    # An empty parent path means "current directory" — always exists.
    if str(parent) not in ("", ".") and not parent.exists():
        console.print(f"[red]Error: --output parent directory does not exist: {parent}[/red]")
        raise typer.Exit(2)


def _load_posture(posture_file: Path):
    """Load and validate a posture JSON file, exiting on errors."""
    if not posture_file.exists():
        console.print(f"[red]Error: File not found: {posture_file}[/red]")
        raise typer.Exit(1)

    try:
        data = json.loads(posture_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        console.print(f"[red]Error: Invalid JSON: {e}[/red]")
        raise typer.Exit(1)

    _require_posture_shape(data, source=str(posture_file))

    from cepheus.models.posture import ContainerPosture

    # Narrow to ValidationError: anything else (AttributeError, TypeError)
    # indicates a refactor bug on the model side and should surface as a
    # real traceback so it gets fixed instead of buried in a friendly
    # "Invalid posture data" message.
    try:
        return ContainerPosture.model_validate(data)
    except ValidationError as e:
        console.print(f"[red]Error: Invalid posture data: {e}[/red]")
        raise typer.Exit(1)


def _run_analysis(
    posture: Any,
    config: CepheusConfig,
    *,
    llm: bool = False,
) -> Any:
    """Run the engine pipeline + optional LLM enrichment on a posture.

    Shared by `analyze` and `ci` so we don't drift the pipeline behaviour
    between user-facing and machine-facing entry points.

    Note: executive summary generation is intentionally NOT done here —
    callers should apply ``_filter_by_severity`` first and then call
    ``_run_executive_summary`` so the summary describes the chains the
    user will actually see in the rendered report.
    """
    from cepheus.engine.analyzer import analyze as run_analysis

    result = run_analysis(posture, config)

    if llm:
        try:
            from cepheus.llm.client import LLMClient

            client = LLMClient(config)
            result.llm_analysis = client.analyze_posture_sync(posture, result.chains)
            # Stash the client on the result so a later
            # `_run_executive_summary` can reuse the same auth.
            result._llm_client = client  # noqa: SLF001 — internal stash, not serialized
        except ImportError:
            console.print("[yellow]Warning: LLM extra not installed. Run: pip install cepheus[llm][/yellow]")
        except (AttributeError, TypeError):
            # Programming bugs (renamed method, wrong signature) must NOT
            # be swallowed as "LLM failed" warnings — they need to be
            # fixed. Re-raise so the user sees a real traceback.
            raise
        except Exception as exc:
            console.print(f"[yellow]Warning: LLM analysis failed: {type(exc).__name__}: {exc}[/yellow]")

    return result


def _run_executive_summary(result: Any, *, llm: bool) -> None:
    """Generate the LLM executive summary on a (potentially filtered)
    result. Mutates ``result.executive_summary`` in place.

    Run AFTER ``_filter_by_severity`` so the summary discusses the
    chains the user will actually see. Pre-0.3.5 the summary was built
    before filtering, producing reports that referenced chains the user
    had explicitly excluded.
    """
    if not llm:
        console.print("[yellow]Warning: --executive-summary requires --llm flag[/yellow]")
        return
    client = getattr(result, "_llm_client", None)
    if client is None:
        return
    try:
        result.executive_summary = client.summarize_sync(result)
    except (AttributeError, TypeError):
        raise
    except Exception as exc:
        console.print(f"[yellow]Warning: Executive summary generation failed: {type(exc).__name__}: {exc}[/yellow]")


def _filter_by_severity(result: Any, min_severity: SeverityFilter) -> None:
    """Drop chains and remediations below the minimum severity. Mutates in
    place. Applied AFTER per-chain LLM enrichment so the LLM sees all
    chains, but BEFORE executive-summary generation so the summary
    describes only the visible set.

    Unknown severities are a programming error (new enum value not added
    to SEVERITY_RANK). Use direct indexing so KeyError surfaces instead
    of `dict.get(..., 0)` silently routing the chain below every gate.

    Also stashes the post-filter unique technique count onto
    ``result.techniques_in_visible_chains`` (additive — does NOT overwrite
    the pre-filter ``techniques_matched`` field that consumers may chart
    over time). Downstream renderers prefer the new field when present
    to keep summary counts consistent with rendered chain counts.
    """
    min_rank = SEVERITY_RANK[min_severity.value]
    result.chains = [c for c in result.chains if SEVERITY_RANK[c.severity.value] >= min_rank]
    result.remediations = [r for r in result.remediations if SEVERITY_RANK[r.severity.value] >= min_rank]
    visible_ids = {step.technique.id for chain in result.chains for step in chain.steps if step.technique is not None}
    result.techniques_in_visible_chains = len(visible_ids)


def _render_output(
    result: Any,
    format: OutputFormat,
    output: Path | None,
    *,
    auto_write_json: bool = False,
) -> None:
    """Format dispatch for analysis results. Shared by `analyze` and `ci`.

    Each format owns its own file-write branch. The ``auto_write_json``
    flag is the one back-compat lever: when True (only ``analyze``
    passes True), the terminal format ALSO writes a JSON report when
    ``-o`` is set — preserving the documented v0.3.x shortcut where
    ``analyze posture.json -o report.json`` (no ``--format``) produces
    JSON on disk. ``ci`` deliberately passes False so its
    ``--format text -o gate.log`` invocation produces text content, not
    a silent JSON dump under a .log extension.
    """
    if output:
        _validate_output_path(output)

    if format == OutputFormat.json:
        if output:
            from cepheus.output.json_report import write_report

            write_report(result, output)
            console.print(f"[green]Report written to {output}[/green]")
        else:
            from cepheus.output.json_report import generate_report

            console.print_json(json.dumps(generate_report(result)))
    elif format == OutputFormat.mitre:
        from cepheus.output.mitre_layer import generate_layer, write_layer

        if output:
            write_layer(result, output)
            console.print(f"[green]MITRE ATT&CK Navigator layer written to {output}[/green]")
        else:
            console.print_json(json.dumps(generate_layer(result)))
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
    elif format == OutputFormat.sarif:
        from cepheus.output.sarif import generate_sarif, write_sarif

        if output:
            write_sarif(result, output)
            console.print(f"[green]SARIF report written to {output}[/green]")
        else:
            console.print_json(json.dumps(generate_sarif(result)))
    else:  # terminal
        if auto_write_json and output:
            # Preserve documented v0.3.x analyze back-compat: bare `-o X.json`
            # without `--format` produces JSON on disk. ci does NOT pass
            # auto_write_json=True so its `--format text -o gate.log`
            # invocation falls through to terminal-only rendering.
            from cepheus.output.json_report import write_report

            write_report(result, output)
            console.print(f"[green]Report written to {output}[/green]")
        from cepheus.output.terminal import print_analysis_result

        print_analysis_result(result)


@app.command()
def analyze(
    posture_file: Path = typer.Argument(..., help="Path to posture JSON from enumerator"),
    format: OutputFormat = typer.Option(OutputFormat.terminal, "--format", "-f", help="Output format"),
    min_severity: SeverityFilter = typer.Option(
        SeverityFilter.low, "--min-severity", "-s", help="Minimum severity to show"
    ),
    llm: bool = typer.Option(False, "--llm", help="Enable LLM enrichment"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write report to file"),
    executive_summary: bool = typer.Option(
        False, "--executive-summary", help="Generate LLM executive summary (requires --llm)"
    ),
) -> None:
    """Analyze a container posture JSON file and identify escape paths."""
    posture = _load_posture(posture_file)
    config = CepheusConfig()
    # 1) Run engine + per-chain LLM hints on the full chain set.
    result = _run_analysis(posture, config, llm=llm)
    # 2) Filter to what the user requested.
    _filter_by_severity(result, min_severity)
    # 3) Summarize what the user will see — runs after filter so the
    #    summary describes only visible chains (pre-0.3.5 bug: summary
    #    referenced chains the user had filtered out).
    if executive_summary:
        _run_executive_summary(result, llm=llm)
    # 4) Render — auto_write_json preserves the documented analyze
    #    back-compat where `-o X.json` writes JSON even without `--format json`.
    _render_output(result, format, output, auto_write_json=True)


class CIFormat(str, Enum):
    """Output formats supported by `cepheus ci`. SARIF is the default
    because it's the format GitHub Code Scanning ingests; JSON for
    other tooling; text for humans inspecting CI logs."""

    sarif = "sarif"
    json = "json"
    text = "text"


@app.command(name="ci")
def ci(
    target: str = typer.Argument(
        ...,
        help=("Image reference (e.g. nginx:latest) OR path to a posture JSON file from a previous enumerate run."),
    ),
    baseline: Path | None = typer.Option(
        None,
        "--baseline",
        "-b",
        help="Path to a previous Cepheus report (JSON or SARIF). When passed with --fail-on-new, exit non-zero on chains absent from this baseline.",
    ),
    max_severity: SeverityFilter | None = typer.Option(
        None,
        "--max-severity",
        "-m",
        help="Fail the build if any chain has this severity or higher. Defaults to no severity gate; pair with --fail-on-new for regression-only gating.",
    ),
    fail_on_new: bool = typer.Option(
        False,
        "--fail-on-new",
        help="Fail the build if any chain is present in the current scan but not in --baseline. Requires --baseline.",
    ),
    format: CIFormat = typer.Option(
        CIFormat.sarif,
        "--format",
        "-f",
        help="Output format. SARIF is uploadable to GitHub Code Scanning.",
    ),
    output: Path | None = typer.Option(
        None,
        "--output",
        "-o",
        help="Write report to file (recommended for CI).",
    ),
    runtime: ContainerRuntime = typer.Option(
        ContainerRuntime.docker,
        "--runtime",
        "-r",
        help="Container runtime for image-based enumeration.",
    ),
) -> None:
    """CI gate: enumerate + analyze + (optionally) compare against a baseline.

    Two ways to call:

      cepheus ci nginx:latest --max-severity critical --format sarif -o out.sarif
      cepheus ci posture.json --baseline baseline.sarif --fail-on-new

    The first form enumerates the image in an ephemeral container, analyzes
    its posture, and exits non-zero if any chain is `critical` or higher.
    The second form analyzes a pre-captured posture file and exits non-zero
    if any chain appears that wasn't in the baseline.

    The default output is SARIF, which GitHub Code Scanning ingests directly
    via `github/codeql-action/upload-sarif`.
    """
    if fail_on_new and baseline is None:
        console.print("[red]Error: --fail-on-new requires --baseline[/red]")
        raise typer.Exit(2)

    # Decide: is `target` a posture file path, or an image reference?
    # A posture file must exist on disk AND parse as JSON containing
    # the ContainerPosture shape. Anything else is treated as an image.
    target_path = Path(target)
    if target_path.exists() and target_path.is_file():
        posture = _load_posture(target_path)
    else:
        # Rich-escape `target` so an image string containing markup
        # (e.g. `nginx[link=evil]:tag`) can't inject clickable links or
        # other Rich markup into CI logs.
        console.print(f"[cyan]Enumerating image: {rich_escape(target)}[/cyan]")
        posture_json = _enumerate_image(target, runtime.value)
        data = _validate_posture_json(posture_json)
        from cepheus.models.posture import ContainerPosture

        try:
            posture = ContainerPosture.model_validate(data)
        except ValidationError as e:
            console.print(f"[red]Error: Invalid posture from enumerator: {e}[/red]")
            raise typer.Exit(1)

    # Run the same analysis pipeline `analyze` uses. No LLM enrichment in
    # CI by default — fast, deterministic, no API-key handling.
    config = CepheusConfig()
    result = _run_analysis(posture, config, llm=False)

    # Severity gate. Use direct indexing on SEVERITY_RANK so a new
    # severity tier raises loudly instead of silently slipping below the
    # gate via `dict.get(..., 0)`.
    gate_severity_fail = False
    if max_severity is not None:
        gate_rank = SEVERITY_RANK[max_severity.value]
        offenders = [c for c in result.chains if SEVERITY_RANK[c.severity.value] >= gate_rank]
        if offenders:
            gate_severity_fail = True
            console.print(
                f"[red]Severity gate failed: {len(offenders)} chain(s) at severity >= {max_severity.value}[/red]"
            )
            for c in offenders[:5]:
                # Backslash-escape the literal square brackets so Rich doesn't
                # interpret e.g. `[critical]` as a markup tag and drop it.
                console.print(f"  - \\[{c.severity.value}] {c.steps[0].technique.id} (score={c.composite_score:.2f})")
            if len(offenders) > 5:
                console.print(f"  ... and {len(offenders) - 5} more")

    # Baseline-regression gate.
    gate_baseline_fail = False
    if baseline is not None:
        from cepheus.engine.baseline import diff as baseline_diff
        from cepheus.engine.baseline import load_baseline

        try:
            baseline_set = load_baseline(baseline)
        except ValueError as e:
            console.print(f"[red]Error loading baseline: {e}[/red]")
            raise typer.Exit(2)
        diff_result = baseline_diff(result.chains, baseline_set)
        console.print(
            f"[cyan]Baseline: {len(diff_result.preserved)} preserved, "
            f"{len(diff_result.new)} new, {len(diff_result.removed)} removed[/cyan]"
        )
        if fail_on_new and diff_result.has_regressions:
            gate_baseline_fail = True
            console.print(f"[red]Baseline regression: {len(diff_result.new)} new chain(s) introduced[/red]")
            for c in diff_result.new[:5]:
                console.print(f"  + \\[{c.severity.value}] {c.steps[0].technique.id} (score={c.composite_score:.2f})")
            if len(diff_result.new) > 5:
                console.print(f"  ... and {len(diff_result.new) - 5} more")

    # Render output regardless of gate result — operators want the report
    # even when the build fails.
    fmt_map = {
        CIFormat.sarif: OutputFormat.sarif,
        CIFormat.json: OutputFormat.json,
        CIFormat.text: OutputFormat.terminal,
    }
    _render_output(result, fmt_map[format], output)

    if gate_severity_fail or gate_baseline_fail:
        raise typer.Exit(1)


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
            _validate_output_path(output)
            Path(output).write_text(json.dumps(report, indent=2), encoding="utf-8")
            console.print(f"[green]Diff report written to {output}[/green]")
        else:
            console.print_json(json.dumps(report))
    else:
        from cepheus.output.diff_terminal import print_diff_result

        print_diff_result(diff_result)


def _find_enumerator_script() -> Path:
    """Locate the enumerator shell script — package-relative first, then
    CWD-relative for in-development runs. Exits 1 if not found."""
    script_path = Path(__file__).parent.parent.parent / "enumerator" / "cepheus-enum.sh"
    if not script_path.exists():
        script_path = Path("enumerator/cepheus-enum.sh")
    if not script_path.exists():
        console.print("[red]Error: Cannot find cepheus-enum.sh[/red]")
        raise typer.Exit(1)
    return script_path


# Wall-clock cap on enumerator subprocess invocations. The enumerator
# itself finishes well under 5s in normal operation; a 120s budget
# tolerates slow image pulls and hostPID-heavy pods while still bounding
# a hung script. Image-pull time counts against this budget.
_ENUMERATOR_TIMEOUT_SECONDS = 120


def _enumerate_container(container_id: str, runtime: str) -> str:
    """Stream the enumerator into a running container's stdin and execute it.

    Returns posture JSON on stdout. Exits 1 on any subprocess error.

    Streams via stdin rather than `docker cp`-then-`docker exec` to
    avoid a TOCTOU window where a co-tenant process in the target
    container could replace `/tmp/cepheus-enum.sh` between the copy and
    the exec. The stdin form never touches a filesystem path in the
    target, leaves no leftover script artifact for forensics to flag,
    and avoids cross-invocation collisions when multiple `cepheus`
    commands run against the same container.
    """
    if not _CONTAINER_ID_RE.match(container_id):
        console.print("[red]Error: Invalid container ID. Must match [a-zA-Z0-9][a-zA-Z0-9_.-]*[/red]")
        raise typer.Exit(1)

    script_path = _find_enumerator_script()
    script_bytes = script_path.read_bytes()

    try:
        result = subprocess.run(
            [runtime, "exec", "-i", "--", container_id, "sh"],
            input=script_bytes,
            check=True,
            capture_output=True,
            timeout=_ENUMERATOR_TIMEOUT_SECONDS,
        )
    except subprocess.CalledProcessError as e:
        stderr_text = ""
        if e.stderr:
            stderr_text = e.stderr.decode("utf-8", errors="replace") if isinstance(e.stderr, bytes) else str(e.stderr)
        console.print(f"[red]Error running enumerator: {rich_escape(stderr_text)}[/red]")
        raise typer.Exit(1)
    except subprocess.TimeoutExpired:
        console.print(
            f"[red]Error: enumerator did not complete within "
            f"{_ENUMERATOR_TIMEOUT_SECONDS}s in container "
            f"'{rich_escape(container_id)}'.[/red]"
        )
        raise typer.Exit(1)
    except FileNotFoundError:
        console.print(f"[red]Error: '{rich_escape(runtime)}' not found in PATH[/red]")
        raise typer.Exit(1)

    stdout_text = result.stdout.decode("utf-8", errors="replace") if isinstance(result.stdout, bytes) else result.stdout

    # Mirror the empty-stdout guard from _enumerate_image — a clean exit
    # 0 with no output silently produces a zero-finding scan, which is
    # the worst failure mode for a security tool. Detect and fail loudly.
    if not (stdout_text or "").strip():
        stderr_text = ""
        if result.stderr:
            raw = result.stderr
            stderr_text = (raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw).strip()
        console.print(
            f"[red]Error: enumerator produced no output for container "
            f"'{rich_escape(container_id)}'. The container's /bin/sh likely "
            f"exited before the enumerator could run, or the enumerator was "
            f"killed mid-run.[/red]"
        )
        if stderr_text:
            console.print(f"[yellow]Enumerator stderr:\n{rich_escape(stderr_text)}[/yellow]")
        raise typer.Exit(1)

    if result.stderr:
        raw = result.stderr
        stderr_text = (raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else raw).strip()
        if stderr_text:
            console.print(f"[yellow]Enumerator stderr (non-fatal):\n{rich_escape(stderr_text)}[/yellow]")

    return stdout_text


def _enumerate_image(image: str, runtime: str) -> str:
    """Spin up an ephemeral container from `image`, run the enumerator
    inside it via `--entrypoint sh`, and capture posture JSON.

    Less rich than enumerating a running pod (no live SA token, no
    cluster context, no real network) but enough to catch privileged +
    capability misconfigs at build time. The CI command relies on this
    to gate `docker build` outputs before they reach a cluster.
    """
    if "://" in image or image.startswith(("-", "/")):
        # Refuse anything that looks like a URL/flag/path. Image refs
        # look like `nginx:latest`, `ghcr.io/org/img:tag`, etc.
        console.print(f"[red]Error: Image reference looks suspicious: {rich_escape(image)}[/red]")
        raise typer.Exit(1)

    script_path = _find_enumerator_script()
    # Mount the enumerator into a fresh container and override its
    # entrypoint to invoke sh. `--rm` cleans up after. The image's own
    # CMD is ignored. A wall-clock timeout caps total wall time including
    # image pull — if the budget is exceeded the docker CLI is killed
    # but the daemon-side container may keep running until its entrypoint
    # exits; `--rm` still fires on that exit, so cleanup happens
    # eventually but not synchronously.
    try:
        result = subprocess.run(
            [
                runtime,
                "run",
                "--rm",
                "-v",
                f"{script_path.resolve()}:/tmp/cepheus-enum.sh:ro",
                "--entrypoint",
                "sh",
                image,
                "/tmp/cepheus-enum.sh",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=_ENUMERATOR_TIMEOUT_SECONDS,
        )
    except subprocess.CalledProcessError as e:
        stderr_text = ""
        if e.stderr:
            stderr_text = e.stderr.decode("utf-8", errors="replace") if isinstance(e.stderr, bytes) else str(e.stderr)
        console.print(
            f"[red]Error running enumerator in image '{rich_escape(image)}': {rich_escape(stderr_text)}[/red]"
        )
        raise typer.Exit(1)
    except subprocess.TimeoutExpired:
        console.print(
            f"[red]Error: enumerator did not complete within "
            f"{_ENUMERATOR_TIMEOUT_SECONDS}s for image "
            f"'{rich_escape(image)}'. The image pull or enumerator script "
            f"may be hung.[/red]"
        )
        raise typer.Exit(1)
    except FileNotFoundError:
        console.print(f"[red]Error: '{rich_escape(runtime)}' not found in PATH[/red]")
        raise typer.Exit(1)

    # `check=True` only catches non-zero exit. Docker can exit 0 with
    # zero stdout when the image lacks /bin/sh (distroless/scratch) and
    # the enumerator never executes — silently producing a zero-finding
    # scan that passes every CI gate. Detect that here.
    if not result.stdout.strip():
        stderr_text = (result.stderr or "").strip()
        console.print(
            f"[red]Error: enumerator produced no output for image '{rich_escape(image)}'. "
            f"The image likely lacks /bin/sh (distroless or scratch). "
            f"Enumerate from inside a running pod via "
            f"`cepheus enumerate --container-id <id>` instead.[/red]"
        )
        if stderr_text:
            console.print(f"[yellow]Enumerator stderr:\n{rich_escape(stderr_text)}[/yellow]")
        raise typer.Exit(1)

    # Surface stderr even on success — Docker emits real warnings there
    # (e.g. platform mismatch) that operators need to see.
    if result.stderr and result.stderr.strip():
        console.print(f"[yellow]Enumerator stderr (non-fatal):\n{rich_escape(result.stderr.strip())}[/yellow]")

    return result.stdout


# Load-bearing top-level keys: the analyzer consumes both `kernel` (for
# every CVE-bound technique's version check) and `runtime` (for sandbox
# / orchestrator / privileged gates), so a posture missing either is
# not a real Cepheus posture. The schema check defends every downstream
# caller against `ContainerPosture.model_validate({})` succeeding (every
# field has a default, so an empty dict yields a "zero-finding" scan
# that passes every gate). `enumeration_version`, `hostname`, etc. are
# informational and not required here so hand-written fixtures with
# only the analyzer-relevant fields remain valid input.
_REQUIRED_POSTURE_KEYS = ("kernel", "runtime")


def _require_posture_shape(data: Any, *, source: str) -> None:
    """Reject anything that doesn't look like a Cepheus posture JSON.

    Pydantic's `ContainerPosture` model defaults every field, so an empty
    `{}` parses successfully into a fully-default posture (no caps, no
    mounts, no CVEs) — which the analyzer reports as zero chains and the
    CI gate passes. That's the worst kind of silent failure for a
    security tool. Refuse here before `model_validate` ever sees the
    data so the user gets a clear error pointing at the broken source.
    """
    if not isinstance(data, dict):
        console.print(f"[red]Error: {source}: posture must be a JSON object (got {type(data).__name__}).[/red]")
        raise typer.Exit(1)

    missing = [k for k in _REQUIRED_POSTURE_KEYS if k not in data]
    if missing:
        console.print(
            f"[red]Error: {source}: posture is missing required key(s): "
            f"{', '.join(missing)}. This is not a valid Cepheus posture; the "
            f"enumerator likely failed to produce output (e.g. distroless image, "
            f"non-POSIX sh, mid-run interruption). See `cepheus enumerate --help`.[/red]"
        )
        raise typer.Exit(1)


def _validate_posture_json(posture_json: str) -> dict[str, Any]:
    """Parse + structurally validate an enumerator's JSON stdout.

    Returns the parsed dict so callers don't have to re-parse. Raises
    typer.Exit on malformed JSON or missing structural keys.
    """
    try:
        data = json.loads(posture_json)
    except json.JSONDecodeError:
        console.print("[red]Error: Enumerator did not produce valid JSON[/red]")
        console.print(posture_json[:500])
        raise typer.Exit(1)

    _require_posture_shape(data, source="enumerator output")
    return data


@app.command()
def verify(
    container_id: str = typer.Option(
        ..., "--container-id", "-c", help="Running container ID or name to verify against"
    ),
    posture_file: Path | None = typer.Option(
        None,
        "--posture",
        "-p",
        help="Path to a posture JSON for this container. If omitted, runs `enumerate` against the container first.",
    ),
    all_critical: bool = typer.Option(
        False,
        "--all-critical",
        help="Only verify techniques with severity 'critical' or 'high'. Default verifies all matched techniques.",
    ),
    technique: list[str] = typer.Option(
        None,
        "--technique",
        "-t",
        help="Verify only these specific technique IDs (repeatable). Combines with --all-critical via OR.",
    ),
    runtime: ContainerRuntime = typer.Option(
        ContainerRuntime.docker, "--runtime", "-r", help="Container runtime for `exec` calls"
    ),
    timeout: int = typer.Option(10, "--timeout", help="Per-verifier wall-clock cap in seconds (kills runaway probes)."),
    format: OutputFormat = typer.Option(
        OutputFormat.terminal, "--format", "-f", help="Output format: terminal or json"
    ),
    output: Path | None = typer.Option(None, "--output", "-o", help="Write verification report to file"),
) -> None:
    """Live verification of matched techniques against a running container.

    For each matched technique that has a ``verify_command`` defined (23
    of the 65 currently), runs the command inside the container and
    classifies the outcome as CONFIRMED (kernel/runtime permits the
    primitive), NOT_CONFIRMED (rejected — static match was a false
    positive), NO_VERIFIER (no automated check exists), or ERROR
    (verifier infrastructure failed: timeout, runtime binary missing).

    Verify commands are BEST-EFFORT non-destructive — most are read-only
    or use the open-then-close (``exec 3>>X; exec 3>&-``) idiom that
    triggers the kernel's permission check without actually writing.
    A couple (``cap_sys_admin_mount``, ``cap_net_admin``) perform
    transient state changes that self-clean on the same shell line;
    treat these as "minimally-destructive transient state" rather than
    "strictly read-only." The verifier never exploits.

    Exit code is 0 if at least one technique is CONFIRMED (the
    container has confirmed escape primitives), 1 otherwise — mirrors
    grep semantics where 0 means "found something." For CI gates that
    want "exit 0 = hardened, exit non-zero = vuln," invert the check
    in the calling script (``cepheus verify || ship_safely``).
    """
    # 1) Load or capture posture.
    if posture_file is not None:
        posture = _load_posture(posture_file)
    else:
        console.print(f"[cyan]Enumerating {rich_escape(container_id)} first...[/cyan]")
        posture_json = _enumerate_container(container_id, runtime.value)
        data = _validate_posture_json(posture_json)
        from cepheus.models.posture import ContainerPosture

        try:
            posture = ContainerPosture.model_validate(data)
        except ValidationError as e:
            console.print(f"[red]Error: Invalid posture from enumerator: {e}[/red]")
            raise typer.Exit(1)

    # 2) Run analysis to get matched techniques.
    config = CepheusConfig()
    result = _run_analysis(posture, config, llm=False)

    # 3) Set up filters.
    only_severities: set[str] | None = None
    if all_critical:
        only_severities = {"critical", "high"}
    only_technique_ids: set[str] | None = None
    if technique:
        only_technique_ids = set(technique)

    # 4) Verify.
    from cepheus.engine.verifier import VerifyOutcome, verify_analysis

    console.print(f"[cyan]Running live verifiers against {rich_escape(container_id)}...[/cyan]")
    report = verify_analysis(
        result,
        container_id=container_id,
        runtime=runtime.value,
        timeout=timeout,
        only_severities=only_severities,
        only_technique_ids=only_technique_ids,
    )

    # 5) Render.
    if format == OutputFormat.json:
        payload = {
            "container_id": container_id,
            "summary": {
                "confirmed": report.confirmed_count,
                "not_confirmed": report.not_confirmed_count,
                "no_verifier": report.no_verifier_count,
                "error": report.error_count,
                "total": len(report.results),
            },
            "results": [
                {
                    "technique_id": r.technique_id,
                    "technique_name": r.technique_name,
                    "severity": r.severity,
                    "outcome": r.outcome.value,
                    "exit_code": r.exit_code,
                    "stderr": r.stderr,
                }
                for r in report.results
            ],
        }
        text = json.dumps(payload, indent=2)
        if output:
            _validate_output_path(output)
            output.write_text(text + "\n", encoding="utf-8")
            console.print(f"[green]Verification report written to {output}[/green]")
        else:
            console.print_json(text)
    else:
        # Terminal table.
        from rich.table import Table

        table = Table(title=f"Cepheus Verify — {rich_escape(container_id)}", show_lines=False)
        table.add_column("Outcome", style="bold")
        table.add_column("Severity")
        table.add_column("Technique")
        table.add_column("Exit", justify="right")

        outcome_color = {
            VerifyOutcome.CONFIRMED: "red",
            VerifyOutcome.NOT_CONFIRMED: "green",
            VerifyOutcome.NO_VERIFIER: "yellow",
            VerifyOutcome.ERROR: "magenta",
        }
        for r in report.results:
            color = outcome_color[r.outcome]
            exit_str = "" if r.exit_code is None else str(r.exit_code)
            table.add_row(
                f"[{color}]{r.outcome.value}[/{color}]",
                r.severity,
                f"{r.technique_id} — {r.technique_name}",
                exit_str,
            )
        console.print(table)
        console.print(
            f"\n[bold]Summary:[/bold] {report.confirmed_count} confirmed, "
            f"{report.not_confirmed_count} not confirmed, "
            f"{report.no_verifier_count} no verifier, "
            f"{report.error_count} error"
        )

    # Exit 0 if any technique CONFIRMED — the container has at least one
    # verified escape primitive. Exit 1 if nothing confirmed (clean) — this
    # mirrors `grep` / `test` semantics where 0 means "found something".
    raise typer.Exit(0 if report.confirmed_count > 0 else 1)


@app.command()
def enumerate(
    container_id: str | None = typer.Option(None, "--container-id", "-c", help="Running container ID or name"),
    image: str | None = typer.Option(
        None, "--image", "-i", help="Image reference (e.g. nginx:latest) — spins up an ephemeral container"
    ),
    runtime: ContainerRuntime = typer.Option(ContainerRuntime.docker, "--runtime", "-r", help="Container runtime"),
    output: Path | None = typer.Option(None, "--output", "-o", help="Save posture JSON to file"),
) -> None:
    """Run the enumerator script inside a container and retrieve the posture JSON.

    Provide exactly one of `--container-id` (enumerate a running container) or
    `--image` (spin up an ephemeral container from an image reference).
    """
    if (container_id is None) == (image is None):
        console.print("[red]Error: pass exactly one of --container-id or --image[/red]")
        # Exit 2 = invocation/configuration error, matching the
        # convention documented in docs/CI.md for `cepheus ci`.
        raise typer.Exit(2)

    if container_id is not None:
        posture_json = _enumerate_container(container_id, runtime.value)
    else:
        assert image is not None
        posture_json = _enumerate_image(image, runtime.value)

    _validate_posture_json(posture_json)

    if output:
        _validate_output_path(output)
        output.write_text(posture_json, encoding="utf-8")
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
            if search_lower in t.name.lower() or search_lower in t.description.lower() or search_lower in t.id.lower()
        ]

    if not techs:
        console.print("[yellow]No techniques matched your filters.[/yellow]")
        raise typer.Exit(0)

    from cepheus.output.terminal import print_techniques

    print_techniques(techs)
