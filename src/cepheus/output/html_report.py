"""Self-contained HTML report output for Cepheus analysis results."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from cepheus.models.result import AnalysisResult

SEVERITY_COLORS = {
    "critical": "#ff0000",
    "high": "#ff8c00",
    "medium": "#ffd700",
    "low": "#00cd00",
}

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Cepheus Analysis Report — {{ hostname }}</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, monospace;
         background: #0d1117; color: #c9d1d9; line-height: 1.6; padding: 20px; }
  .container { max-width: 1100px; margin: 0 auto; }
  h1 { color: #58a6ff; margin-bottom: 5px; }
  h2 { color: #58a6ff; margin: 30px 0 15px; border-bottom: 1px solid #21262d; padding-bottom: 8px; }
  h3 { color: #8b949e; margin: 15px 0 8px; }
  .meta { color: #8b949e; font-size: 0.9em; margin-bottom: 20px; }
  .badge { display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 0.85em;
           font-weight: bold; color: #fff; text-transform: uppercase; }
  .badge-critical { background: #ff0000; }
  .badge-high { background: #ff8c00; }
  .badge-medium { background: #ffd700; color: #000; }
  .badge-low { background: #00cd00; color: #000; }
  .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                  gap: 15px; margin: 15px 0; }
  .summary-card { background: #161b22; border: 1px solid #21262d; border-radius: 8px; padding: 15px; }
  .summary-card .label { color: #8b949e; font-size: 0.85em; }
  .summary-card .value { font-size: 1.4em; font-weight: bold; color: #c9d1d9; }
  table { width: 100%; border-collapse: collapse; margin: 10px 0; }
  th { background: #161b22; color: #58a6ff; text-align: left; padding: 10px; border-bottom: 2px solid #21262d; }
  td { padding: 10px; border-bottom: 1px solid #21262d; }
  tr:hover { background: #161b22; }
  details { background: #161b22; border: 1px solid #21262d; border-radius: 8px; margin: 10px 0; }
  summary { padding: 12px 15px; cursor: pointer; font-weight: bold; color: #c9d1d9; }
  summary:hover { background: #1c2128; }
  .detail-content { padding: 0 15px 15px; }
  .poc { background: #0d1117; border: 1px solid #21262d; border-radius: 4px; padding: 10px;
         font-family: monospace; font-size: 0.9em; white-space: pre-wrap; overflow-x: auto; }
  .llm-analysis { background: #161b22; border-left: 3px solid #a371f7; padding: 15px;
                  border-radius: 0 8px 8px 0; margin: 15px 0; white-space: pre-wrap; }
  .footer { margin-top: 40px; padding-top: 15px; border-top: 1px solid #21262d;
            color: #484f58; font-size: 0.85em; text-align: center; }
</style>
</head>
<body>
<div class="container">

<h1>Cepheus Analysis Report</h1>
<div class="meta">Host: {{ hostname }} | Kernel: {{ kernel_version }} | Runtime: {{ runtime }} | {{ timestamp }}</div>

<h2>Executive Summary</h2>
<div class="summary-grid">
  <div class="summary-card">
    <div class="label">Techniques Checked</div>
    <div class="value">{{ total_techniques }}</div>
  </div>
  <div class="summary-card">
    <div class="label">Techniques Matched</div>
    <div class="value">{{ techniques_matched }}</div>
  </div>
  <div class="summary-card">
    <div class="label">Escape Chains</div>
    <div class="value">{{ chain_count }}</div>
  </div>
  <div class="summary-card">
    <div class="label">Privileged</div>
    <div class="value">{{ privileged }}</div>
  </div>
  <div class="summary-card">
    <div class="label">Seccomp</div>
    <div class="value">{{ seccomp }}</div>
  </div>
</div>

{% if chains %}
<h2>Escape Chains</h2>
{% for chain in chains %}
<details>
  <summary>
    <span class="badge badge-{{ chain.severity }}">{{ chain.severity }}</span>
    {{ chain.description }} — Score: {{ chain.score }}
  </summary>
  <div class="detail-content">
    <p><strong>Chain ID:</strong> {{ chain.id }}</p>
    <p><strong>Reliability:</strong> {{ chain.reliability }} | <strong>Stealth:</strong> {{ chain.stealth }}</p>
    {% for step in chain.steps %}
    <h3>Step {{ loop.index }}: {{ step.name }}</h3>
    <p>{{ step.description }}</p>
    <p><strong>Confidence:</strong> {{ step.confidence }}</p>
    {% if step.poc %}
    <div class="poc">{{ step.poc }}</div>
    {% endif %}
    {% endfor %}
  </div>
</details>
{% endfor %}
{% endif %}

{% if remediations %}
<h2>Remediations</h2>
<table>
  <thead>
    <tr><th>Severity</th><th>Technique</th><th>Issue</th><th>Fix</th><th>Flag</th></tr>
  </thead>
  <tbody>
    {% for rem in remediations %}
    <tr>
      <td><span class="badge badge-{{ rem.severity }}">{{ rem.severity }}</span></td>
      <td>{{ rem.technique_id }}</td>
      <td>{{ rem.current_state }}</td>
      <td>{{ rem.recommended_fix }}</td>
      <td>{{ rem.runtime_flag }}</td>
    </tr>
    {% endfor %}
  </tbody>
</table>
{% endif %}

{% if mitre_ids %}
<h2>MITRE ATT&CK Mapping</h2>
<table>
  <thead>
    <tr><th>Technique ID</th><th>Matched Techniques</th></tr>
  </thead>
  <tbody>
    {% for mitre in mitre_ids %}
    <tr>
      <td>{{ mitre.id }}</td>
      <td>{{ mitre.techniques }}</td>
    </tr>
    {% endfor %}
  </tbody>
</table>
{% endif %}

{% if llm_analysis %}
<h2>LLM Analysis</h2>
<div class="llm-analysis">{{ llm_analysis }}</div>
{% endif %}

<div class="footer">
  Generated by Cepheus Container Escape Scenario Modeler
</div>

</div>
</body>
</html>
"""


def _prepare_context(result: AnalysisResult) -> dict[str, Any]:
    """Build the template context dict from an AnalysisResult."""
    chains = []
    mitre_map: dict[str, list[str]] = {}

    for chain in result.chains:
        steps = []
        for step in chain.steps:
            steps.append({
                "name": step.technique.name,
                "description": step.technique.description,
                "confidence": f"{step.prerequisite_confidence:.2f}",
                "poc": step.poc_command or "",
            })
            for mid in step.technique.mitre_attack:
                mitre_map.setdefault(mid, [])
                if step.technique.name not in mitre_map[mid]:
                    mitre_map[mid].append(step.technique.name)

        chains.append({
            "id": chain.id,
            "severity": chain.severity.value,
            "description": chain.description,
            "score": f"{chain.composite_score:.4f}",
            "reliability": f"{chain.reliability_score:.2f}",
            "stealth": f"{chain.stealth_score:.2f}",
            "steps": steps,
        })

    remediations = []
    for rem in result.remediations:
        remediations.append({
            "severity": rem.severity.value,
            "technique_id": rem.technique_id,
            "current_state": rem.current_state,
            "recommended_fix": rem.recommended_fix,
            "runtime_flag": rem.runtime_flag or "",
        })

    mitre_ids = [{"id": mid, "techniques": ", ".join(names)} for mid, names in sorted(mitre_map.items())]

    return {
        "hostname": result.posture.hostname or "unknown",
        "kernel_version": result.posture.kernel.version or "unknown",
        "runtime": result.posture.runtime.runtime,
        "timestamp": result.analysis_timestamp,
        "total_techniques": result.total_techniques_checked,
        "techniques_matched": result.techniques_matched,
        "chain_count": len(result.chains),
        "privileged": result.posture.runtime.privileged,
        "seccomp": result.posture.security.seccomp,
        "chains": chains,
        "remediations": remediations,
        "mitre_ids": mitre_ids,
        "llm_analysis": result.llm_analysis or "",
    }


def generate_html(result: AnalysisResult) -> str:
    """Render the analysis result as a self-contained HTML string."""
    try:
        from jinja2 import Environment
    except ImportError:
        raise ImportError(
            "jinja2 is required for HTML reports. Install it with: pip install cepheus[html]"
        )

    from markupsafe import Markup

    env = Environment(autoescape=True)
    template = env.from_string(_HTML_TEMPLATE)
    context = _prepare_context(result)
    # Mark PoC commands as safe — they come from internal templates, not user input
    for chain in context.get("chains", []):
        for step in chain.get("steps", []):
            if step.get("poc"):
                step["poc"] = Markup(step["poc"])
    return template.render(**context)


def write_html(result: AnalysisResult, path: str | Path) -> Path:
    """Write analysis result as a self-contained HTML file."""
    path = Path(path)
    html = generate_html(result)
    path.write_text(html)
    return path
