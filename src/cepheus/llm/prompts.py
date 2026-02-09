"""Prompt templates for LLM-assisted container escape analysis."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cepheus.models.chain import EscapeChain
    from cepheus.models.posture import ContainerPosture
    from cepheus.models.result import AnalysisResult


SYSTEM_PROMPT = """\
You are an expert container security analyst specializing in container escape \
techniques and privilege escalation. You analyze container security postures \
and identify potential escape paths, including novel combinations that \
automated tools might miss.

Your analysis should be:
- Technically precise with specific commands and paths
- Prioritized by risk (most dangerous first)
- Actionable with clear remediation steps
- Aware of the specific runtime and orchestrator context"""


def _format_posture(posture: ContainerPosture) -> str:
    """Summarize the container posture into a compact text block."""
    lines: list[str] = []

    lines.append(f"Kernel: {posture.kernel.version} "
                 f"({posture.kernel.major}.{posture.kernel.minor}.{posture.kernel.patch})")
    lines.append(f"Hostname: {posture.hostname}")
    lines.append(f"Cgroup version: {posture.cgroup_version}")

    # Capabilities
    if posture.capabilities.effective:
        lines.append(f"Effective capabilities: {', '.join(posture.capabilities.effective)}")
    if posture.capabilities.bounding:
        lines.append(f"Bounding capabilities: {', '.join(posture.capabilities.bounding)}")

    # Mounts
    if posture.mounts:
        lines.append("Mounts:")
        for m in posture.mounts:
            opts = ",".join(m.options) if m.options else "none"
            lines.append(f"  {m.source} -> {m.destination} ({m.fstype}, {opts})")

    # Security profiles
    lines.append(f"Seccomp: {posture.security.seccomp}")
    if posture.security.apparmor:
        lines.append(f"AppArmor: {posture.security.apparmor}")
    if posture.security.selinux:
        lines.append(f"SELinux: {posture.security.selinux}")

    # Namespaces
    ns = posture.namespaces
    shared = [n for n, active in [
        ("pid", ns.pid), ("net", ns.net), ("mnt", ns.mnt),
        ("user", ns.user), ("uts", ns.uts), ("ipc", ns.ipc),
        ("cgroup", ns.cgroup),
    ] if not active]
    if shared:
        lines.append(f"Shared namespaces (not isolated): {', '.join(shared)}")

    # Runtime
    rt = posture.runtime
    lines.append(f"Runtime: {rt.runtime}"
                 + (f" {rt.runtime_version}" if rt.runtime_version else ""))
    if rt.orchestrator:
        lines.append(f"Orchestrator: {rt.orchestrator}")
    if rt.privileged:
        lines.append("Container is PRIVILEGED")
    lines.append(f"PID 1: {rt.pid_one}")

    # Network
    net = posture.network
    if net.interfaces:
        lines.append(f"Network interfaces: {', '.join(net.interfaces)}")
    if net.can_reach_metadata:
        lines.append("Can reach cloud metadata endpoint")
    if net.can_reach_docker_sock:
        lines.append("Can reach Docker socket over network")
    if net.listening_ports:
        lines.append(f"Listening ports: {', '.join(str(p) for p in net.listening_ports)}")

    # Credentials
    cred = posture.credentials
    if cred.service_account_token:
        lines.append("Service account token present")
    if cred.environment_secrets:
        lines.append(f"Env vars with secrets: {', '.join(cred.environment_secrets)}")
    if cred.cloud_metadata_available:
        lines.append("Cloud metadata available")

    # Extras
    if posture.writable_paths:
        lines.append(f"Writable paths: {', '.join(posture.writable_paths)}")
    if posture.available_tools:
        lines.append(f"Available tools: {', '.join(posture.available_tools)}")

    return "\n".join(lines)


def _format_chains(chains: list[EscapeChain]) -> str:
    """Format matched escape chains into a compact text block."""
    if not chains:
        return "No escape chains were matched by the deterministic engine."

    lines: list[str] = []
    for i, chain in enumerate(chains, 1):
        lines.append(f"Chain {i}: {chain.id} (severity={chain.severity.value}, "
                     f"composite={chain.composite_score:.2f}, "
                     f"confidence={chain.confidence_score:.2f})")
        if chain.description:
            lines.append(f"  Description: {chain.description}")
        for j, step in enumerate(chain.steps, 1):
            t = step.technique
            lines.append(f"  Step {j}: [{t.id}] {t.name} "
                         f"(category={t.category.value}, severity={t.severity.value})")
            if step.poc_command:
                lines.append(f"    PoC: {step.poc_command}")
    return "\n".join(lines)


def build_analysis_prompt(
    posture: ContainerPosture,
    chains: list[EscapeChain],
) -> str:
    """Build the user prompt for posture + chain analysis."""
    return f"""\
Analyze the following container security posture and escape chains found by \
the deterministic engine.

== Container Posture ==
{_format_posture(posture)}

== Escape Chains Found ==
{_format_chains(chains)}

Based on this information:
1. Identify novel escape paths NOT covered by the chains above.
2. Assess which of the found chains are most dangerous in this specific context \
and explain why.
3. Suggest chain combinations the deterministic engine might have missed \
(e.g., combining a capability with a mount or kernel vuln).
4. Provide contextual remediation priorities — which fixes would have the \
highest impact?
5. Note any unusual or suspicious configurations that warrant investigation."""


def build_summary_prompt(result: AnalysisResult) -> str:
    """Build a prompt requesting an executive summary of the full analysis."""
    posture_text = _format_posture(result.posture)
    chains_text = _format_chains(result.chains)

    remediation_lines: list[str] = []
    for r in result.remediations:
        remediation_lines.append(
            f"- [{r.severity.value}] {r.technique_id}: {r.current_state} "
            f"-> {r.recommended_fix}"
            + (f" (flag: {r.runtime_flag})" if r.runtime_flag else "")
        )
    remediation_text = "\n".join(remediation_lines) if remediation_lines else "None"

    return f"""\
Provide an executive summary suitable for a security report based on this \
container escape analysis.

== Container Posture ==
{posture_text}

== Escape Chains ({len(result.chains)} found, \
{result.techniques_matched}/{result.total_techniques_checked} techniques matched) ==
{chains_text}

== Recommended Remediations ==
{remediation_text}

Write a concise executive summary covering:
1. Overall risk level and key findings
2. The most critical escape paths and their real-world impact
3. Top 3 remediation actions in priority order
4. Any additional observations

Keep the summary under 500 words. Use clear, non-jargon language suitable for \
both technical and management audiences."""
