"""Precision regression suite — locks in the 100%/100% TP/FP result from v0.3.1.

These tests load 10 real-world container posture JSONs captured from a
deliberately-vulnerable Kubernetes Goat cluster on `kind` and assert that
the analyzer produces exactly the matched-technique set we expect for each
posture. The fixtures live at `tests/fixtures/k8s-goat/`; see the README
there for provenance and the regeneration procedure.

Two kinds of regression caught here:

1. **Precision regression** — a technique fires on a pod where it shouldn't.
   The per-pod EXPECTED sets are exact: any extra technique match surfaces
   immediately. The shared FORBIDDEN_TECHNIQUES set lists technique IDs
   that should NEVER match these postures (they're the specific FPs we
   eliminated in v0.3.1 — IngressNightmare without ingress-nginx,
   nf_tables CVE on WSL2-backported kernels, etc.).

2. **Recall regression** — a technique that legitimately matches stops
   matching (e.g. someone tightens a prerequisite too far). The per-pod
   EXPECTED sets are exact in both directions: any missing match fails.

The 10-pod scan totals: **71 matched techniques** distributed as 20 + 18 +
4 + 4 + 4 + 5 + 4 + 4 + 4 + 4 = 71.

These tests are marked `@pytest.mark.benchmark` and load fixtures from
disk, so they're slower than the unit suite. Skip with `pytest -m "not
benchmark"` during fast local iteration.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cepheus.config import CepheusConfig
from cepheus.engine.analyzer import analyze
from cepheus.models.posture import ContainerPosture

FIXTURES = Path(__file__).parent / "fixtures" / "k8s-goat"


# Expected matched-technique sets per pod, established at v0.3.1.
# To re-baseline after legitimate technique-database changes, run:
#   python -c "import json; from pathlib import Path; from cepheus.engine.analyzer import analyze; from cepheus.models.posture import ContainerPosture; \
#     p = ContainerPosture.model_validate_json(Path('tests/fixtures/k8s-goat/T1-system-monitor-posture.json').read_text()); \
#     r = analyze(p); \
#     print(sorted({s.technique.id for c in r.chains for s in c.steps}))"
# and update the corresponding set below.
EXPECTED_MATCHES: dict[str, set[str]] = {
    "T1-system-monitor": {
        # Privileged + hostPID + hostIPC + hostPath:/ rw — textbook host escape.
        "cap_dac_override",
        "cap_dac_read_search",
        "cap_net_admin",
        "cap_sys_admin_bpf",
        "cap_sys_admin_mount",
        "cap_sys_ptrace",  # TP here because hostPID:true
        "cap_sys_rawio",
        "devfs_access",
        "ebpf_probe_write_user",
        "env_secret_leak",  # K8S_GOAT_VAULT_KEY injected via env
        "k8s_configmap_secrets",
        "k8s_kubelet_api",
        "k8s_node_proxy",
        "k8s_service_account",
        "lsm_selinux_unconfined",  # WSL has no SELinux
        "proc_fd_symlink_traversal",
        "procfs_core_pattern",
        "procfs_sysrq",
        "tmpfs_shm_cross_container",
        "writable_proc_privileged",
    },
    "T2-health-check": {
        # Privileged + full caps + writable proc/sys/dev — broad capability TPs.
        "cap_dac_override",
        "cap_dac_read_search",
        "cap_net_admin",
        "cap_sys_admin_bpf",
        "cap_sys_admin_mount",
        "cap_sys_rawio",
        "devfs_access",
        "ebpf_probe_write_user",
        "k8s_configmap_secrets",
        "k8s_kubelet_api",
        "k8s_node_proxy",
        "k8s_service_account",
        "lsm_selinux_unconfined",
        "proc_fd_symlink_traversal",
        "procfs_core_pattern",
        "procfs_sysrq",
        "tmpfs_shm_cross_container",
        "writable_proc_privileged",
    },
    "T3-hunger-check": {
        # Unprivileged with SA token + (intentionally overprivileged) role.
        # Only the SA-token / kubelet-API techniques should fire here.
        "k8s_configmap_secrets",
        "k8s_kubelet_api",
        "k8s_node_proxy",
        "k8s_service_account",
    },
    "T4-build-code": {
        "k8s_configmap_secrets",
        "k8s_kubelet_api",
        "k8s_node_proxy",
        "k8s_service_account",
    },
    "T5a-internal-api": {
        "k8s_configmap_secrets",
        "k8s_kubelet_api",
        "k8s_node_proxy",
        "k8s_service_account",
    },
    "T5b-info-app": {
        # Has metadata-db env hint variables — env_secret_leak fires.
        "env_secret_leak",
        "k8s_configmap_secrets",
        "k8s_kubelet_api",
        "k8s_node_proxy",
        "k8s_service_account",
    },
    "T6-poor-registry": {
        "k8s_configmap_secrets",
        "k8s_kubelet_api",
        "k8s_node_proxy",
        "k8s_service_account",
    },
    "T9-metadata-db": {
        "k8s_configmap_secrets",
        "k8s_kubelet_api",
        "k8s_node_proxy",
        "k8s_service_account",
    },
    "T-cache-store": {
        "k8s_configmap_secrets",
        "k8s_kubelet_api",
        "k8s_node_proxy",
        "k8s_service_account",
    },
    "T-goat-home": {
        "k8s_configmap_secrets",
        "k8s_kubelet_api",
        "k8s_node_proxy",
        "k8s_service_account",
    },
}

# Total expected matches across all 10 pods. Sanity check at aggregate level.
TOTAL_EXPECTED_MATCHES = sum(len(s) for s in EXPECTED_MATCHES.values())  # 71

# Technique IDs that must NEVER match any of these postures. These are the
# false positives the v0.3.1 precision overhaul eliminated. If any of these
# appears in a future scan, a prerequisite was loosened too far or a new
# technique was added with insufficient gating.
FORBIDDEN_TECHNIQUES: set[str] = {
    # k8s component-presence FPs (require posture.kubernetes.cluster_components)
    "cve_2025_1974",  # IngressNightmare — no ingress-nginx in this cluster
    "k8s_etcd_access",  # etcd unreachable from these pods
    # BuildKit CVEs (require can_reach_docker_sock)
    "cve_2024_23650",
    "cve_2024_23651",
    "cve_2024_23652",
    "cve_2024_23653",
    "cve_2024_24557",
    # runc CVEs (require detected runtime.runc_version <= vulnerable)
    "runc_cve_2019_5736",
    "cve_2024_21626",
    "cve_2025_31133",
    "cve_2025_52565",
    "cve_2025_52881",
    "containerd_shim_escape",
    # Kernel-version-only matches that should be capped/dropped on WSL2 distro kernels
    "cve_2024_1086",  # nf_tables — backport-patched on WSL2 6.6.x
    "cve_2024_53104",  # USB Video Class — no USB device
    "cve_2025_21756",  # vsock — not present
    "cve_2022_0185",
    "cve_2022_0847",  # older kernel CVEs out of range / patched
    "cve_2021_22555",
    "cve_2022_2588",
    "cve_2023_0386",
    "cve_2023_32233",
    "cve_2021_31440",
    "cve_2022_23222",
    # Vendor-specific that shouldn't fire here
    "cve_2025_3224",
    "docker_desktop_file_share",
    "cve_2025_9074",
    "nvidia_container_toolkit",
    "nvidia_container_device",
}


def _load_posture(name: str) -> ContainerPosture:
    """Load a posture fixture by short name (without -posture.json suffix)."""
    return ContainerPosture.model_validate_json((FIXTURES / f"{name}-posture.json").read_text(encoding="utf-8"))


def _matched_techniques(posture: ContainerPosture) -> set[str]:
    """Return the set of technique IDs that match this posture under the
    default CepheusConfig."""
    result = analyze(posture, CepheusConfig())
    return {step.technique.id for chain in result.chains for step in chain.steps if step.technique is not None}


@pytest.fixture(scope="module", params=sorted(EXPECTED_MATCHES.keys()))
def pod_name(request) -> str:
    return request.param


@pytest.mark.benchmark
def test_per_pod_matched_set_is_exact(pod_name: str) -> None:
    """Each pod must produce EXACTLY its expected matched-technique set.

    Extra matches indicate a precision regression. Missing matches indicate
    a recall regression. Either way, the test diff should be reviewed and
    the EXPECTED_MATCHES set updated only after the change is confirmed
    intentional.
    """
    posture = _load_posture(pod_name)
    actual = _matched_techniques(posture)
    expected = EXPECTED_MATCHES[pod_name]

    extra = actual - expected
    missing = expected - actual
    assert not extra and not missing, (
        f"{pod_name}: matched-technique drift detected.\n"
        f"  +{len(extra)} unexpected: {sorted(extra)}\n"
        f"  -{len(missing)} missing:    {sorted(missing)}\n"
        f"  If intentional, update EXPECTED_MATCHES[{pod_name!r}] in this file."
    )


@pytest.mark.benchmark
def test_no_forbidden_technique_anywhere() -> None:
    """No fixture should ever match any technique in FORBIDDEN_TECHNIQUES.

    These are confirmed false positives from the v0.3.1 precision audit.
    If any of them fires, a prerequisite was loosened (or a new technique
    matches by accident). Reproduce with: cepheus analyze <fixture>.
    """
    violations: dict[str, set[str]] = {}
    for name in EXPECTED_MATCHES:
        actual = _matched_techniques(_load_posture(name))
        bad = actual & FORBIDDEN_TECHNIQUES
        if bad:
            violations[name] = bad
    assert not violations, "FORBIDDEN technique matched in one or more fixtures (precision regression):\n" + "\n".join(
        f"  {pod}: {sorted(techs)}" for pod, techs in violations.items()
    )


@pytest.mark.benchmark
def test_aggregate_precision_and_recall() -> None:
    """Across all 10 fixtures: zero forbidden matches, expected aggregate
    match count. This is a coarser version of the per-pod test that catches
    drift across the suite in one go.
    """
    total_matched = 0
    total_forbidden = 0
    for name in EXPECTED_MATCHES:
        actual = _matched_techniques(_load_posture(name))
        total_matched += len(actual)
        total_forbidden += len(actual & FORBIDDEN_TECHNIQUES)
    assert total_forbidden == 0, f"{total_forbidden} forbidden matches across the suite"
    assert total_matched == TOTAL_EXPECTED_MATCHES, (
        f"Total matched={total_matched}, expected={TOTAL_EXPECTED_MATCHES}. "
        f"If a legitimate refinement caused this drift, update the per-pod "
        f"EXPECTED_MATCHES sets and TOTAL_EXPECTED_MATCHES will update with them."
    )


def test_fixtures_present_and_parseable() -> None:
    """Smoke: each expected fixture file exists and parses as a
    ContainerPosture. Not marked benchmark so it runs in the fast suite."""
    for name in EXPECTED_MATCHES:
        path = FIXTURES / f"{name}-posture.json"
        assert path.exists(), f"Missing fixture: {path}"
        # Parsing should not raise:
        posture = _load_posture(name)
        assert posture.hostname, f"{name}: empty hostname in posture"
