"""Tests for cepheus.importers.podspec — PodSpec → ContainerPosture."""

from __future__ import annotations

from cepheus.importers.podspec import (
    _ALL_CAPABILITIES,
    _DOCKER_DEFAULT_CAPABILITIES,
    _parse_kernel_version,
    posture_from_podspec,
)


# --- capability extraction ------------------------------------------


def test_no_security_context_yields_default_docker_caps():
    spec = {"containers": [{"name": "app"}]}
    p = posture_from_podspec(spec)
    assert set(p.capabilities.effective) == set(_DOCKER_DEFAULT_CAPABILITIES)
    assert not p.runtime.privileged


def test_privileged_container_grants_all_caps():
    spec = {"containers": [{"name": "app", "securityContext": {"privileged": True}}]}
    p = posture_from_podspec(spec)
    assert set(p.capabilities.effective) == set(_ALL_CAPABILITIES)
    assert p.runtime.privileged


def test_drop_all_clears_default_set():
    spec = {
        "containers": [
            {"name": "app", "securityContext": {"capabilities": {"drop": ["ALL"]}}},
        ]
    }
    p = posture_from_podspec(spec)
    assert p.capabilities.effective == []


def test_add_sys_admin_to_default_set():
    spec = {
        "containers": [
            {"name": "app", "securityContext": {"capabilities": {"add": ["SYS_ADMIN"]}}},
        ]
    }
    p = posture_from_podspec(spec)
    assert "CAP_SYS_ADMIN" in p.capabilities.effective


def test_normalize_cap_prefix():
    """Pod manifests accept both `SYS_ADMIN` and `CAP_SYS_ADMIN`;
    importer normalizes to the `CAP_` prefix."""
    spec_no_prefix = {
        "containers": [{"name": "a", "securityContext": {"capabilities": {"add": ["SYS_PTRACE"]}}}],
    }
    spec_prefix = {
        "containers": [{"name": "a", "securityContext": {"capabilities": {"add": ["CAP_SYS_PTRACE"]}}}],
    }
    p1 = posture_from_podspec(spec_no_prefix)
    p2 = posture_from_podspec(spec_prefix)
    assert "CAP_SYS_PTRACE" in p1.capabilities.effective
    assert p1.capabilities.effective == p2.capabilities.effective


def test_multi_container_union_caps():
    """A pod with two containers — one with CAP_NET_ADMIN, one with
    CAP_SYS_PTRACE — should expose BOTH at the pod level. Either
    container being compromised gets you both caps' worth of
    primitives, so the analyzer must see the union."""
    spec = {
        "containers": [
            {"name": "a", "securityContext": {"capabilities": {"add": ["NET_ADMIN"]}}},
            {"name": "b", "securityContext": {"capabilities": {"add": ["SYS_PTRACE"]}}},
        ],
    }
    p = posture_from_podspec(spec)
    assert "CAP_NET_ADMIN" in p.capabilities.effective
    assert "CAP_SYS_PTRACE" in p.capabilities.effective


def test_init_container_contributes_caps():
    """initContainers run before the main containers; their caps
    matter for posture evaluation just as much."""
    spec = {
        "initContainers": [
            {"name": "init", "securityContext": {"capabilities": {"add": ["SYS_ADMIN"]}}},
        ],
        "containers": [{"name": "app"}],
    }
    p = posture_from_podspec(spec)
    assert "CAP_SYS_ADMIN" in p.capabilities.effective


def test_any_privileged_container_marks_pod_privileged():
    """A pod with one sidecar declared privileged is a privileged pod —
    namespace sharing means everything else inherits the surface."""
    spec = {
        "containers": [
            {"name": "app"},
            {"name": "sidecar", "securityContext": {"privileged": True}},
        ],
    }
    p = posture_from_podspec(spec)
    assert p.runtime.privileged


# --- namespace flags ------------------------------------------------


def test_default_namespaces_are_private():
    """No hostX flags → all namespaces private (Kubernetes default)."""
    p = posture_from_podspec({"containers": [{"name": "a"}]})
    assert p.namespaces.pid
    assert p.namespaces.net
    assert p.namespaces.ipc


def test_hostpid_inverts_pid_namespace_flag():
    """hostPID=true means SHARED with host → NamespaceInfo.pid=False
    (private=False = shared)."""
    p = posture_from_podspec({"hostPID": True, "containers": [{"name": "a"}]})
    assert not p.namespaces.pid


def test_hostnetwork_inverts_net_namespace():
    p = posture_from_podspec({"hostNetwork": True, "containers": [{"name": "a"}]})
    assert not p.namespaces.net


def test_hostipc_inverts_ipc_namespace():
    p = posture_from_podspec({"hostIPC": True, "containers": [{"name": "a"}]})
    assert not p.namespaces.ipc


# --- hostPath mounts ------------------------------------------------


def test_hostpath_root_appears_as_mount_and_writable():
    spec = {
        "containers": [
            {
                "name": "app",
                "volumeMounts": [{"name": "host", "mountPath": "/host"}],
            }
        ],
        "volumes": [{"name": "host", "hostPath": {"path": "/"}}],
    }
    p = posture_from_podspec(spec)
    assert any(m.source == "/" and m.destination == "/host" for m in p.mounts)
    assert "/host" in p.writable_paths
    # Host-side path also exposed so techniques keyed on `/host/etc`
    # match against the actual mount root.
    assert "/" in p.writable_paths


def test_hostpath_readonly_does_not_appear_in_writable():
    spec = {
        "containers": [
            {
                "name": "app",
                "volumeMounts": [{"name": "host", "mountPath": "/host", "readOnly": True}],
            }
        ],
        "volumes": [{"name": "host", "hostPath": {"path": "/"}}],
    }
    p = posture_from_podspec(spec)
    assert p.writable_paths == []
    # The mount itself is still recorded (with ro option).
    assert any("ro" in m.options for m in p.mounts)


def test_emptydir_volumes_are_ignored():
    """Only hostPath mounts can produce escape primitives; emptyDir /
    configMap / secret mounts contribute zero attack surface."""
    spec = {
        "containers": [
            {
                "name": "app",
                "volumeMounts": [{"name": "tmp", "mountPath": "/tmp"}],
            }
        ],
        "volumes": [{"name": "tmp", "emptyDir": {}}],
    }
    p = posture_from_podspec(spec)
    assert p.mounts == []
    assert p.writable_paths == []


def test_docker_sock_hostpath_sets_can_reach_docker_sock():
    spec = {
        "containers": [{"name": "app", "volumeMounts": [{"name": "d", "mountPath": "/var/run/docker.sock"}]}],
        "volumes": [{"name": "d", "hostPath": {"path": "/var/run/docker.sock"}}],
    }
    p = posture_from_podspec(spec)
    assert p.network.can_reach_docker_sock


def test_containerd_sock_hostpath_sets_can_reach_containerd_sock():
    spec = {
        "containers": [
            {"name": "app", "volumeMounts": [{"name": "c", "mountPath": "/run/containerd/containerd.sock"}]}
        ],
        "volumes": [{"name": "c", "hostPath": {"path": "/run/containerd/containerd.sock"}}],
    }
    p = posture_from_podspec(spec)
    assert p.network.can_reach_containerd_sock


# --- service account token -----------------------------------------


def test_sa_token_default_is_mounted():
    """Kubernetes default behaviour: SA token IS mounted unless
    automountServiceAccountToken is explicitly false."""
    p = posture_from_podspec({"containers": [{"name": "a"}]})
    assert p.credentials.service_account_token


def test_automount_false_disables_sa_token():
    spec = {"automountServiceAccountToken": False, "containers": [{"name": "a"}]}
    p = posture_from_podspec(spec)
    assert not p.credentials.service_account_token


# --- runtimeClass + sandbox detection ------------------------------


def test_runtimeclass_gvisor_detected_as_sandbox():
    spec = {"runtimeClassName": "gvisor", "containers": [{"name": "a"}]}
    p = posture_from_podspec(spec)
    assert p.runtime.sandbox_runtime == "gvisor"


def test_runtimeclass_kata_detected_as_sandbox():
    spec = {"runtimeClassName": "kata-clh", "containers": [{"name": "a"}]}
    p = posture_from_podspec(spec)
    assert p.runtime.sandbox_runtime == "kata"


def test_runtimeclass_unknown_yields_no_sandbox():
    spec = {"runtimeClassName": "custom-runtime", "containers": [{"name": "a"}]}
    p = posture_from_podspec(spec)
    assert p.runtime.sandbox_runtime is None


# --- analyzer integration ------------------------------------------


def test_privileged_pod_with_hostpath_root_produces_critical_chains():
    """End-to-end: privileged + hostPath:/ should match many critical
    primitives. This is the canonical 'block-this-pod' admission case."""
    from cepheus.config import CepheusConfig
    from cepheus.engine.analyzer import analyze

    spec = {
        "containers": [
            {
                "name": "app",
                "securityContext": {"privileged": True},
                "volumeMounts": [{"name": "host", "mountPath": "/host"}],
            }
        ],
        "volumes": [{"name": "host", "hostPath": {"path": "/"}}],
        "hostPID": True,
    }
    posture = posture_from_podspec(spec, namespace="default", pod_name="evil-pod")
    result = analyze(posture, CepheusConfig())
    criticals = [c for c in result.chains if c.severity.value == "critical"]
    # At least: hostpath_mount_root, privileged_docker_sock (if sock
    # in mounts — not here), writable_proc_privileged, cap_sys_admin_* family.
    assert len(criticals) >= 3, f"expected >=3 criticals, got {len(criticals)}"


def test_minimal_hardened_pod_produces_no_evaluable_criticals():
    """End-to-end: drop ALL caps, no hostPath, no host-namespaces, no SA
    token, hardened seccomp → should have zero evaluable criticals
    (kernel CVEs may still fire but the admission server filters those)."""
    from cepheus.config import CepheusConfig
    from cepheus.engine.analyzer import analyze
    from cepheus.models.technique import TechniqueCategory

    spec = {
        "containers": [
            {
                "name": "app",
                "securityContext": {
                    "privileged": False,
                    "capabilities": {"drop": ["ALL"]},
                    "readOnlyRootFilesystem": True,
                },
            }
        ],
        "automountServiceAccountToken": False,
    }
    posture = posture_from_podspec(spec)
    result = analyze(posture, CepheusConfig())
    # Filter to non-kernel chains (what the admission server gates on).
    evaluable_criticals = [
        c
        for c in result.chains
        if c.severity.value == "critical"
        and all(s.technique.category != TechniqueCategory.KERNEL for s in c.steps if s.technique)
    ]
    assert evaluable_criticals == [], (
        f"hardened pod should have zero evaluable criticals; got "
        f"{[c.steps[0].technique.id for c in evaluable_criticals]}"
    )


# --- kernel_version kwarg ------------------------------------------


def test_kernel_version_omitted_yields_empty_kernel_info():
    """Default behaviour — caller doesn't have node kernel context."""
    p = posture_from_podspec({"containers": [{"name": "app"}]})
    assert p.kernel.version == ""
    assert p.kernel.major == 0
    assert p.kernel.minor == 0
    assert p.kernel.patch == 0


def test_kernel_version_populates_kernel_info():
    """When the admission webhook resolves a Node's kernel, the
    importer must propagate it into posture.kernel so the matcher's
    kernel_gte / kernel_lte prereqs have a value to compare against."""
    p = posture_from_podspec(
        {"containers": [{"name": "app"}]},
        kernel_version="5.15.0-76-generic",
    )
    assert p.kernel.version == "5.15.0-76-generic"
    assert p.kernel.major == 5
    assert p.kernel.minor == 15
    assert p.kernel.patch == 0


def test_parse_kernel_version_handles_realistic_strings():
    """Spot-check the parser against the kernel-version formats we see
    in the wild across Ubuntu, Debian, WSL2, Amazon Linux, GKE."""
    assert _parse_kernel_version("5.15.0-76-generic") == (5, 15, 0)
    assert _parse_kernel_version("6.1.0-13-amd64") == (6, 1, 0)
    assert _parse_kernel_version("5.15.146.1-microsoft-standard-WSL2") == (5, 15, 146)
    assert _parse_kernel_version("5.10.205-195.804.amzn2.x86_64") == (5, 10, 205)
    assert _parse_kernel_version("6.6.13-gke.1100000") == (6, 6, 13)


def test_parse_kernel_version_handles_malformed_strings():
    """A garbage kernel string degrades to (0, 0, 0) so the matcher's
    kernel_gte/kernel_lte checks return a definitive miss instead of
    crashing on a malformed version."""
    assert _parse_kernel_version("") == (0, 0, 0)
    assert _parse_kernel_version("not-a-version") == (0, 0, 0)
    assert _parse_kernel_version("5.x.0") == (5, 0, 0)


def test_empty_string_kernel_version_raises():
    """An empty string is a programming bug at the call site — pass
    ``None`` for "unknown". Silently treating "" like None would let a
    future cache-layer refactor that forgets to filter empties
    silently disable kernel-CVE gating without any signal."""
    import pytest

    with pytest.raises(ValueError, match="empty string"):
        posture_from_podspec({"containers": [{"name": "app"}]}, kernel_version="")
