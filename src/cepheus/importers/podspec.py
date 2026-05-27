"""PodSpec → ContainerPosture transformer.

Converts a Kubernetes PodSpec dict (as it appears in an AdmissionReview
request, or as parsed from `kubectl get pod -o json`) into a synthetic
``ContainerPosture`` so the rest of the Cepheus analyzer pipeline can
reason about the pod at apply time.

Important: not every posture field is knowable from a PodSpec. Kernel
version, actual runtime, runc version, /proc reachability, namespace
inode comparison, etc. are all *runtime* facts that only the enumerator
script can collect from inside a running container. Those fields stay
at their model defaults so the analyzer treats them as "unknown" rather
than "explicitly absent" — the matcher already handles this via the
``confidence_if_absent`` prerequisite mechanism.

This means the admission-time posture has lower fidelity than a
runtime-enumerated posture: kernel-CVE techniques won't fire (no kernel
version), but capability / mount / namespace / SA-token / runtimeClass
techniques will, which is the bulk of what admission control needs to
catch anyway. The admission webhook's gate decision is therefore
PodSpec-evaluable techniques only.
"""

from __future__ import annotations

from typing import Any

from cepheus.models.posture import (
    CapabilityInfo,
    ContainerPosture,
    CredentialInfo,
    KubernetesInfo,
    MountInfo,
    NamespaceInfo,
    NetworkInfo,
    RuntimeInfo,
    SecurityProfile,
)

# Linux capabilities Docker grants by default (per
# https://docs.docker.com/engine/security/#linux-kernel-capabilities).
# Used when a container has no securityContext.capabilities block, since
# the kernel will give the container these caps at runtime.
_DOCKER_DEFAULT_CAPABILITIES = frozenset(
    {
        "CAP_AUDIT_WRITE",
        "CAP_CHOWN",
        "CAP_DAC_OVERRIDE",
        "CAP_FOWNER",
        "CAP_FSETID",
        "CAP_KILL",
        "CAP_MKNOD",
        "CAP_NET_BIND_SERVICE",
        "CAP_NET_RAW",
        "CAP_SETFCAP",
        "CAP_SETGID",
        "CAP_SETPCAP",
        "CAP_SETUID",
        "CAP_SYS_CHROOT",
    }
)

# The full set of Linux capabilities — what a `privileged: true` container
# effectively holds. Used when the PodSpec sets privileged on any
# container (the container CapEff really is all-ones at runtime).
_ALL_CAPABILITIES = frozenset(
    {
        "CAP_AUDIT_CONTROL",
        "CAP_AUDIT_READ",
        "CAP_AUDIT_WRITE",
        "CAP_BLOCK_SUSPEND",
        "CAP_BPF",
        "CAP_CHECKPOINT_RESTORE",
        "CAP_CHOWN",
        "CAP_DAC_OVERRIDE",
        "CAP_DAC_READ_SEARCH",
        "CAP_FOWNER",
        "CAP_FSETID",
        "CAP_IPC_LOCK",
        "CAP_IPC_OWNER",
        "CAP_KILL",
        "CAP_LEASE",
        "CAP_LINUX_IMMUTABLE",
        "CAP_MAC_ADMIN",
        "CAP_MAC_OVERRIDE",
        "CAP_MKNOD",
        "CAP_NET_ADMIN",
        "CAP_NET_BIND_SERVICE",
        "CAP_NET_BROADCAST",
        "CAP_NET_RAW",
        "CAP_PERFMON",
        "CAP_SETFCAP",
        "CAP_SETGID",
        "CAP_SETPCAP",
        "CAP_SETUID",
        "CAP_SYS_ADMIN",
        "CAP_SYS_BOOT",
        "CAP_SYS_CHROOT",
        "CAP_SYS_MODULE",
        "CAP_SYS_NICE",
        "CAP_SYS_PACCT",
        "CAP_SYS_PTRACE",
        "CAP_SYS_RAWIO",
        "CAP_SYS_RESOURCE",
        "CAP_SYS_TIME",
        "CAP_SYS_TTY_CONFIG",
        "CAP_SYSLOG",
        "CAP_WAKE_ALARM",
    }
)


def _normalize_cap(name: str) -> str:
    """Pod securityContext caps come in as either `SYS_ADMIN` or
    `CAP_SYS_ADMIN`. Normalize to the `CAP_` prefix used throughout
    the technique database."""
    n = name.strip().upper()
    return n if n.startswith("CAP_") else f"CAP_{n}"


def _effective_capabilities(container: dict, privileged: bool) -> list[str]:
    """Compute the effective capability set for one container.

    Order of operations matches Kubernetes' actual runtime semantics:
      1. privileged=true => all Linux caps (overrides everything).
      2. Otherwise: start from the Docker default set.
      3. Drop caps in securityContext.capabilities.drop (`ALL` is a
         valid value that clears the set).
      4. Add caps in securityContext.capabilities.add.
    """
    if privileged:
        return sorted(_ALL_CAPABILITIES)

    sec_ctx = container.get("securityContext") or {}
    caps_block = sec_ctx.get("capabilities") or {}
    drops = {_normalize_cap(c) for c in (caps_block.get("drop") or [])}
    adds = {_normalize_cap(c) for c in (caps_block.get("add") or [])}

    if "CAP_ALL" in drops:
        effective: set[str] = set()
    else:
        effective = set(_DOCKER_DEFAULT_CAPABILITIES) - drops
    effective |= adds
    return sorted(effective)


def _container_is_privileged(container: dict) -> bool:
    """A container is privileged if EITHER its securityContext.privileged
    is True OR (less common) it has hostPath mounts to /var/run/docker.sock
    while running as root — the latter is detected by the analyzer chain,
    not here."""
    sec_ctx = container.get("securityContext") or {}
    return bool(sec_ctx.get("privileged"))


def _hostpath_volumes(spec: dict) -> list[dict]:
    """Extract hostPath volume definitions, keyed by volume name.

    Returns a list of {name, hostPath: str, readOnly: bool} dicts —
    not every PodSpec uses hostPath, so this may be empty.
    """
    out = []
    for vol in spec.get("volumes") or []:
        host = vol.get("hostPath")
        if host:
            out.append(
                {
                    "name": vol.get("name", ""),
                    "hostPath": host.get("path", ""),
                    "type": host.get("type", ""),
                }
            )
    return out


def _mounts_from_volume_mounts(container: dict, hostpath_volumes: list[dict]) -> tuple[list[MountInfo], list[str]]:
    """Map a container's volumeMounts to MountInfo + writable_paths
    entries, but ONLY for hostPath mounts (the others are emptyDir /
    configMap / secret which the analyzer doesn't gate on)."""
    hp_by_name = {h["name"]: h for h in hostpath_volumes}
    mounts: list[MountInfo] = []
    writable: list[str] = []
    for vm in container.get("volumeMounts") or []:
        name = vm.get("name")
        if not name or name not in hp_by_name:
            continue
        hp = hp_by_name[name]
        mount_path = vm.get("mountPath", "")
        read_only = bool(vm.get("readOnly"))
        mounts.append(
            MountInfo(
                source=hp["hostPath"],
                destination=mount_path,
                fstype="bind",
                options=["ro"] if read_only else ["rw"],
            )
        )
        if not read_only and mount_path:
            writable.append(mount_path)
            # Also expose the host-path side so techniques that key on
            # /host/etc, /host, etc. fire when the pod maps host root
            # under a non-/host mountPath.
            if hp["hostPath"]:
                writable.append(hp["hostPath"])
    return mounts, writable


def _can_reach_docker_sock(hostpath_volumes: list[dict]) -> bool:
    """Pod-level: is a docker socket bind-mounted into the pod?
    Detected by hostPath sources of /var/run/docker.sock or paths under
    /var/run/docker.* — covers the common misconfig patterns."""
    for hp in hostpath_volumes:
        p = (hp.get("hostPath") or "").rstrip("/")
        if p in ("/var/run/docker.sock", "/run/docker.sock"):
            return True
        if p.startswith("/var/run/docker") or p.startswith("/run/docker"):
            return True
    return False


def _can_reach_containerd_sock(hostpath_volumes: list[dict]) -> bool:
    for hp in hostpath_volumes:
        p = (hp.get("hostPath") or "").rstrip("/")
        if p in ("/run/containerd/containerd.sock", "/var/run/containerd/containerd.sock"):
            return True
    return False


def _can_reach_crio_sock(hostpath_volumes: list[dict]) -> bool:
    for hp in hostpath_volumes:
        p = (hp.get("hostPath") or "").rstrip("/")
        if p in ("/var/run/crio/crio.sock", "/run/crio/crio.sock"):
            return True
    return False


def _detect_sandbox_runtime(spec: dict) -> str | None:
    """RuntimeClassName indicates a non-default runtime. Known sandbox
    runtimes: gvisor, kata, firecracker. Anything else is treated as
    "unknown" (returns None) — the matcher won't apply the sandbox
    mitigation factor."""
    rcn = (spec.get("runtimeClassName") or "").lower()
    if not rcn:
        return None
    if "gvisor" in rcn or "runsc" in rcn:
        return "gvisor"
    if "kata" in rcn:
        return "kata"
    if "firecracker" in rcn or "firekube" in rcn:
        return "firecracker"
    return None


def posture_from_podspec(
    spec: dict[str, Any],
    *,
    namespace: str | None = None,
    pod_name: str | None = None,
) -> ContainerPosture:
    """Build a synthetic ContainerPosture from a PodSpec dict.

    For multi-container pods the returned posture represents the UNION
    of all containers' security surfaces — any container being
    privileged makes the pod's posture privileged, any container's
    caps land in the effective set, etc. This is the right model for
    admission control because a single misconfigured sidecar
    compromises the whole pod's namespace.

    Args:
        spec: The PodSpec dict, e.g. AdmissionReview's
            ``request.object.spec`` or ``kubectl get pod -o json``'s
            ``spec`` field.
        namespace: Optional Kubernetes namespace (recorded in
            ``KubernetesInfo``; not used by gates).
        pod_name: Optional pod name (recorded; not used by gates).

    Returns:
        A populated ``ContainerPosture`` with the fields the PodSpec
        knows about. Runtime-only fields (kernel.version,
        runtime.runc_version, etc.) stay at model defaults so the
        analyzer's ``confidence_if_absent`` logic handles them as
        unknown rather than explicitly absent.
    """
    containers = (spec.get("containers") or []) + (spec.get("initContainers") or [])

    any_privileged = any(_container_is_privileged(c) for c in containers)
    union_caps: set[str] = set()
    for c in containers:
        union_caps.update(_effective_capabilities(c, _container_is_privileged(c)))

    hostpath_vols = _hostpath_volumes(spec)

    all_mounts: list[MountInfo] = []
    all_writable: set[str] = set()
    for c in containers:
        mnts, wr = _mounts_from_volume_mounts(c, hostpath_vols)
        all_mounts.extend(mnts)
        all_writable.update(wr)

    # PodSpec-level boolean fields. The Kubernetes default is False
    # for all three — the absence of the field means "private namespace".
    host_pid = bool(spec.get("hostPID"))
    host_ipc = bool(spec.get("hostIPC"))
    host_network = bool(spec.get("hostNetwork"))

    # SA token: by default, ServiceAccount tokens are mounted into
    # containers. Only an explicit `automountServiceAccountToken: false`
    # disables it (or the ServiceAccount itself opting out, which we
    # can't see from the PodSpec alone — assume worst case).
    automount = spec.get("automountServiceAccountToken")
    has_sa_token = automount is not False  # None / True / missing → True

    sandbox = _detect_sandbox_runtime(spec)

    return ContainerPosture(
        enumeration_version="podspec-importer-0.5.0",
        hostname=pod_name or "",
        # kernel: defaults to empty KernelInfo — no kernel version
        # available pre-runtime. Kernel-CVE techniques will gracefully
        # drop because their version-range prereqs can't match.
        capabilities=CapabilityInfo(
            effective=sorted(union_caps),
            bounding=sorted(union_caps),
            permitted=sorted(union_caps),
        ),
        mounts=all_mounts,
        # Namespaces: in Kubernetes, hostX=true means SHARED with the
        # host (NamespaceInfo.X=False means "shared"). Default False
        # for the host flags maps to NamespaceInfo defaults of True
        # (private).
        namespaces=NamespaceInfo(
            pid=not host_pid,
            ipc=not host_ipc,
            net=not host_network,
        ),
        security=SecurityProfile(
            # Default Kubernetes seccomp is RuntimeDefault on >= 1.27
            # if PodSecurityStandard "baseline" is enforced; we can't
            # know without the cluster's PSS config, so default to
            # "filtering" (the safer assumption — better to miss a
            # finding than over-report).
            seccomp="filtering",
            # AppArmor profile is set via annotation; reading it would
            # require the full Pod object (not just PodSpec). Leave
            # as None (unconfined) which is the worst case.
            apparmor=None,
        ),
        network=NetworkInfo(
            can_reach_docker_sock=_can_reach_docker_sock(hostpath_vols),
            can_reach_containerd_sock=_can_reach_containerd_sock(hostpath_vols),
            can_reach_crio_sock=_can_reach_crio_sock(hostpath_vols),
        ),
        credentials=CredentialInfo(
            service_account_token=has_sa_token,
        ),
        runtime=RuntimeInfo(
            # We don't know the actual runtime from the PodSpec — leave
            # at "unknown" so runtime-specific CVE techniques degrade
            # to their confidence_if_absent rather than firing
            # spuriously.
            runtime="unknown",
            orchestrator="kubernetes",
            privileged=any_privileged,
            sandbox_runtime=sandbox,
        ),
        kubernetes=KubernetesInfo(
            namespace=namespace,
            pod_name=pod_name,
        ),
        writable_paths=sorted(all_writable),
    )
