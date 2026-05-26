"""Container security posture model — output of the enumerator."""

from __future__ import annotations

from pydantic import BaseModel, Field


class KernelInfo(BaseModel):
    version: str = Field(default="", description="Full kernel version string, e.g. '5.15.0-76-generic'")
    major: int = 0
    minor: int = 0
    patch: int = 0
    is_distro_kernel: bool = Field(
        default=False,
        description=(
            "True when the kernel version string matches a known distro/vendor "
            "build with security backports (WSL2, EKS, AKS, GKE, RHEL, etc.). "
            "Set by the enumerator; consumed by the matcher to downgrade "
            "confidence on kernel-range-only CVE matches."
        ),
    )
    distro_kernel_tag: str | None = Field(
        default=None,
        description=(
            "If is_distro_kernel is True, the specific tag matched "
            "(e.g. 'microsoft-standard-WSL2', 'aws', 'azure', 'gke', 'el8')."
        ),
    )


class CapabilityInfo(BaseModel):
    effective: list[str] = Field(default_factory=list, description="Effective capabilities, e.g. ['CAP_SYS_ADMIN']")
    bounding: list[str] = Field(default_factory=list)
    permitted: list[str] = Field(default_factory=list)


class MountInfo(BaseModel):
    source: str
    destination: str
    fstype: str
    options: list[str] = Field(default_factory=list)


class NamespaceInfo(BaseModel):
    pid: bool = True
    net: bool = True
    mnt: bool = True
    user: bool = True
    uts: bool = True
    ipc: bool = True
    cgroup: bool = True


class SecurityProfile(BaseModel):
    seccomp: str = "disabled"
    apparmor: str | None = None
    selinux: str | None = None


class NetworkInfo(BaseModel):
    interfaces: list[str] = Field(default_factory=list)
    can_reach_metadata: bool = False
    can_reach_docker_sock: bool = False
    can_reach_containerd_sock: bool = False
    can_reach_crio_sock: bool = False
    listening_ports: list[int] = Field(default_factory=list)
    # Component reachability — populated by the enumerator (best-effort TCP probe).
    # Used by techniques that should only fire when the vulnerable component is
    # actually network-reachable from this pod, not merely "the host runs k8s".
    can_reach_etcd: bool | None = Field(
        default=None,
        description="TCP connect to typical etcd ports (2379) succeeds from this pod",
    )
    can_reach_kubelet_api: bool | None = Field(
        default=None,
        description="TCP connect to kubelet API (10250) on node IP succeeds",
    )
    component_reachability: dict[str, bool] = Field(
        default_factory=dict,
        description=(
            "Optional named-component → reachable map. Enumerator probes "
            "well-known cluster components (e.g. 'ingress-nginx-controller' "
            "on its service VIP). Missing key means 'not probed'."
        ),
    )


class CredentialInfo(BaseModel):
    service_account_token: bool = False
    environment_secrets: list[str] = Field(default_factory=list, description="Env var names (not values)")
    cloud_metadata_available: bool = False


class RuntimeInfo(BaseModel):
    runtime: str = "unknown"
    runtime_version: str | None = None
    orchestrator: str | None = None
    privileged: bool = False
    pid_one: str = "unknown"
    runc_version: str | None = None
    sandbox_runtime: str | None = None


class GpuInfo(BaseModel):
    """GPU device information for escape assessment."""

    nvidia_devices: list[str] = Field(default_factory=list)
    nvidia_toolkit_version: str | None = None
    nvidia_driver_version: str | None = None


class KubernetesInfo(BaseModel):
    rbac_permissions: list[str] = Field(default_factory=list)
    pod_security_standard: str | None = None
    has_sidecar: bool = False
    sidecar_type: str | None = None
    node_access_indicators: list[str] = Field(default_factory=list)
    namespace: str | None = None
    pod_name: str | None = None
    node_name: str | None = None
    # Cluster-component inventory — populated by the enumerator when the pod's
    # SA token has list-pods or list-services permission. Empty list means the
    # enumerator couldn't determine; the matcher should treat this as "unknown"
    # (confidence_if_absent=0.3) not "absent" (0.0). See P1 in design doc.
    cluster_components: list[str] = Field(
        default_factory=list,
        description=(
            "Names of detected cluster components (e.g. 'ingress-nginx', "
            "'argocd', 'buildkit', 'harbor'). Populated by enumerator using SA "
            "token to query the K8s API for known component labels/images."
        ),
    )
    cluster_components_probed: bool = Field(
        default=False,
        description=(
            "True if the enumerator successfully queried the K8s API for "
            "components. False means the cluster_components list is "
            "indeterminate (couldn't list); techniques should treat absent "
            "components as 'unknown' rather than 'definitely not present'."
        ),
    )


class ContainerPosture(BaseModel):
    enumeration_version: str = "0.1.0"
    timestamp: str = ""
    hostname: str = ""
    kernel: KernelInfo = Field(default_factory=KernelInfo)
    capabilities: CapabilityInfo = Field(default_factory=CapabilityInfo)
    mounts: list[MountInfo] = Field(default_factory=list)
    namespaces: NamespaceInfo = Field(default_factory=NamespaceInfo)
    security: SecurityProfile = Field(default_factory=SecurityProfile)
    network: NetworkInfo = Field(default_factory=NetworkInfo)
    credentials: CredentialInfo = Field(default_factory=CredentialInfo)
    runtime: RuntimeInfo = Field(default_factory=RuntimeInfo)
    gpu: GpuInfo = Field(default_factory=GpuInfo)
    kubernetes: KubernetesInfo = Field(default_factory=KubernetesInfo)
    cgroup_version: int = 1
    writable_paths: list[str] = Field(default_factory=list)
    available_tools: list[str] = Field(default_factory=list)
