"""Container security posture model — output of the enumerator."""

from __future__ import annotations

from pydantic import BaseModel, Field


class KernelInfo(BaseModel):
    version: str = Field(default="", description="Full kernel version string, e.g. '5.15.0-76-generic'")
    major: int = 0
    minor: int = 0
    patch: int = 0


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
    listening_ports: list[int] = Field(default_factory=list)


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
    cgroup_version: int = 1
    writable_paths: list[str] = Field(default_factory=list)
    available_tools: list[str] = Field(default_factory=list)
