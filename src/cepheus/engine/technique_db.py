"""Complete database of 65 container escape techniques."""

from __future__ import annotations

import copy
import threading

from cepheus.models.technique import (
    EscapeTechnique,
    Prerequisite,
    Severity,
    TechniqueCategory,
)

_TECHNIQUES: list[EscapeTechnique] | None = None
# Guards the lazy build below. Created at import time (never lazily) so the
# lock itself can't race. The threaded admission server and the fleet
# ThreadPoolExecutor can both hit a cold cache concurrently.
_TECHNIQUES_LOCK = threading.Lock()

# Compliance crosswalk — control IDs from CIS Kubernetes Benchmark,
# NIST SP 800-190, and PCI DSS v4 that each technique violates or
# undermines. Maintained as a single side-car dict rather than
# inline-on-each-technique so the technique definitions stay readable
# and so the compliance mapping has one source of truth that's easy
# to audit + extend. Techniques absent from this map carry empty lists,
# which means "not yet enumerated" not "no applicable control".
#
# CIS Kubernetes Benchmark IDs reference v1.10 (2024). NIST 800-190
# IDs reference the 2017 publication's section numbers, which remain
# the canonical mapping until 800-190r1 publishes. PCI DSS IDs
# reference v4.0.1.
_COMPLIANCE_CROSSWALK: dict[str, dict[str, list[str]]] = {
    "cap_sys_admin_mount": {
        "cis": ["5.2.1", "5.2.6", "5.2.8"],
        "nist": ["4.2.4", "4.2.5"],
        "pci": ["2.2.5", "7.2.1"],
    },
    "cap_sys_admin_cgroup_escape": {
        "cis": ["5.2.1", "5.2.6"],
        "nist": ["4.2.4", "4.2.5"],
        "pci": ["2.2.5"],
    },
    "cap_sys_admin_bpf": {"cis": ["5.2.1"], "nist": ["4.2.5"], "pci": ["2.2.5"]},
    "cap_sys_ptrace": {"cis": ["5.2.8"], "nist": ["4.2.4"], "pci": ["2.2.5"]},
    "cap_dac_read_search": {"cis": ["5.2.8"], "nist": ["4.2.4"], "pci": ["2.2.5"]},
    "cap_dac_override": {"cis": ["5.2.8"], "nist": ["4.2.4"], "pci": ["2.2.5"]},
    "cap_net_admin": {"cis": ["5.2.8"], "nist": ["4.2.4"], "pci": ["1.2.1"]},
    "cap_sys_rawio": {"cis": ["5.2.8"], "nist": ["4.2.4"], "pci": ["2.2.5"]},
    "docker_socket_mount": {
        "cis": ["5.1.5", "5.2.6"],
        "nist": ["4.5.1", "4.5.2"],
        "pci": ["6.4.1"],
    },
    "containerd_sock_mount": {"cis": ["5.1.5", "5.2.6"], "nist": ["4.5.1"], "pci": ["6.4.1"]},
    "crio_sock_mount": {"cis": ["5.1.5", "5.2.6"], "nist": ["4.5.1"], "pci": ["6.4.1"]},
    "hostpath_mount_root": {
        "cis": ["5.2.10", "5.7.2"],
        "nist": ["4.2.2", "4.5.4"],
        "pci": ["2.2.5"],
    },
    "hostpath_mount_etc": {"cis": ["5.2.10", "5.7.2"], "nist": ["4.2.2"], "pci": ["2.2.5"]},
    "procfs_sysrq": {"cis": ["5.2.10"], "nist": ["4.2.2"], "pci": ["2.2.5"]},
    "procfs_core_pattern": {"cis": ["5.2.10"], "nist": ["4.2.2"], "pci": ["2.2.5"]},
    "k8s_service_account": {
        "cis": ["5.1.5", "5.1.6"],
        "nist": ["4.5.2"],
        "pci": ["7.2.1", "8.2.1"],
    },
    "k8s_configmap_secrets": {
        "cis": ["5.4.1", "5.4.2"],
        "nist": ["4.3.5"],
        "pci": ["3.5.1", "8.6.1"],
    },
    "env_secret_leak": {
        "cis": ["5.4.1"],
        "nist": ["4.3.5"],
        "pci": ["3.5.1", "8.6.1"],
    },
    "cloud_metadata_ssrf": {
        "cis": ["5.7.4"],
        "nist": ["4.5.5"],
        "pci": ["1.3.1"],
    },
    "lsm_apparmor_unconfined": {"cis": ["5.7.2"], "nist": ["4.2.1"], "pci": ["2.2.5"]},
    "lsm_selinux_unconfined": {"cis": ["5.7.2"], "nist": ["4.2.1"], "pci": ["2.2.5"]},
    "cap_sys_admin_no_seccomp": {"cis": ["5.7.2"], "nist": ["4.2.1"], "pci": ["2.2.5"]},
    # Mount / device / cgroup escape families.
    "cgroupfs_escape": {"cis": ["5.2.1", "5.2.6"], "nist": ["4.2.4", "4.2.5"], "pci": ["2.2.5"]},
    "systemd_cgroup_injection": {"cis": ["5.2.1", "5.2.6"], "nist": ["4.2.4"], "pci": ["2.2.5"]},
    "devfs_access": {"cis": ["5.2.10"], "nist": ["4.2.2"], "pci": ["2.2.5"]},
    "device_mapper_access": {"cis": ["5.2.10"], "nist": ["4.2.2"], "pci": ["2.2.5"]},
    "sysfs_hugepages": {"cis": ["5.2.10"], "nist": ["4.2.2"], "pci": ["2.2.5"]},
    "tmpfs_shm_cross_container": {"cis": ["5.2.10"], "nist": ["4.2.2"], "pci": ["2.2.5"]},
    "vm_param_manipulation": {"cis": ["5.2.10"], "nist": ["4.2.2"], "pci": ["2.2.5"]},
    "proc_fd_symlink_traversal": {"cis": ["5.2.10"], "nist": ["4.2.2", "4.3.5"], "pci": ["2.2.5"]},
    # Capability / eBPF family.
    "ebpf_probe_write_user": {"cis": ["5.2.1"], "nist": ["4.2.5"], "pci": ["2.2.5"]},
}


# Per-technique impact — the consequence an attacker achieves if the
# technique succeeds (end-state / blast radius), in one line. Kept as a
# side-car keyed by technique id (same rationale as _COMPLIANCE_CROSSWALK)
# so the technique definitions stay readable. A technique absent from this
# map keeps impact="" and SARIF/UI consumers fall back to a
# severity+category-derived statement (see output/sarif.py), so the field
# is never blank.
_IMPACT: dict[str, str] = {
    # ── CAPABILITY ──
    "cap_sys_admin_mount": "Read/write access to the entire host filesystem, leading to full node compromise.",
    "cap_sys_admin_cgroup_escape": "Arbitrary command execution as root on the host via the cgroup release_agent.",
    "cap_sys_admin_bpf": "Arbitrary kernel memory read/write, escalating to root code execution on the host.",
    "cap_sys_ptrace": "Code injection into host processes, escalating to host-level code execution.",
    "cap_dac_read_search": "Read access to any file on the host, including credentials, keys, and tokens.",
    "cap_dac_override": "Write access to any file on the host, enabling persistence and privilege escalation.",
    "cap_net_admin": "Host network reconfiguration enabling traffic interception and ARP/DNS spoofing.",
    "cap_sys_rawio": "Direct disk and device access bypassing the filesystem, leading to host compromise.",
    "ebpf_probe_write_user": "Kernel-assisted writes to process memory, escalating to host code execution.",
    "cap_sys_module": "Load an arbitrary kernel module for immediate ring-0 code execution on the host.",
    "cap_sys_boot": "Reboot or power off the entire host node from inside the container — host-wide denial of service.",
    "cap_syslog": "Leak kernel pointers (KASLR bypass), turning unreliable kernel exploits into reliable host escapes.",
    "cap_perfmon": "Read kernel/cross-process performance data to leak addresses and memory (KASLR bypass).",
    # ── MOUNT ──
    "docker_socket_mount": "Full control of the Docker daemon — launch a privileged container to own the host.",
    "procfs_core_pattern": "Host command execution as root by hijacking the kernel core-dump handler.",
    "procfs_modprobe_path": "Host command execution as root by hijacking the kernel modprobe helper.",
    "podman_sock_mount": "Full control of the Podman engine — launch a privileged container to own the host.",
    "sysfs_uevent_helper": "Host command execution as root by hijacking the kernel uevent helper.",
    "procfs_sysrq": "Crash or reboot the host kernel — host-wide denial of service.",
    "sysfs_hugepages": "Kernel-parameter tampering via writable sysfs that can destabilize or compromise the host.",
    "hostpath_mount_etc": "Write host /etc (passwd/shadow/cron) to gain persistent root on the node.",
    "hostpath_mount_root": "Unrestricted read/write of the host root filesystem — full node compromise.",
    "cgroupfs_escape": "Host command execution via writable cgroup release_agent abuse.",
    "devfs_access": "Raw read/write of host disks and devices, bypassing all filesystem controls.",
    "containerd_sock_mount": "Direct containerd control — create privileged containers and take over the host.",
    "crio_sock_mount": "Direct CRI-O control — create privileged containers and take over the node.",
    "systemd_cgroup_injection": "Execute an attacker-defined systemd unit as root on the host.",
    "tmpfs_shm_cross_container": "Cross-container data exfiltration via shared writable /dev/shm.",
    "proc_fd_symlink_traversal": "Read/write host files outside the container via /proc/self/fd symlinks.",
    "device_mapper_access": "Block-device remapping that can expose or corrupt host storage.",
    "vm_param_manipulation": "Kernel memory-management tampering that can degrade or destabilize the host.",
    # ── KERNEL (CVE) ──
    "cve_2022_0185": "Kernel heap overflow → container-to-host privilege escalation (root on the node).",
    "cve_2022_0847": "DirtyPipe: overwrite read-only host files → root privilege escalation and container escape.",
    "cve_2021_22555": "Netfilter heap corruption → kernel code execution and root on the host.",
    "cve_2022_2588": "net/sched use-after-free → privilege escalation from container to host root.",
    "cve_2023_0386": "OverlayFS setuid copy-up flaw → local root on the host node.",
    "cve_2023_32233": "nf_tables use-after-free → arbitrary kernel code execution and host root.",
    "cve_2024_1086": "nf_tables double-free → kernel code execution and container escape to host root.",
    "cve_2021_31440": "eBPF verifier flaw → out-of-bounds kernel access and privilege escalation.",
    "cve_2022_23222": "BPF verifier type confusion → arbitrary kernel read/write and escalation.",
    "cve_2024_21626": "runc fd leak (Leaky Vessels) → host filesystem access and container escape to the node.",
    "cve_2024_53104": "UVC driver out-of-bounds write → local privilege escalation on the host.",
    "cve_2025_21756": "vsock use-after-free → kernel code execution and host compromise.",
    "cve_2025_31133": "runc masked-path race → host file access during container start.",
    "cve_2025_52565": "runc /dev/console race → host file write via symlink redirection.",
    "cve_2025_52881": "runc /proc write redirection → host file tampering during container setup.",
    "cve_2024_23651": "BuildKit cache-mount TOCTOU → host access at image-build time.",
    "cve_2024_23652": "BuildKit path traversal → arbitrary host file deletion at build time.",
    "cve_2024_23653": "BuildKit unchecked security.insecure entitlement → privileged build container escapes to host.",
    # ── RUNTIME ──
    "k8s_service_account": "Service-account token abuse against the Kubernetes API enabling lateral movement.",
    "k8s_kubelet_api": "Command execution in any pod on the node via the unauthenticated kubelet API.",
    "k8s_etcd_access": "Direct etcd access exposes all cluster secrets and enables full cluster takeover.",
    "docker_api_unauth": "Unauthenticated Docker API → full control of every container and the host.",
    "containerd_shim_escape": "containerd-shim exploitation → host access via the container runtime.",
    "runc_cve_2019_5736": "Overwrite the host runc binary via /proc/self/exe → code execution on the host.",
    "cloud_metadata_ssrf": "Reachable cloud metadata endpoint → theft of instance IAM credentials.",
    "lsm_apparmor_unconfined": "No AppArmor confinement — removes the MAC layer that blunts escape attempts.",
    "lsm_selinux_unconfined": "SELinux disabled/unconfined — removes the MAC layer that contains escapes.",
    "k8s_node_proxy": "Kubelet proxy abuse to reach other pods and services on the node for lateral movement.",
    "host_pid_namespace": "Visibility and control of all host processes — read their secrets via /proc and signal them.",
    "cve_2025_23266": "NVIDIA Container Toolkit OCI-hook LD_PRELOAD abuse → container escape to the host.",
    "cve_2024_0132": "Malicious image abuses the NVIDIA Container Toolkit → host access.",
    "cve_2024_0133": "Crafted image uses a symlink to make the NVIDIA Container Toolkit write host files → host compromise.",
    "cve_2025_1974": "Unauthenticated RCE in the ingress-nginx admission webhook → cluster compromise.",
    "cve_2025_9074": "Docker Desktop container escape → access to the host from within a container.",
    # ── COMBINATORIAL ──
    "cap_sys_admin_no_seccomp": "Unfiltered CAP_SYS_ADMIN enables mount/cgroup/BPF escapes → root on the host.",
    "privileged_docker_sock": "Privileged container plus Docker socket → near-guaranteed, trivial host takeover.",
    "cap_net_raw_metadata": "ARP spoofing plus metadata access → interception of cloud IAM credentials.",
    "writable_proc_privileged": "Privileged container with writable /proc/sys/kernel → core_pattern host code execution.",
    "user_ns_kernel_exploit": "User namespaces plus a vulnerable kernel → unprivileged-to-host privilege escalation.",
    "cap_sys_admin_apparmor_unconfined": "CAP_SYS_ADMIN without AppArmor confinement → unrestricted host escape.",
    # ── INFO DISCLOSURE ──
    "env_secret_leak": "Exposed credentials in environment variables enabling lateral movement.",
    "cloud_metadata_creds": "Leaked cloud IAM credentials and identity tokens enabling cloud-account compromise.",
    "k8s_configmap_secrets": "Readable Kubernetes secrets and configmaps enabling lateral movement.",
    "docker_env_inspection": "Inspection of other containers' environment variables, leaking their secrets.",
}


def _apply_compliance(techs: list[EscapeTechnique]) -> list[EscapeTechnique]:
    """Merge ``_COMPLIANCE_CROSSWALK`` into the techniques in place.

    Kept as a separate pass over the built list so the inline technique
    definitions don't carry the noisy compliance-id lists — those
    triple the visual weight of every technique constructor and made
    code review of technique-DB changes much harder.
    """
    for t in techs:
        mapping = _COMPLIANCE_CROSSWALK.get(t.id)
        if not mapping:
            continue
        t.cis_kubernetes_benchmark = list(mapping.get("cis", []))
        t.nist_800_190 = list(mapping.get("nist", []))
        t.pci_dss = list(mapping.get("pci", []))
    return techs


def _apply_impact(techs: list[EscapeTechnique]) -> list[EscapeTechnique]:
    """Merge ``_IMPACT`` into the techniques in place.

    Same side-car pattern as ``_apply_compliance`` — keeps the per-technique
    consequence statements in one auditable place instead of bloating every
    technique constructor. Techniques absent from the map keep ``impact=""``;
    SARIF/UI consumers derive a severity+category fallback so the field is
    never blank.
    """
    for t in techs:
        impact = _IMPACT.get(t.id)
        if impact:
            t.impact = impact
    return techs


# Techniques whose ``verify_command`` only proves a PRECONDITION, not the
# exploitable primitive itself. A passing probe here means "the necessary
# condition is present" — NOT "this concrete host is exploitable". The
# confirmation layer downgrades a pass on these from CONFIRMED to POTENTIAL so
# a patched-but-precondition-present host (e.g. a GPU node running a FIXED
# NVIDIA toolkit, or an unpatched-range kernel that's actually backported) is
# never reported as a confirmed escape. A FAIL still refutes — an absent
# precondition means the CVE cannot be exploited here at all.
#
# Rationale per entry:
#   - unshare-based kernel CVEs: `unshare -Ur...` proves user-namespace
#     creation is permitted (the delivery vector) but a PATCHED kernel still
#     permits unshare — so a pass does not prove the bug is present.
#   - DirtyPipe: the verifier is a uname version-range check — opportunistic,
#     identical to the kernel-range static signal, not a primitive proof.
#   - cap-bit CVEs (BPF): a CapEff probe proves the capability is held, not
#     that the kernel's BPF verifier is the vulnerable version.
#   - BuildKit/Docker-Desktop: socket / runtime-marker presence is the
#     precondition (reachable build daemon / Docker Desktop), not the race/
#     version bug.
#   - NVIDIA toolkit CVEs: GPU device presence is the precondition; it says
#     nothing about the toolkit version.
#   - IngressNightmare: DNS resolution proves the admission controller is
#     deployed and reachable, not that it is a vulnerable version.
# Deliberately ABSENT (these verifiers DO prove the primitive, stay CONFIRMED):
#   - cve_2024_21626 (runc leaked fd): readlink finds a live leaked host fd —
#     that IS the exploitable primitive, not merely a precondition.
#   - all misconfig probes (privileged, cap SYS_ADMIN mount, writable
#     docker.sock, hostPath): they exercise the actual operation.
_PRECONDITION_ONLY_VERIFIERS: set[str] = {
    "cve_2022_0185",
    "cve_2021_22555",
    "cve_2022_2588",
    "cve_2023_0386",
    "cve_2023_32233",
    "cve_2024_1086",
    "cve_2022_0847",
    "cve_2022_23222",
    "cve_2024_23651",
    "cve_2024_23652",
    "cve_2025_23266",
    "cve_2024_0132",
    "cve_2024_0133",
    "cve_2025_1974",
    "cve_2025_9074",
    "cve_2024_23653",
}


def _apply_verify_semantics(techs: list[EscapeTechnique]) -> list[EscapeTechnique]:
    """Mark precondition-only verifiers (see ``_PRECONDITION_ONLY_VERIFIERS``).

    Side-car pattern so the classification lives in one auditable place rather
    than a flag scattered across CVE constructors. A defensive guard rejects
    an entry that names a technique with no verifier at all — that's almost
    certainly a typo'd id, and silently ignoring it would let a CVE keep
    over-confirming.
    """
    by_id = {t.id: t for t in techs}
    for tid in _PRECONDITION_ONLY_VERIFIERS:
        t = by_id.get(tid)
        if t is not None and t.verify_command:
            t.verify_confirms_primitive = False
    return techs


def _build_techniques() -> list[EscapeTechnique]:
    """Build and return all 65 escape techniques."""
    techs = _raw_techniques()
    techs = _apply_compliance(techs)
    techs = _apply_impact(techs)
    return _apply_verify_semantics(techs)


def _raw_techniques() -> list[EscapeTechnique]:
    """Pure technique definitions, no compliance crosswalk applied."""
    return [
        # ── CAPABILITY (9) ───────────────────────────────────────────
        EscapeTechnique(
            id="cap_sys_admin_mount",
            name="Mount host filesystem via CAP_SYS_ADMIN",
            category=TechniqueCategory.CAPABILITY,
            severity=Severity.CRITICAL,
            description=(
                "With CAP_SYS_ADMIN the container can mount the host's block "
                "device and gain full read/write access to the host filesystem."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="capabilities.effective",
                    check_type="contains",
                    check_value="CAP_SYS_ADMIN",
                    description="Requires CAP_SYS_ADMIN capability",
                ),
                Prerequisite(
                    check_field="security.seccomp",
                    check_type="not_equals",
                    check_value="strict",
                    description="Seccomp must not be in strict mode",
                ),
            ],
            mitre_attack=["T1611"],
            references=[
                "https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/",
            ],
            reliability=0.9,
            stealth=0.3,
            remediation="--cap-drop=ALL --cap-add=<needed>",
            cli_flag="--cap-drop=SYS_ADMIN",
            verify_command="d=/tmp/_cep_v_$$; mkdir -p $d && mount -t tmpfs -o size=1m tmpfs $d && umount $d && rmdir $d",
        ),
        EscapeTechnique(
            id="cap_sys_admin_cgroup_escape",
            name="cgroup release_agent escape",
            category=TechniqueCategory.CAPABILITY,
            severity=Severity.CRITICAL,
            description=("Abuse cgroup v1 release_agent to execute commands on the host when a cgroup becomes empty."),
            prerequisites=[
                Prerequisite(
                    check_field="capabilities.effective",
                    check_type="contains",
                    check_value="CAP_SYS_ADMIN",
                    description="Requires CAP_SYS_ADMIN capability",
                ),
                Prerequisite(
                    check_field="cgroup_version",
                    check_type="equals",
                    check_value=1,
                    description="Requires cgroup v1",
                ),
            ],
            mitre_attack=["T1611"],
            references=[
                "https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/",
            ],
            reliability=0.85,
            stealth=0.4,
            remediation="Use cgroup v2 or drop CAP_SYS_ADMIN",
            # cgroup v1 release_agent escape requires a writable cgroup
            # tree. Probe writability of any cgroup.procs file — the v1
            # paths under /sys/fs/cgroup/<controller>/cgroup.procs.
            # Non-destructive: tests the open-for-write permission without
            # writing.
            verify_command="for f in /sys/fs/cgroup/memory/cgroup.procs /sys/fs/cgroup/cpu/cgroup.procs /sys/fs/cgroup/devices/cgroup.procs; do exec 3>>$f 2>/dev/null && exec 3>&- && exit 0; done; exit 1",
        ),
        EscapeTechnique(
            id="cap_sys_admin_bpf",
            name="eBPF-based escape",
            category=TechniqueCategory.CAPABILITY,
            severity=Severity.CRITICAL,
            description=(
                "Use CAP_SYS_ADMIN to load eBPF programs that can read/write "
                "arbitrary kernel memory, enabling privilege escalation."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="capabilities.effective",
                    check_type="contains",
                    check_value="CAP_SYS_ADMIN",
                    description="Requires CAP_SYS_ADMIN capability",
                ),
                Prerequisite(
                    check_field="kernel.version",
                    check_type="kernel_gte",
                    check_value="4.18.0",
                    description="eBPF features available from kernel 4.18+",
                ),
            ],
            mitre_attack=["T1611", "T1068"],
            references=[
                "https://www.graplsecurity.com/post/kernel-pwning-with-ebpf-a-love-story",
            ],
            reliability=0.7,
            stealth=0.6,
            remediation="Drop CAP_SYS_ADMIN and CAP_BPF",
            # bpftool prog list requires CAP_BPF (kernel >= 5.8) or
            # CAP_SYS_ADMIN to enumerate loaded BPF programs. Returns 0
            # if the call succeeds (the cap is held); non-zero on EPERM.
            # Falls back to checking /sys/kernel/btf/vmlinux which is
            # root-readable and indicates BPF subsystem availability.
            verify_command="(command -v bpftool >/dev/null 2>&1 && bpftool prog list >/dev/null 2>&1) || [ -r /sys/kernel/btf/vmlinux ]",
        ),
        EscapeTechnique(
            id="cap_sys_ptrace",
            name="Ptrace host processes",
            category=TechniqueCategory.CAPABILITY,
            severity=Severity.HIGH,
            description=(
                "With CAP_SYS_PTRACE and a shared PID namespace, attach to host processes and inject code for escape."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="capabilities.effective",
                    check_type="contains",
                    check_value="CAP_SYS_PTRACE",
                    description="Requires CAP_SYS_PTRACE capability",
                ),
                Prerequisite(
                    check_field="namespaces.pid",
                    check_type="equals",
                    check_value=False,
                    description="PID namespace must be shared with host",
                ),
            ],
            # T1055 (Process Injection) covers the ptrace primitive itself;
            # T1611 (Escape to Host) covers the outcome when the target PID
            # is a host process (hostPID:true). Both apply here.
            mitre_attack=["T1055", "T1611"],
            references=[
                "https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts",
            ],
            reliability=0.8,
            stealth=0.5,
            remediation="--cap-drop=SYS_PTRACE --pid=container",
            cli_flag="--cap-drop=SYS_PTRACE",
            # No verifier: the previous probe (`ps -p 1 -o stat=`) only
            # checked that /proc/1 was readable, which is true in every
            # container regardless of CAP_SYS_PTRACE, so the verifier
            # reported CONFIRMED 100% of the time and defeated the
            # false-positive-reduction purpose of `cepheus verify` for
            # this technique. A real probe would need to call
            # `ptrace(PTRACE_ATTACH, host_pid, ...)` against a host
            # process — only meaningful when hostPID is shared, which
            # the verifier can't determine from inside the container.
            # Set to None so the outcome is NO_VERIFIER (honest) rather
            # than always-CONFIRMED (a silent lie).
            verify_command=None,
        ),
        EscapeTechnique(
            id="cap_dac_read_search",
            name="Read arbitrary host files",
            category=TechniqueCategory.CAPABILITY,
            severity=Severity.HIGH,
            description=(
                "CAP_DAC_READ_SEARCH bypasses file read permission checks "
                "and directory read/execute checks, allowing access to any file."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="capabilities.effective",
                    check_type="contains",
                    check_value="CAP_DAC_READ_SEARCH",
                    description="Requires CAP_DAC_READ_SEARCH capability",
                ),
            ],
            # T1005 (Data from Local System) covers the read; T1611 (Escape
            # to Host) covers the impact when the bypass is used to read
            # host secrets (admin.conf, /etc/kubernetes/pki/*).
            mitre_attack=["T1005", "T1611"],
            references=[
                "https://man7.org/linux/man-pages/man7/capabilities.7.html",
            ],
            reliability=0.95,
            stealth=0.7,
            remediation="--cap-drop=DAC_READ_SEARCH",
            cli_flag="--cap-drop=DAC_READ_SEARCH",
            verify_command="test -r /etc/shadow && head -c 1 /etc/shadow >/dev/null",
        ),
        EscapeTechnique(
            id="cap_dac_override",
            name="Write arbitrary host files",
            category=TechniqueCategory.CAPABILITY,
            severity=Severity.HIGH,
            description=(
                "CAP_DAC_OVERRIDE bypasses file write permission checks, "
                "enabling writes to any host file accessible from the mount namespace. "
                "Note: CAP_DAC_OVERRIDE is part of the Docker default capability set; "
                "it is only an escape primitive when the container can already see "
                "host files (privileged, hostPath mount, or shared mount namespace)."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="capabilities.effective",
                    check_type="contains",
                    check_value="CAP_DAC_OVERRIDE",
                    description="Requires CAP_DAC_OVERRIDE capability",
                    confidence_if_absent=0.0,
                ),
                Prerequisite(
                    check_field="runtime.privileged",
                    check_type="equals",
                    check_value=True,
                    description=(
                        "Container must be privileged OR have a host mount; "
                        "CAP_DAC_OVERRIDE alone in a non-privileged container "
                        "only bypasses DAC within the container's own mount namespace."
                    ),
                    confidence_if_absent=0.2,
                ),
            ],
            # T1565 (Data Manipulation) covers the unauthorized write;
            # T1611 (Escape to Host) covers the outcome when the writable
            # target lives in the host mount namespace.
            mitre_attack=["T1565", "T1611"],
            references=[
                "https://man7.org/linux/man-pages/man7/capabilities.7.html",
                "https://docs.docker.com/engine/security/#linux-kernel-capabilities",
            ],
            reliability=0.95,
            stealth=0.4,
            remediation="--cap-drop=DAC_OVERRIDE and avoid privileged/hostPath mounts",
            cli_flag="--cap-drop=DAC_OVERRIDE",
            # Open-for-append-then-close on a root-owned file the
            # container shouldn't be able to touch without
            # CAP_DAC_OVERRIDE. /etc/shadow is mode 0640 root:shadow on
            # most distros so a non-root container without DAC_OVERRIDE
            # fails. No write is ever performed (append-mode open
            # triggers the permission check without dirtying the file),
            # so the probe is strictly non-destructive — replacing the
            # previous create-and-delete on /var/log/_cepheus_v which
            # could leak state if interrupted between create and rm.
            verify_command="exec 3>>/etc/shadow 2>/dev/null && exec 3>&-",
        ),
        EscapeTechnique(
            id="cap_net_admin",
            name="Network namespace manipulation",
            category=TechniqueCategory.CAPABILITY,
            severity=Severity.MEDIUM,
            description=(
                "CAP_NET_ADMIN allows network interface configuration, routing "
                "table modification, and ARP spoofing within the network namespace."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="capabilities.effective",
                    check_type="contains",
                    check_value="CAP_NET_ADMIN",
                    description="Requires CAP_NET_ADMIN capability",
                ),
            ],
            mitre_attack=["T1557"],
            references=[
                "https://man7.org/linux/man-pages/man7/capabilities.7.html",
            ],
            reliability=0.8,
            stealth=0.6,
            remediation="--cap-drop=NET_ADMIN",
            cli_flag="--cap-drop=NET_ADMIN",
            verify_command="command -v ip >/dev/null 2>&1 && ip link set lo up",
        ),
        EscapeTechnique(
            id="cap_sys_rawio",
            name="Raw I/O to host devices",
            category=TechniqueCategory.CAPABILITY,
            severity=Severity.CRITICAL,
            description=(
                "CAP_SYS_RAWIO permits raw I/O port access and direct device "
                "manipulation, enabling low-level host compromise."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="capabilities.effective",
                    check_type="contains",
                    check_value="CAP_SYS_RAWIO",
                    description="Requires CAP_SYS_RAWIO capability",
                ),
            ],
            # T1006 (Direct Volume Access) covers raw device I/O;
            # T1611 (Escape to Host) covers the impact when the raw
            # device exposes host content (block devices, /dev/mem).
            mitre_attack=["T1006", "T1611"],
            references=[
                "https://man7.org/linux/man-pages/man7/capabilities.7.html",
            ],
            reliability=0.75,
            stealth=0.2,
            remediation="--cap-drop=SYS_RAWIO",
            cli_flag="--cap-drop=SYS_RAWIO",
            verify_command="for d in /dev/sda /dev/vda /dev/nvme0n1; do [ -r $d ] && dd if=$d of=/dev/null bs=1 count=0 2>/dev/null && exit 0; done; exit 1",
        ),
        EscapeTechnique(
            id="cap_sys_module",
            name="Load kernel module via CAP_SYS_MODULE",
            category=TechniqueCategory.CAPABILITY,
            severity=Severity.CRITICAL,
            description=(
                "CAP_SYS_MODULE permits the init_module/finit_module syscalls, "
                "letting an attacker load an arbitrary kernel module and execute "
                "code in ring 0 on the host — an immediate, total container "
                "escape. The only gates are the capability itself and whether "
                "module loading has been globally disabled "
                "(/proc/sys/kernel/modules_disabled)."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="capabilities.effective",
                    check_type="contains",
                    check_value="CAP_SYS_MODULE",
                    description="Requires CAP_SYS_MODULE capability",
                    confidence_if_absent=0.0,
                ),
            ],
            mitre_attack=["T1611", "T1547.006"],
            references=[
                "https://man7.org/linux/man-pages/man7/capabilities.7.html",
                "https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation",
            ],
            reliability=0.9,
            stealth=0.2,
            remediation="--cap-drop=SYS_MODULE",
            cli_flag="--cap-drop=SYS_MODULE",
            # CAP_SYS_MODULE is capability bit 16. A passing probe means the
            # capability is held AND module loading is not globally disabled —
            # the loadable-module primitive is genuinely available, so this is a
            # true confirmation (not precondition-only).
            verify_command=(
                "b=$(awk '/^CapEff:/ {print $2}' /proc/self/status); "
                '[ -n "$b" ] && [ $((0x$b & (1 << 16))) -ne 0 ] && '
                '[ "$(cat /proc/sys/kernel/modules_disabled 2>/dev/null || echo 0)" = "0" ]'
            ),
        ),
        EscapeTechnique(
            id="cap_sys_boot",
            name="Reboot the host via CAP_SYS_BOOT",
            category=TechniqueCategory.CAPABILITY,
            severity=Severity.HIGH,
            description=(
                "CAP_SYS_BOOT permits the reboot(2) syscall, which acts on the "
                "host kernel regardless of the container boundary — a container "
                "holding it can reboot or power off the entire node, a host-wide "
                "denial of service."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="capabilities.effective",
                    check_type="contains",
                    check_value="CAP_SYS_BOOT",
                    description="Requires CAP_SYS_BOOT capability",
                    confidence_if_absent=0.0,
                ),
            ],
            mitre_attack=["T1529"],
            references=[
                "https://man7.org/linux/man-pages/man7/capabilities.7.html",
            ],
            reliability=0.85,
            stealth=0.1,
            remediation="--cap-drop=SYS_BOOT",
            cli_flag="--cap-drop=SYS_BOOT",
            # CAP_SYS_BOOT is capability bit 22. Holding it IS the primitive
            # (reboot(2) acts on the host), so a passing bit check is a true
            # confirmation. The probe only reads CapEff — it never calls reboot.
            verify_command=(
                "b=$(awk '/^CapEff:/ {print $2}' /proc/self/status); [ -n \"$b\" ] && [ $((0x$b & (1 << 22))) -ne 0 ]"
            ),
        ),
        EscapeTechnique(
            id="cap_syslog",
            name="Kernel address disclosure via CAP_SYSLOG",
            category=TechniqueCategory.CAPABILITY,
            severity=Severity.MEDIUM,
            description=(
                "CAP_SYSLOG permits syslog(2) (dmesg) and bypasses "
                "kptr_restrict, exposing kernel pointers in the ring buffer and "
                "via /proc. Those addresses defeat KASLR, turning an otherwise "
                "unreliable kernel exploit into a reliable host escape — a "
                "force-multiplier rather than a standalone escape."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="capabilities.effective",
                    check_type="contains",
                    check_value="CAP_SYSLOG",
                    description="Requires CAP_SYSLOG capability",
                    confidence_if_absent=0.0,
                ),
            ],
            mitre_attack=["T1082"],
            references=[
                "https://man7.org/linux/man-pages/man7/capabilities.7.html",
            ],
            reliability=0.7,
            stealth=0.5,
            remediation="--cap-drop=SYSLOG",
            cli_flag="--cap-drop=SYSLOG",
            # CAP_SYSLOG is capability bit 34. A pass means the capability is
            # held AND kptr_restrict is not fully locked (2), so kernel pointers
            # are actually leakable — the disclosure primitive is real.
            verify_command=(
                "b=$(awk '/^CapEff:/ {print $2}' /proc/self/status); "
                '[ -n "$b" ] && [ $((0x$b & (1 << 34))) -ne 0 ] && '
                '[ "$(cat /proc/sys/kernel/kptr_restrict 2>/dev/null || echo 0)" != "2" ]'
            ),
        ),
        EscapeTechnique(
            id="cap_perfmon",
            name="Kernel memory disclosure via CAP_PERFMON",
            category=TechniqueCategory.CAPABILITY,
            severity=Severity.MEDIUM,
            description=(
                "CAP_PERFMON (split out of CAP_SYS_ADMIN in kernel 5.8) permits "
                "perf_event_open(2) and bypasses perf_event_paranoid, exposing "
                "kernel and cross-process performance data that can leak "
                "addresses and memory contents — a KASLR-defeating "
                "information-disclosure primitive that strengthens kernel "
                "exploitation toward host escape."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="capabilities.effective",
                    check_type="contains",
                    check_value="CAP_PERFMON",
                    description="Requires CAP_PERFMON capability",
                    confidence_if_absent=0.0,
                ),
            ],
            mitre_attack=["T1082"],
            references=[
                "https://man7.org/linux/man-pages/man7/capabilities.7.html",
            ],
            reliability=0.6,
            stealth=0.5,
            remediation="--cap-drop=PERFMON",
            cli_flag="--cap-drop=PERFMON",
            # CAP_PERFMON is capability bit 38. Holding it lets perf_event_open
            # bypass perf_event_paranoid, so the bit check confirms the real
            # disclosure primitive. The probe only reads CapEff.
            verify_command=(
                "b=$(awk '/^CapEff:/ {print $2}' /proc/self/status); [ -n \"$b\" ] && [ $((0x$b & (1 << 38))) -ne 0 ]"
            ),
        ),
        EscapeTechnique(
            id="ebpf_probe_write_user",
            name="bpf_probe_write_user kernel manipulation",
            category=TechniqueCategory.CAPABILITY,
            severity=Severity.CRITICAL,
            description=(
                "With CAP_BPF or CAP_SYS_ADMIN, the bpf_probe_write_user "
                "helper can write to user-space memory of any process, "
                "enabling arbitrary code execution on the host."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="capabilities.effective",
                    check_type="any_of",
                    check_value=["CAP_SYS_ADMIN", "CAP_BPF"],
                    description="Requires CAP_SYS_ADMIN or CAP_BPF",
                    confidence_if_absent=0.0,
                ),
                Prerequisite(
                    check_field="kernel.version",
                    check_type="kernel_gte",
                    check_value="4.17.0",
                    description="bpf_probe_write_user available from kernel 4.17+",
                ),
                Prerequisite(
                    check_field="security.seccomp",
                    check_type="not_equals",
                    check_value="strict",
                    description="Seccomp must not be in strict mode",
                ),
            ],
            mitre_attack=["T1611", "T1068"],
            references=[
                "https://www.graplsecurity.com/post/kernel-pwning-with-ebpf-a-love-story",
            ],
            reliability=0.6,
            stealth=0.7,
            remediation="Drop CAP_SYS_ADMIN and CAP_BPF, enable seccomp",
            # Same probe as cap_sys_admin_bpf — bpftool requires the same
            # capabilities that bpf_probe_write_user does. Confirms the
            # BPF call surface is reachable from this container.
            verify_command="(command -v bpftool >/dev/null 2>&1 && bpftool prog list >/dev/null 2>&1) || [ -r /sys/kernel/btf/vmlinux ]",
        ),
        # ── MOUNT (15) ───────────────────────────────────────────────
        EscapeTechnique(
            id="docker_socket_mount",
            name="Docker socket mounted — host command exec",
            category=TechniqueCategory.MOUNT,
            severity=Severity.CRITICAL,
            description=(
                "Docker socket (/var/run/docker.sock) is reachable from the "
                "container, allowing full Docker API access and trivial escape."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="network.can_reach_docker_sock",
                    check_type="equals",
                    check_value=True,
                    description="Docker socket must be reachable",
                ),
                # NOTE: the old `available_tools contains curl` prerequisite is
                # removed. `contains` returns 0.0 (a HARD FAIL) when curl is
                # absent, so the technique NEVER fired on the many images without
                # curl (alpine, busybox, distroless) — even though a mounted,
                # writable docker.sock is a full escape regardless of which HTTP
                # client is installed. The reachable+writable socket IS the
                # primitive; the tool-free verify_command below confirms it.
            ],
            mitre_attack=["T1611"],
            references=[
                "https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation",
            ],
            reliability=0.95,
            stealth=0.2,
            remediation="Never mount Docker socket into containers",
            verify_command="[ -S /var/run/docker.sock ] && [ -w /var/run/docker.sock ]",
        ),
        EscapeTechnique(
            id="podman_sock_mount",
            name="Podman socket mounted — host command exec",
            category=TechniqueCategory.MOUNT,
            severity=Severity.CRITICAL,
            description=(
                "The Podman API socket (/run/podman/podman.sock) is mounted and "
                "writable inside the container. Like the Docker socket, it grants "
                "full control of the container engine — an attacker can launch a "
                "privileged container that mounts the host filesystem and escape. "
                "Completes socket-mount coverage alongside docker/containerd/cri-o."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="writable_paths",
                    check_type="contains",
                    check_value="/run/podman/podman.sock",
                    description="Podman socket must be mounted and writable",
                    confidence_if_absent=0.0,
                ),
            ],
            mitre_attack=["T1611"],
            references=[
                "https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation",
            ],
            reliability=0.95,
            stealth=0.2,
            remediation="Never mount the Podman socket into containers",
            verify_command="[ -S /run/podman/podman.sock ] && [ -w /run/podman/podman.sock ]",
        ),
        EscapeTechnique(
            id="procfs_core_pattern",
            name="Write to /proc/sys/kernel/core_pattern",
            category=TechniqueCategory.MOUNT,
            severity=Severity.CRITICAL,
            description=(
                "If /proc/sys/kernel/core_pattern is writable AND the container "
                "has CAP_SYS_ADMIN, an attacker can set it to a pipe command "
                "that executes on the host when a core dump is triggered. "
                "Note: DAC permission alone is insufficient — kernel rejects "
                "writes to /proc/sys/kernel/* without CAP_SYS_ADMIN even when "
                "the procfs mount appears writable to the container."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="writable_paths",
                    check_type="contains",
                    check_value="/proc/sys/kernel/core_pattern",
                    description="/proc/sys/kernel/core_pattern must be writable",
                    confidence_if_absent=0.0,
                ),
                Prerequisite(
                    check_field="capabilities.effective",
                    check_type="contains",
                    check_value="CAP_SYS_ADMIN",
                    description=(
                        "CAP_SYS_ADMIN required for the kernel to honor writes "
                        "to /proc/sys/kernel/* — DAC-only access yields EROFS"
                    ),
                    confidence_if_absent=0.0,
                ),
            ],
            mitre_attack=["T1611"],
            references=[
                "https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation",
            ],
            reliability=0.85,
            stealth=0.3,
            remediation="Mount /proc read-only or use seccomp",
            verify_command="exec 3>>/proc/sys/kernel/core_pattern && exec 3>&-",
        ),
        EscapeTechnique(
            id="procfs_modprobe_path",
            name="Overwrite /proc/sys/kernel/modprobe",
            category=TechniqueCategory.MOUNT,
            severity=Severity.CRITICAL,
            description=(
                "If /proc/sys/kernel/modprobe is writable AND the container has "
                "CAP_SYS_ADMIN, an attacker can repoint the kernel's modprobe "
                "helper at an attacker-controlled script, then trigger an "
                "auto-modprobe (e.g. executing a file with an unknown binfmt or "
                "opening a socket for an unregistered protocol) to run that "
                "script as root on the host. Like core_pattern, the kernel "
                "rejects writes to /proc/sys/kernel/* without CAP_SYS_ADMIN even "
                "when the procfs mount looks writable."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="writable_paths",
                    check_type="contains",
                    check_value="/proc/sys/kernel/modprobe",
                    description="/proc/sys/kernel/modprobe must be writable",
                    confidence_if_absent=0.0,
                ),
                Prerequisite(
                    check_field="capabilities.effective",
                    check_type="contains",
                    check_value="CAP_SYS_ADMIN",
                    description=(
                        "CAP_SYS_ADMIN required for the kernel to honor writes "
                        "to /proc/sys/kernel/* — DAC-only access yields EROFS"
                    ),
                    confidence_if_absent=0.0,
                ),
            ],
            mitre_attack=["T1611", "T1547.006"],
            references=[
                "https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation",
            ],
            reliability=0.8,
            stealth=0.35,
            remediation="Mount /proc read-only or drop CAP_SYS_ADMIN",
            verify_command="exec 3>>/proc/sys/kernel/modprobe && exec 3>&-",
        ),
        EscapeTechnique(
            id="sysfs_uevent_helper",
            name="Overwrite /sys/kernel/uevent_helper",
            category=TechniqueCategory.MOUNT,
            severity=Severity.CRITICAL,
            description=(
                "If /sys/kernel/uevent_helper is writable (a host /sys mounted "
                "read-write, typical of privileged containers), an attacker can "
                "set it to an attacker-controlled path and then trigger a uevent "
                "(e.g. `echo change > /sys/.../uevent`). The kernel runs the "
                "helper as root in the host's initial namespace — a full escape."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="writable_paths",
                    check_type="contains",
                    check_value="/sys/kernel/uevent_helper",
                    description="/sys/kernel/uevent_helper must be writable",
                    confidence_if_absent=0.0,
                ),
            ],
            mitre_attack=["T1611"],
            references=[
                "https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation",
            ],
            reliability=0.85,
            stealth=0.3,
            remediation="Mount /sys read-only",
            verify_command="exec 3>>/sys/kernel/uevent_helper && exec 3>&-",
        ),
        EscapeTechnique(
            id="procfs_sysrq",
            name="/proc/sysrq-trigger abuse",
            category=TechniqueCategory.MOUNT,
            severity=Severity.HIGH,
            description=(
                "Writing to /proc/sysrq-trigger can crash or reboot the host "
                "kernel, causing denial of service. Requires both write access "
                "to the procfs path AND CAP_SYS_ADMIN — non-privileged "
                "containers see the file as writable per DAC but the kernel "
                "rejects the write with EROFS."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="writable_paths",
                    check_type="contains",
                    check_value="/proc/sysrq-trigger",
                    description="/proc/sysrq-trigger must be writable",
                    confidence_if_absent=0.0,
                ),
                Prerequisite(
                    check_field="capabilities.effective",
                    check_type="contains",
                    check_value="CAP_SYS_ADMIN",
                    description=(
                        "CAP_SYS_ADMIN required for the kernel to honor sysrq writes — "
                        "DAC-only access yields EROFS in unprivileged containers"
                    ),
                    confidence_if_absent=0.0,
                ),
            ],
            mitre_attack=["T1529"],
            references=[
                "https://docs.kernel.org/admin-guide/sysrq.html",
            ],
            reliability=0.9,
            stealth=0.1,
            remediation="Mount /proc read-only",
            verify_command="exec 3>>/proc/sysrq-trigger && exec 3>&-",
        ),
        EscapeTechnique(
            id="sysfs_hugepages",
            name="sysfs writeback exploitation",
            category=TechniqueCategory.MOUNT,
            severity=Severity.HIGH,
            description=(
                "Writable /sys filesystem allows manipulation of kernel "
                "parameters including hugepages, device settings, and more. "
                "Note: /sys is mounted read-only in non-privileged containers; "
                "DAC may show write permission but the mount is ro at the "
                "kernel level. Real write access requires CAP_SYS_ADMIN."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="writable_paths",
                    check_type="contains",
                    check_value="/sys",
                    description="/sys must be writable",
                    confidence_if_absent=0.0,
                ),
                Prerequisite(
                    check_field="capabilities.effective",
                    check_type="contains",
                    check_value="CAP_SYS_ADMIN",
                    description=(
                        "CAP_SYS_ADMIN required for the kernel to honor writes "
                        "to /sys — DAC-only access yields EROFS in unprivileged "
                        "containers."
                    ),
                    confidence_if_absent=0.0,
                ),
            ],
            mitre_attack=["T1611"],
            references=[
                "https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts",
            ],
            reliability=0.6,
            stealth=0.4,
            remediation="Mount /sys read-only",
            verify_command="exec 3>>/sys/kernel/uevent_helper 2>/dev/null && exec 3>&- 2>/dev/null",
        ),
        EscapeTechnique(
            id="hostpath_mount_etc",
            name="Writable host /etc mount",
            category=TechniqueCategory.MOUNT,
            severity=Severity.CRITICAL,
            description=(
                "Host /etc is mounted writable in the container, allowing "
                "modification of passwd, shadow, cron, and other critical files."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="writable_paths",
                    check_type="contains",
                    check_value="/host/etc",
                    confidence_if_absent=0.2,
                    description="Host /etc mounted and writable",
                ),
            ],
            mitre_attack=["T1611"],
            references=[
                "https://kubernetes.io/docs/concepts/storage/volumes/#hostpath",
            ],
            reliability=0.95,
            stealth=0.3,
            remediation="Avoid hostPath mounts or use readOnly",
            verify_command="[ -d /host/etc ] || [ -d /host-system/etc ] || [ -d /host-root/etc ]",
        ),
        EscapeTechnique(
            id="hostpath_mount_root",
            name="Writable host / mount",
            category=TechniqueCategory.MOUNT,
            severity=Severity.CRITICAL,
            description=(
                "The host root filesystem is mounted writable in the container, "
                "providing unrestricted access to the entire host."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="writable_paths",
                    check_type="contains",
                    check_value="/host",
                    confidence_if_absent=0.2,
                    description="Host root filesystem mounted and writable",
                ),
            ],
            mitre_attack=["T1611"],
            references=[
                "https://kubernetes.io/docs/concepts/storage/volumes/#hostpath",
            ],
            reliability=0.95,
            stealth=0.2,
            remediation="Never mount host root filesystem",
            verify_command="[ -d /host/var ] || [ -d /host-system/var ] || [ -d /host-root/var ]",
        ),
        EscapeTechnique(
            id="cgroupfs_escape",
            name="Writable cgroup filesystem",
            category=TechniqueCategory.MOUNT,
            severity=Severity.HIGH,
            description=(
                "Writable cgroup v1 filesystem allows mounting new cgroups, "
                "setting release_agent, and executing host commands."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="writable_paths",
                    check_type="contains",
                    check_value="/sys/fs/cgroup",
                    description="/sys/fs/cgroup must be writable",
                ),
                Prerequisite(
                    check_field="cgroup_version",
                    check_type="equals",
                    check_value=1,
                    description="Requires cgroup v1",
                ),
            ],
            mitre_attack=["T1611"],
            references=[
                "https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/",
            ],
            reliability=0.8,
            stealth=0.4,
            remediation="Use cgroup v2, mount cgroups read-only",
            # Tests writability of the cgroup hierarchy — opens any v1
            # controller's cgroup.procs file for append (non-destructive)
            # and immediately closes. Returns 0 iff the kernel honours
            # writes (which requires both DAC perms AND CAP_SYS_ADMIN
            # for /sys/fs/cgroup on non-privileged containers).
            verify_command="for f in /sys/fs/cgroup/memory/cgroup.procs /sys/fs/cgroup/cpu/cgroup.procs; do exec 3>>$f 2>/dev/null && exec 3>&- && exit 0; done; exit 1",
        ),
        EscapeTechnique(
            id="devfs_access",
            name="Access to /dev host devices",
            category=TechniqueCategory.MOUNT,
            severity=Severity.CRITICAL,
            description=(
                "Privileged containers have full access to host /dev, allowing "
                "direct read/write to disk devices and other hardware."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="runtime.privileged",
                    check_type="equals",
                    check_value=True,
                    description="Container must be running in privileged mode",
                ),
            ],
            mitre_attack=["T1006"],
            references=[
                "https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation",
            ],
            reliability=0.85,
            stealth=0.2,
            remediation="--privileged=false, use --device for specific needs",
            cli_flag="--privileged=false",
            verify_command="for d in /dev/sda /dev/vda /dev/nvme0n1 /dev/loop0; do [ -r $d ] && exit 0; done; exit 1",
        ),
        EscapeTechnique(
            id="containerd_sock_mount",
            name="Containerd socket access",
            category=TechniqueCategory.MOUNT,
            severity=Severity.CRITICAL,
            description=(
                "Containerd socket is accessible from the container, allowing "
                "direct containerd API access to manage containers on the host."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="network.can_reach_containerd_sock",
                    check_type="equals",
                    check_value=True,
                    description="Containerd socket must be reachable",
                ),
            ],
            mitre_attack=["T1611"],
            references=[
                "https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation",
            ],
            reliability=0.9,
            stealth=0.2,
            remediation="Never mount containerd socket into containers",
            verify_command="[ -S /run/containerd/containerd.sock ] || [ -S /var/run/containerd/containerd.sock ]",
        ),
        EscapeTechnique(
            id="crio_sock_mount",
            name="CRI-O socket access",
            category=TechniqueCategory.MOUNT,
            severity=Severity.CRITICAL,
            description=(
                "CRI-O socket is accessible from the container, allowing "
                "direct CRI API access to manage containers on the host."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="network.can_reach_crio_sock",
                    check_type="equals",
                    check_value=True,
                    description="CRI-O socket must be reachable",
                ),
            ],
            mitre_attack=["T1611"],
            references=[
                "https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation",
            ],
            reliability=0.9,
            stealth=0.2,
            remediation="Never mount CRI-O socket into containers",
            verify_command="[ -S /var/run/crio/crio.sock ] || [ -S /run/crio/crio.sock ]",
        ),
        EscapeTechnique(
            id="systemd_cgroup_injection",
            name="Systemd unit injection via writable cgroup v1",
            category=TechniqueCategory.MOUNT,
            severity=Severity.CRITICAL,
            description=(
                "Writable cgroup v1 hierarchy under systemd allows creating "
                "a transient systemd unit that executes on the host."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="writable_paths",
                    check_type="contains",
                    check_value="/sys/fs/cgroup",
                    description="/sys/fs/cgroup must be writable",
                ),
                Prerequisite(
                    check_field="cgroup_version",
                    check_type="equals",
                    check_value=1,
                    description="Requires cgroup v1",
                ),
                Prerequisite(
                    check_field="capabilities.effective",
                    check_type="contains",
                    check_value="CAP_SYS_ADMIN",
                    description="Requires CAP_SYS_ADMIN capability",
                ),
            ],
            mitre_attack=["T1611"],
            references=[
                "https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/",
            ],
            reliability=0.8,
            stealth=0.3,
            remediation="Use cgroup v2, mount cgroups read-only, drop CAP_SYS_ADMIN",
            # systemd unit injection requires writable systemd cgroup
            # hierarchy. Probe the systemd-specific paths used by
            # systemd-run --scope abuse patterns.
            verify_command="for f in /sys/fs/cgroup/systemd/cgroup.procs /sys/fs/cgroup/systemd.slice/cgroup.subtree_control; do exec 3>>$f 2>/dev/null && exec 3>&- && exit 0; done; exit 1",
        ),
        EscapeTechnique(
            id="tmpfs_shm_cross_container",
            name="Shared /dev/shm cross-container data exfil",
            category=TechniqueCategory.MOUNT,
            severity=Severity.MEDIUM,
            description=(
                "Writable /dev/shm shared between containers on the same host "
                "allows cross-container data exchange and exfiltration. "
                "Note: every container has a writable /dev/shm by default — "
                "this technique only represents an actual exposure when the IPC "
                "namespace is shared with the host (hostIPC) or with another pod "
                "via an explicit shared emptyDir volume."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="writable_paths",
                    check_type="contains",
                    check_value="/dev/shm",
                    description="/dev/shm must be writable",
                    confidence_if_absent=0.0,
                ),
                Prerequisite(
                    check_field="runtime.privileged",
                    check_type="equals",
                    check_value=True,
                    description=(
                        "Privileged container (proxy for hostIPC/shared-IPC "
                        "exposure — direct hostIPC detection is unreliable in "
                        "the 0.4.0 enumerator). Non-privileged pods get a "
                        "private /dev/shm via emptyDir tmpfs."
                    ),
                    confidence_if_absent=0.1,
                ),
            ],
            mitre_attack=["T1005", "T1080"],
            references=[
                "https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts",
            ],
            reliability=0.7,
            stealth=0.8,
            remediation="Use --ipc=private, restrict /dev/shm size",
            cli_flag="--ipc=private",
            verify_command="[ -d /dev/shm ] && [ -w /dev/shm ]",
        ),
        EscapeTechnique(
            id="proc_fd_symlink_traversal",
            name="/proc/self/fd symlink to host",
            category=TechniqueCategory.MOUNT,
            severity=Severity.HIGH,
            description=(
                "Symlinks in /proc/self/fd can point to host filesystem "
                "locations, enabling file reads/writes outside the container. "
                "Every container has /proc/self/fd; the exploit primitive only "
                "yields host access when combined with a capability that "
                "permits reading the symlink target (CAP_DAC_READ_SEARCH or "
                "CAP_SYS_ADMIN), or with CVE-2024-21626-style runc fd leaks."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="writable_paths",
                    check_type="contains",
                    check_value="/proc/self/fd",
                    description="/proc/self/fd must be accessible and writable",
                    confidence_if_absent=0.0,
                ),
                Prerequisite(
                    check_field="capabilities.effective",
                    check_type="any_of",
                    check_value=["CAP_DAC_READ_SEARCH", "CAP_SYS_ADMIN"],
                    description=(
                        "Need a capability that bypasses path-resolution DAC "
                        "checks on the symlink target. CAP_DAC_OVERRIDE is in "
                        "the default Docker cap set but doesn't actually permit "
                        "reading symlinks pointing outside the container's "
                        "mount namespace — only CAP_DAC_READ_SEARCH and "
                        "CAP_SYS_ADMIN do."
                    ),
                    confidence_if_absent=0.1,
                ),
            ],
            mitre_attack=["T1611"],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2024-21626",
            ],
            reliability=0.6,
            stealth=0.5,
            remediation="Restrict /proc access, use read-only /proc mounts",
            verify_command="[ -L /proc/self/fd/0 ] && readlink /proc/self/fd/0 >/dev/null",
        ),
        EscapeTechnique(
            id="device_mapper_access",
            name="Device-mapper direct access",
            category=TechniqueCategory.MOUNT,
            severity=Severity.HIGH,
            description=(
                "Direct access to device-mapper allows creating and manipulating "
                "block device mappings, potentially accessing host storage."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="writable_paths",
                    check_type="contains",
                    check_value="/sys/devices/virtual/misc/device-mapper/dev",
                    description="Device-mapper must be accessible",
                ),
                Prerequisite(
                    check_field="capabilities.effective",
                    check_type="contains",
                    check_value="CAP_SYS_ADMIN",
                    description="Requires CAP_SYS_ADMIN capability",
                ),
            ],
            mitre_attack=["T1006"],
            references=[
                "https://man7.org/linux/man-pages/man8/dmsetup.8.html",
            ],
            reliability=0.5,
            stealth=0.3,
            remediation="Remove device-mapper access, drop CAP_SYS_ADMIN",
            # /dev/mapper/control is the device-mapper ioctl entry; its
            # presence + readability indicates the container can issue
            # dm_ioctl calls (requires CAP_SYS_ADMIN to actually use).
            verify_command="[ -c /dev/mapper/control ] && [ -r /dev/mapper/control ]",
        ),
        EscapeTechnique(
            id="vm_param_manipulation",
            name="/proc/sys/vm parameter manipulation",
            category=TechniqueCategory.MOUNT,
            severity=Severity.MEDIUM,
            description=(
                "Writable /proc/sys/vm allows manipulation of kernel memory "
                "management parameters, potentially causing host instability "
                "or enabling side-channel attacks. Like other /proc/sys/* "
                "interfaces, real write access requires CAP_SYS_ADMIN even "
                "when DAC permissions appear to allow it."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="writable_paths",
                    check_type="contains",
                    check_value="/proc/sys/vm",
                    description="/proc/sys/vm must be writable",
                    confidence_if_absent=0.0,
                ),
                Prerequisite(
                    check_field="capabilities.effective",
                    check_type="contains",
                    check_value="CAP_SYS_ADMIN",
                    description=("CAP_SYS_ADMIN required to write kernel sysctls"),
                    confidence_if_absent=0.0,
                ),
            ],
            mitre_attack=["T1529"],
            references=[
                "https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts",
            ],
            reliability=0.6,
            stealth=0.4,
            remediation="Mount /proc read-only or use seccomp",
            verify_command="exec 3>>/proc/sys/vm/drop_caches 2>/dev/null && exec 3>&- 2>/dev/null",
        ),
        # ── KERNEL (17) ──────────────────────────────────────────────
        EscapeTechnique(
            id="cve_2022_0185",
            name="FSConfig heap overflow",
            category=TechniqueCategory.KERNEL,
            severity=Severity.CRITICAL,
            description=(
                "Heap buffer overflow in the legacy_parse_param function of "
                "fs/fs_context.c allows container escape via user namespaces."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="kernel.version",
                    check_type="kernel_between",
                    check_value=["5.1.0", "5.16.2"],
                    description="Kernel between 5.1.0 and 5.16.2",
                ),
            ],
            mitre_attack=["T1068"],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2022-0185",
                "https://www.willsroot.io/2022/01/cve-2022-0185.html",
            ],
            cve="CVE-2022-0185",
            reliability=0.7,
            stealth=0.5,
            remediation="Update kernel to >= 5.16.2",
            # legacy_parse_param() is reached via a mount of a user-namespaced
            # fs context. The exploit needs (a) vulnerable kernel (matcher
            # checks via posture) and (b) unprivileged user-namespace + mount
            # surface available inside the container. Probe (b) by trying to
            # create a transient user+net+mount namespace; success means the
            # syscall chain the PoC opens is reachable. Failure (seccomp,
            # unprivileged_userns_clone=0, AppArmor deny) means the precondition
            # is missing and the static-posture match was a false positive.
            verify_command="unshare -Urn true 2>/dev/null",
        ),
        EscapeTechnique(
            id="cve_2022_0847",
            name="DirtyPipe",
            category=TechniqueCategory.KERNEL,
            severity=Severity.CRITICAL,
            description=(
                "DirtyPipe allows overwriting data in arbitrary read-only files, "
                "enabling privilege escalation and container escape."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="kernel.version",
                    check_type="kernel_between",
                    check_value=["5.8.0", "5.16.11"],
                    description="Kernel between 5.8.0 and 5.16.11",
                ),
            ],
            mitre_attack=["T1068"],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2022-0847",
                "https://dirtypipe.cm4all.com/",
            ],
            cve="CVE-2022-0847",
            reliability=0.9,
            stealth=0.6,
            remediation="Update kernel to >= 5.16.11",
            # DirtyPipe needs no capabilities — only a kernel in the
            # vulnerable band (5.8 .. 5.16.11). The static matcher already
            # checks /proc/version, but in-container `uname -r` is the
            # authoritative live signal. Done as a portable awk
            # numeric-compare so we don't depend on `sort -V` (busybox
            # often lacks it). Parses M.m.p out of the release string
            # `5.10.110-3-amd64` etc; the `[.-]` field separator handles
            # both vanilla and distro-suffixed forms.
            verify_command=(
                'k=$(uname -r); v=$(echo "$k" | awk -F"[.-]" '
                "'{printf \"%d\", $1*10000+$2*100+$3}'); "
                '[ -n "$v" ] && [ "$v" -ge 50800 ] && [ "$v" -lt 51611 ]'
            ),
        ),
        EscapeTechnique(
            id="cve_2021_22555",
            name="Netfilter heap OOB write",
            category=TechniqueCategory.KERNEL,
            severity=Severity.CRITICAL,
            description=(
                "Out-of-bounds write in Netfilter setsockopt IPT_SO_SET_REPLACE "
                "allows heap corruption and privilege escalation."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="kernel.version",
                    check_type="kernel_between",
                    check_value=["2.6.19", "5.12.0"],
                    description="Kernel between 2.6.19 and 5.12.0",
                ),
            ],
            mitre_attack=["T1068"],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2021-22555",
                "https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html",
            ],
            cve="CVE-2021-22555",
            reliability=0.65,
            stealth=0.4,
            remediation="Update kernel to >= 5.12",
            # IPT_SO_SET_REPLACE setsockopt is reached only after the
            # exploit has set up its own user+net namespace with
            # CAP_NET_ADMIN inside it. Probe that we can actually open
            # such a namespace; if seccomp/AppArmor blocks unshare, the
            # PoC can't even start.
            verify_command="unshare -Urn true 2>/dev/null",
        ),
        EscapeTechnique(
            id="cve_2022_2588",
            name="route4 use-after-free",
            category=TechniqueCategory.KERNEL,
            severity=Severity.CRITICAL,
            description=("Use-after-free in net/sched/cls_route.c allows privilege escalation from container to host."),
            prerequisites=[
                Prerequisite(
                    check_field="kernel.version",
                    check_type="kernel_lte",
                    check_value="5.19.2",
                    description="Kernel <= 5.19.2",
                ),
            ],
            mitre_attack=["T1068"],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2022-2588",
            ],
            cve="CVE-2022-2588",
            reliability=0.6,
            stealth=0.4,
            remediation="Update kernel to >= 5.19.2",
            # cls_route is reached via tc / netlink from inside a user+net
            # namespace. unshare-ability is the necessary surface check.
            verify_command="unshare -Urn true 2>/dev/null",
        ),
        EscapeTechnique(
            id="cve_2023_0386",
            name="OverlayFS privilege escalation",
            category=TechniqueCategory.KERNEL,
            severity=Severity.CRITICAL,
            description=(
                "Flaw in OverlayFS allows a local user to gain elevated "
                "privileges via setuid file copy-up from nosuid mounts."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="kernel.version",
                    check_type="kernel_between",
                    check_value=["5.11.0", "6.2.0"],
                    description="Kernel between 5.11.0 and 6.2.0",
                ),
            ],
            mitre_attack=["T1068"],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2023-0386",
            ],
            cve="CVE-2023-0386",
            reliability=0.75,
            stealth=0.5,
            remediation="Update kernel to >= 6.2",
            # OverlayFS copy-up setuid bug is reachable by mounting an
            # overlay from a userns-owned mount namespace. The PoC begins
            # with `unshare -Urm`, so a positive probe says the necessary
            # mount-in-userns surface is available.
            verify_command="unshare -Urm true 2>/dev/null",
        ),
        EscapeTechnique(
            id="cve_2023_32233",
            name="nf_tables use-after-free",
            category=TechniqueCategory.KERNEL,
            severity=Severity.CRITICAL,
            description=(
                "Use-after-free in nf_tables when processing batch requests "
                "allows arbitrary code execution in the kernel."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="kernel.version",
                    check_type="kernel_lte",
                    check_value="6.4.0",
                    description="Kernel <= 6.4.0",
                ),
            ],
            mitre_attack=["T1068"],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2023-32233",
            ],
            cve="CVE-2023-32233",
            reliability=0.65,
            stealth=0.4,
            remediation="Update kernel to >= 6.4",
            # nf_tables batch handling is reached via netlink from inside
            # a user+net namespace. The PoC's first step is `unshare -Urn`.
            verify_command="unshare -Urn true 2>/dev/null",
        ),
        EscapeTechnique(
            id="cve_2024_1086",
            name="nf_tables double-free",
            category=TechniqueCategory.KERNEL,
            severity=Severity.CRITICAL,
            description=(
                "Double-free in nf_tables verdict handling enables arbitrary code execution and container escape."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="kernel.version",
                    check_type="kernel_between",
                    check_value=["3.15.0", "6.8.0"],
                    description="Kernel between 3.15.0 and 6.8.0",
                ),
            ],
            mitre_attack=["T1068"],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2024-1086",
                "https://pwning.tech/nftables/",
            ],
            cve="CVE-2024-1086",
            reliability=0.7,
            stealth=0.4,
            remediation="Update kernel to >= 6.8",
            # nf_tables verdict double-free is reached via the same
            # userns + netlink path as CVE-2023-32233.
            verify_command="unshare -Urn true 2>/dev/null",
        ),
        EscapeTechnique(
            id="cve_2021_31440",
            name="eBPF verifier bypass",
            category=TechniqueCategory.KERNEL,
            severity=Severity.HIGH,
            description=(
                "eBPF verifier bounds tracking flaw allows out-of-bounds "
                "read/write in kernel memory via crafted BPF programs."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="kernel.version",
                    check_type="kernel_between",
                    check_value=["5.7.0", "5.12.0"],
                    description="Kernel between 5.7.0 and 5.12.0",
                ),
                Prerequisite(
                    check_field="capabilities.effective",
                    check_type="any_of",
                    check_value=["CAP_SYS_ADMIN", "CAP_BPF"],
                    description="Requires CAP_SYS_ADMIN or CAP_BPF",
                    confidence_if_absent=0.0,
                ),
            ],
            mitre_attack=["T1068"],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2021-31440",
            ],
            cve="CVE-2021-31440",
            reliability=0.55,
            stealth=0.5,
            remediation="Update kernel, drop CAP_BPF/CAP_SYS_ADMIN",
        ),
        EscapeTechnique(
            id="cve_2022_23222",
            name="eBPF type confusion",
            category=TechniqueCategory.KERNEL,
            severity=Severity.HIGH,
            description=(
                "Type confusion in BPF verifier allows pointer arithmetic "
                "bypass leading to arbitrary kernel read/write."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="kernel.version",
                    check_type="kernel_between",
                    check_value=["5.8.0", "5.16.0"],
                    description="Kernel between 5.8.0 and 5.16.0",
                ),
                Prerequisite(
                    check_field="capabilities.effective",
                    check_type="contains",
                    check_value="CAP_BPF",
                    confidence_if_absent=0.4,
                    description="Requires CAP_BPF capability",
                ),
            ],
            mitre_attack=["T1068"],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2022-23222",
            ],
            cve="CVE-2022-23222",
            reliability=0.6,
            stealth=0.5,
            remediation="Update kernel to >= 5.16",
            # eBPF verifier type-confusion needs the BPF syscall surface
            # open. That means either (a) CAP_BPF in CapEff (bit 39 = 1<<39
            # = 0x8000000000), (b) CAP_SYS_ADMIN (bit 21 = 1<<21 = 0x200000),
            # or (c) unprivileged_bpf_disabled=0. Probe all three:
            # exit 0 if any one is true. Uses POSIX shell arithmetic which
            # accepts 0x literals; the masks fit in a 64-bit signed long
            # so this works on every 64-bit host (the only arch container
            # CVE-2022-23222 applies to).
            verify_command=(
                'b=$(awk "/^CapEff:/ {print \\$2}" /proc/self/status); '
                'if [ -n "$b" ]; then '
                "  if [ $((0x$b & 0x8000000000)) -ne 0 ]; then exit 0; fi; "
                "  if [ $((0x$b & 0x200000)) -ne 0 ]; then exit 0; fi; "
                "fi; "
                '[ "$(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null)" = "0" ]'
            ),
        ),
        EscapeTechnique(
            id="cve_2024_21626",
            name="runc process.cwd container breakout",
            category=TechniqueCategory.KERNEL,
            severity=Severity.CRITICAL,
            description=(
                "runc file descriptor leak allows a newly started container "
                "to access the host filesystem via /proc/self/fd."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="runtime.runtime",
                    check_type="equals",
                    check_value="docker",
                    confidence_if_absent=0.5,
                    description="Docker runtime likely uses runc",
                ),
                Prerequisite(
                    check_field="kernel.version",
                    check_type="kernel_lte",
                    check_value="6.7.0",
                    description="Kernel <= 6.7.0",
                ),
                Prerequisite(
                    check_field="runtime.runc_version",
                    check_type="version_lte",
                    check_value="1.1.11",
                    confidence_if_absent=0.0,
                    description=(
                        "runc <= 1.1.11 is vulnerable. The runc version is NOT "
                        "observable from inside a container, so "
                        "confidence_if_absent=0.0: this CVE does not fire from "
                        "in-container enumeration unless a posture supplies a "
                        "known-vulnerable runc_version. Firing critical on every "
                        "docker container with kernel<=6.7 (regardless of the "
                        "actual runc version) was a false positive."
                    ),
                ),
            ],
            mitre_attack=["T1611"],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2024-21626",
                "https://snyk.io/blog/cve-2024-21626-runc-process-cwd-container-breakout/",
            ],
            cve="CVE-2024-21626",
            reliability=0.75,
            stealth=0.6,
            remediation="Update runc to >= 1.1.12",
            # The bug is a runc-side FD leak: when a container is started
            # with WORKDIR=/proc/self/fd/N, runc accidentally hands the
            # container a directory FD that points OUT of the container
            # root (into /run/containerd or /var/lib/docker). The exploit
            # primitive — a leaked host-filesystem FD — can be detected by
            # walking /proc/self/fd and matching readlink targets against
            # known runtime-state paths. A match = the runc FD leak is
            # actually present in THIS running container, not just the
            # version is vulnerable. No match = either the runc version
            # is patched, or the leak path differs on this runtime.
            verify_command=(
                "for fd in /proc/self/fd/*; do "
                't=$(readlink "$fd" 2>/dev/null); '
                'case "$t" in '
                "/run/containerd*|/run/runc*|/var/lib/docker*|/var/lib/containerd*|/run/docker*) "
                "exit 0;; "
                "esac; "
                "done; exit 1"
            ),
        ),
        EscapeTechnique(
            id="cve_2024_53104",
            name="USB Video Class OOB write",
            category=TechniqueCategory.KERNEL,
            severity=Severity.HIGH,
            description=(
                "Out-of-bounds write in the USB Video Class (UVC) driver "
                "allows local privilege escalation via crafted USB device."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="kernel.version",
                    check_type="kernel_lte",
                    check_value="6.12.0",
                    description="Kernel <= 6.12.0",
                ),
            ],
            mitre_attack=["T1068"],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2024-53104",
            ],
            cve="CVE-2024-53104",
            reliability=0.5,
            stealth=0.3,
            remediation="Update kernel to >= 6.12.1",
        ),
        EscapeTechnique(
            id="cve_2025_21756",
            name="vsock use-after-free",
            category=TechniqueCategory.KERNEL,
            severity=Severity.CRITICAL,
            description=(
                "Use-after-free in vsock transport allows arbitrary code "
                "execution in the kernel, enabling container escape."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="kernel.version",
                    check_type="kernel_lte",
                    check_value="6.14.0",
                    description="Kernel <= 6.14.0",
                ),
            ],
            mitre_attack=["T1068"],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2025-21756",
            ],
            cve="CVE-2025-21756",
            reliability=0.65,
            stealth=0.4,
            remediation="Update kernel to >= 6.14.1",
        ),
        EscapeTechnique(
            id="cve_2025_31133",
            name="runc Masked Path Race (CVE-2025-31133)",
            category=TechniqueCategory.KERNEL,
            severity=Severity.HIGH,
            description=(
                "Race condition in runc's masked path handling allows replacing /dev/null "
                "with a symlink during container init, causing runc to bind-mount an "
                "attacker-controlled target read-write, enabling writes to /proc and full escape."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="runtime.runc_version",
                    check_type="version_lte",
                    # Unknown runc version must stay BELOW min_confidence (0.3)
                    # so we don't claim this CVE when the version is unobserved
                    # — a known-vulnerable version still matches at
                    # confidence_if_met. (version_lte is no longer kernel-only
                    # capped, so this is the only suppression for the unknown case.)
                    check_value="1.2.7",
                    description="runc <= 1.2.7 is vulnerable",
                    confidence_if_absent=0.2,
                ),
            ],
            mitre_attack=["T1611"],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2025-31133"],
            cve="CVE-2025-31133",
            reliability=0.6,
            stealth=0.3,
            remediation="Upgrade runc to >= 1.2.8 or >= 1.3.3 or >= 1.4.0-rc3.",
        ),
        EscapeTechnique(
            id="cve_2025_52565",
            name="runc /dev/console Race (CVE-2025-52565)",
            category=TechniqueCategory.KERNEL,
            severity=Severity.HIGH,
            description=(
                "Race condition in runc's /dev/console bind mount allows redirection via "
                "symlink so runc mounts an unexpected target before protections are applied, "
                "exposing writable procfs access."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="runtime.runc_version",
                    check_type="version_lte",
                    # Unknown runc version must stay BELOW min_confidence (0.3)
                    # so we don't claim this CVE when the version is unobserved
                    # — a known-vulnerable version still matches at
                    # confidence_if_met. (version_lte is no longer kernel-only
                    # capped, so this is the only suppression for the unknown case.)
                    check_value="1.2.7",
                    description="runc <= 1.2.7 is vulnerable",
                    confidence_if_absent=0.2,
                ),
            ],
            mitre_attack=["T1611"],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2025-52565"],
            cve="CVE-2025-52565",
            reliability=0.5,
            stealth=0.3,
            remediation="Upgrade runc to >= 1.2.8 or >= 1.3.3 or >= 1.4.0-rc3.",
        ),
        EscapeTechnique(
            id="cve_2025_52881",
            name="runc procfs Write Redirect (CVE-2025-52881)",
            category=TechniqueCategory.KERNEL,
            severity=Severity.HIGH,
            description=(
                "runc can be tricked into performing writes to /proc that are redirected "
                "to attacker-controlled targets, bypassing LSM relabel protections. Turns "
                "ordinary runc writes into arbitrary writes to files like /proc/sysrq-trigger."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="runtime.runc_version",
                    check_type="version_lte",
                    # Unknown runc version must stay BELOW min_confidence (0.3)
                    # so we don't claim this CVE when the version is unobserved
                    # — a known-vulnerable version still matches at
                    # confidence_if_met. (version_lte is no longer kernel-only
                    # capped, so this is the only suppression for the unknown case.)
                    check_value="1.2.7",
                    description="runc <= 1.2.7 is vulnerable",
                    confidence_if_absent=0.2,
                ),
            ],
            mitre_attack=["T1611"],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2025-52881"],
            cve="CVE-2025-52881",
            reliability=0.6,
            stealth=0.4,
            remediation="Upgrade runc to >= 1.2.8 or >= 1.3.3 or >= 1.4.0-rc3.",
        ),
        EscapeTechnique(
            id="cve_2024_23651",
            name="BuildKit Cache Race (CVE-2024-23651)",
            category=TechniqueCategory.KERNEL,
            severity=Severity.CRITICAL,
            description=(
                "TOCTOU race condition in BuildKit when mounting cache volumes at build time "
                "allows escalation from disk access to full host root command execution. "
                "Note: BuildKit is a build-time tool — this only applies to pods that can "
                "invoke `docker build` or `buildctl` against a vulnerable BuildKit daemon. "
                "Runtime-only workloads are not affected."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="runtime.runtime",
                    check_type="regex",
                    check_value="docker|containerd",
                    description="Requires Docker or containerd runtime",
                    confidence_if_absent=0.0,
                ),
                Prerequisite(
                    check_field="network.can_reach_docker_sock",
                    check_type="equals",
                    check_value=True,
                    description=(
                        "BuildKit exploitation requires reachability to the "
                        "build daemon socket (Docker / BuildKit). Pods without "
                        "socket access cannot invoke `docker build` and so "
                        "cannot trigger this CVE."
                    ),
                    confidence_if_absent=0.1,
                ),
            ],
            mitre_attack=["T1611", "T1068"],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2024-23651"],
            cve="CVE-2024-23651",
            reliability=0.5,
            stealth=0.3,
            remediation="Upgrade BuildKit to >= 0.12.5 and Docker to >= 25.0.2.",
            # BuildKit exploitation requires reachability to either the
            # Docker socket or a dedicated BuildKit daemon socket.
            verify_command="[ -S /var/run/docker.sock ] || [ -S /run/buildkit/buildkitd.sock ] || [ -S /var/run/buildkit/buildkitd.sock ]",
        ),
        EscapeTechnique(
            id="cve_2024_23652",
            name="BuildKit Path Traversal (CVE-2024-23652)",
            category=TechniqueCategory.KERNEL,
            severity=Severity.CRITICAL,
            description=(
                "Path traversal vulnerability in BuildKit allows deletion of arbitrary files "
                "on the host during the image building process. Same scope as CVE-2024-23651: "
                "build-time only, requires access to a BuildKit daemon."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="runtime.runtime",
                    check_type="regex",
                    check_value="docker|containerd",
                    description="Requires Docker or containerd runtime",
                    confidence_if_absent=0.0,
                ),
                Prerequisite(
                    check_field="network.can_reach_docker_sock",
                    check_type="equals",
                    check_value=True,
                    description=(
                        "BuildKit exploitation requires reachability to the "
                        "build daemon socket. See CVE-2024-23651 for scope notes."
                    ),
                    confidence_if_absent=0.1,
                ),
            ],
            mitre_attack=["T1611", "T1565"],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2024-23652"],
            cve="CVE-2024-23652",
            reliability=0.6,
            stealth=0.2,
            remediation="Upgrade BuildKit to >= 0.12.5 and Docker to >= 25.0.2.",
            # Same precondition as CVE-2024-23651 — BuildKit daemon reachable.
            verify_command="[ -S /var/run/docker.sock ] || [ -S /run/buildkit/buildkitd.sock ] || [ -S /var/run/buildkit/buildkitd.sock ]",
        ),
        EscapeTechnique(
            id="cve_2024_23653",
            name="BuildKit Privileged Exec (CVE-2024-23653)",
            category=TechniqueCategory.KERNEL,
            severity=Severity.CRITICAL,
            description=(
                "BuildKit's interactive containers API fails to validate "
                "security.insecure entitlement, letting a malicious build run a "
                "privileged container and escape to the host. Same scope as the "
                "other Leaky Vessels BuildKit CVEs: build-time only, requires "
                "access to a vulnerable BuildKit daemon."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="runtime.runtime",
                    check_type="regex",
                    check_value="docker|containerd",
                    description="Requires Docker or containerd runtime",
                    confidence_if_absent=0.0,
                ),
                Prerequisite(
                    check_field="network.can_reach_docker_sock",
                    check_type="equals",
                    check_value=True,
                    description=(
                        "BuildKit exploitation requires reachability to the "
                        "build daemon socket. See CVE-2024-23651 for scope notes."
                    ),
                    confidence_if_absent=0.1,
                ),
            ],
            mitre_attack=["T1611", "T1068"],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2024-23653"],
            cve="CVE-2024-23653",
            reliability=0.55,
            stealth=0.3,
            remediation="Upgrade BuildKit to >= 0.12.5 and Docker to >= 25.0.2.",
            # Same precondition as CVE-2024-23651 — BuildKit daemon reachable.
            verify_command="[ -S /var/run/docker.sock ] || [ -S /run/buildkit/buildkitd.sock ] || [ -S /var/run/buildkit/buildkitd.sock ]",
        ),
        # ── RUNTIME (15) ─────────────────────────────────────────────
        EscapeTechnique(
            id="host_pid_namespace",
            name="Shared host PID namespace",
            category=TechniqueCategory.RUNTIME,
            severity=Severity.HIGH,
            description=(
                "The container shares the host PID namespace (hostPID:true), so "
                "it sees every host process. Even without CAP_SYS_PTRACE this "
                "exposes host process command lines and /proc/<pid>/environ "
                "(secrets, tokens) and allows signalling host processes; "
                "combined with CAP_SYS_PTRACE it escalates to code injection "
                "into host processes (see cap_sys_ptrace)."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="namespaces.pid",
                    check_type="equals",
                    check_value=False,
                    description="PID namespace must be shared with host (hostPID:true)",
                    confidence_if_absent=0.0,
                ),
            ],
            mitre_attack=["T1057", "T1611"],
            references=[
                "https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation",
            ],
            reliability=0.7,
            stealth=0.5,
            remediation="--pid=container (do not set hostPID: true)",
            cli_flag="--pid=container",
            # PID 2 is kthreadd, a host kernel thread. It is visible only when
            # the PID namespace is shared with the host — in a private container
            # PID namespace /proc/2 is absent or is some container process. Seeing
            # kthreadd genuinely proves the shared-host-PID primitive.
            verify_command="grep -q kthreadd /proc/2/comm 2>/dev/null",
        ),
        EscapeTechnique(
            id="k8s_service_account",
            name="K8s SA token privilege escalation",
            category=TechniqueCategory.RUNTIME,
            severity=Severity.HIGH,
            description=(
                "Kubernetes service account token is mounted and can be used "
                "to query the API server for secrets, pods, and more."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="credentials.service_account_token",
                    check_type="equals",
                    check_value=True,
                    description="Service account token must be present",
                ),
                Prerequisite(
                    check_field="runtime.orchestrator",
                    check_type="equals",
                    check_value="kubernetes",
                    description="Must be running under Kubernetes",
                ),
            ],
            mitre_attack=["T1078"],
            references=[
                "https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/",
            ],
            reliability=0.8,
            stealth=0.7,
            remediation="automountServiceAccountToken: false",
            verify_command="[ -r /var/run/secrets/kubernetes.io/serviceaccount/token ]",
        ),
        EscapeTechnique(
            id="k8s_kubelet_api",
            name="Direct kubelet API access",
            category=TechniqueCategory.RUNTIME,
            severity=Severity.HIGH,
            description=(
                "Direct access to the kubelet API (port 10250) allows executing commands in any pod on the node."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="runtime.orchestrator",
                    check_type="equals",
                    check_value="kubernetes",
                    description="Must be running under Kubernetes",
                ),
                Prerequisite(
                    check_field="network.listening_ports",
                    check_type="not_empty",
                    confidence_if_absent=0.3,
                    description="Network ports accessible (kubelet on 10250)",
                ),
            ],
            mitre_attack=["T1106"],
            references=[
                "https://book.hacktricks.xyz/pentesting/pentesting-kubernetes/enumeration-from-a-pod",
            ],
            reliability=0.7,
            stealth=0.5,
            remediation="Enable kubelet authentication and authorization",
            # Probes kubelet on the node's default-gateway IP at port 10250.
            # `curl -k` accepts the kubelet's self-signed cert; `--max-time 2`
            # caps probe time. Returns 0 on any HTTP response (kubelet
            # reachable from this pod, indicating either flat network or
            # missing NetworkPolicy isolation).
            verify_command='command -v curl >/dev/null 2>&1 && gw=$(awk \'$2 == "00000000" {printf "%d.%d.%d.%d", "0x"substr($3,7,2), "0x"substr($3,5,2), "0x"substr($3,3,2), "0x"substr($3,1,2); exit}\' /proc/self/net/route 2>/dev/null) && [ -n "$gw" ] && curl -ksf --max-time 2 "https://${gw}:10250/healthz" >/dev/null 2>&1',
        ),
        EscapeTechnique(
            id="k8s_etcd_access",
            name="Direct etcd access",
            category=TechniqueCategory.RUNTIME,
            severity=Severity.CRITICAL,
            description=(
                "Direct access to etcd (port 2379) exposes all Kubernetes "
                "secrets, configurations, and cluster state. In a properly "
                "configured cluster etcd is on the control plane only and "
                "isolated from workload pods — this technique requires the "
                "enumerator to confirm TCP reachability to 2379 from inside "
                "the pod, not merely that the workload runs in Kubernetes."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="runtime.orchestrator",
                    check_type="equals",
                    check_value="kubernetes",
                    description="Must be running under Kubernetes",
                    confidence_if_absent=0.0,
                ),
                Prerequisite(
                    check_field="network.can_reach_etcd",
                    check_type="equals",
                    check_value=True,
                    description=(
                        "etcd:2379 must be TCP-reachable from this pod. "
                        "When the enumerator hasn't probed (field is None), "
                        "we degrade to confidence_if_absent rather than 0 so "
                        "the technique stays visible at low priority."
                    ),
                    confidence_if_absent=0.2,
                ),
            ],
            mitre_attack=["T1005"],
            references=[
                "https://book.hacktricks.xyz/pentesting/pentesting-kubernetes/kubernetes-enumeration",
            ],
            reliability=0.6,
            stealth=0.3,
            remediation="Restrict etcd access with TLS client certs",
            # Probes etcd's well-known cluster DNS name + control-plane IP
            # on port 2379. Reachability from a workload pod implies a
            # misconfigured NetworkPolicy (etcd should never be on the
            # pod network in a hardened cluster).
            verify_command='command -v curl >/dev/null 2>&1 && (curl -ksf --max-time 2 "https://etcd.kube-system.svc:2379/version" >/dev/null 2>&1 || ([ -n "$KUBERNETES_SERVICE_HOST" ] && curl -ksf --max-time 2 "https://${KUBERNETES_SERVICE_HOST}:2379/version" >/dev/null 2>&1))',
        ),
        EscapeTechnique(
            id="docker_api_unauth",
            name="Unauthenticated Docker remote API",
            category=TechniqueCategory.RUNTIME,
            severity=Severity.CRITICAL,
            description=(
                "Docker daemon API is exposed without authentication, allowing "
                "full control over all containers and the host."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="network.can_reach_docker_sock",
                    check_type="equals",
                    check_value=True,
                    description="Docker socket/API must be reachable",
                ),
            ],
            mitre_attack=["T1106"],
            references=[
                "https://book.hacktricks.xyz/network-services-pentesting/2375-pentesting-docker",
            ],
            reliability=0.9,
            stealth=0.3,
            remediation="Enable TLS on Docker daemon socket",
            # Probes both the unix socket and the TCP 2375 unauth port.
            # Either reachable means Docker API is exposed without auth.
            verify_command="command -v curl >/dev/null 2>&1 && (curl -sf --max-time 2 --unix-socket /var/run/docker.sock http://localhost/_ping >/dev/null 2>&1 || curl -sf --max-time 2 http://localhost:2375/_ping >/dev/null 2>&1)",
        ),
        EscapeTechnique(
            id="containerd_shim_escape",
            name="containerd shim vulnerability",
            category=TechniqueCategory.RUNTIME,
            severity=Severity.HIGH,
            description=(
                "Exploit vulnerabilities in containerd-shim to gain host "
                "access via the container runtime interface. Most public "
                "containerd-shim CVEs (e.g. CVE-2020-15257) require both an "
                "unpatched containerd AND reachability to the shim's abstract "
                "Unix socket — flag as low-priority opportunistic match unless "
                "the containerd version is independently verified vulnerable."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="runtime.runtime",
                    check_type="equals",
                    check_value="containerd",
                    description="Runtime must be containerd",
                    confidence_if_absent=0.0,
                ),
                Prerequisite(
                    check_field="network.can_reach_containerd_sock",
                    check_type="equals",
                    check_value=True,
                    description=(
                        "Need reachability to containerd's UNIX socket or the "
                        "shim's abstract socket to trigger known exploits"
                    ),
                    confidence_if_absent=0.1,
                ),
            ],
            mitre_attack=["T1611"],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2020-15257",
            ],
            reliability=0.5,
            stealth=0.4,
            remediation="Update containerd to latest",
            # containerd shim exploit requires reachability to either the
            # containerd UNIX socket or the shim's abstract socket.
            verify_command="[ -S /run/containerd/containerd.sock ] || [ -S /var/run/containerd/containerd.sock ]",
        ),
        EscapeTechnique(
            id="runc_cve_2019_5736",
            name="runc overwrite (/proc/self/exe)",
            category=TechniqueCategory.RUNTIME,
            severity=Severity.CRITICAL,
            description=(
                "Overwrite the host runc binary via /proc/self/exe to gain "
                "code execution on the host when runc is next invoked. "
                "Patched in runc >= 1.0.0-rc7 (Feb 2019) — current Docker / "
                "containerd builds ship patched runc. Only flag when runc "
                "version is independently verified vulnerable."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="runtime.runtime",
                    check_type="regex",
                    check_value="^(docker|containerd)$",
                    description="Runtime uses runc (Docker or containerd)",
                    confidence_if_absent=0.0,
                ),
                Prerequisite(
                    check_field="runtime.runc_version",
                    check_type="version_lte",
                    check_value="1.0.0-rc6",
                    description=(
                        "runc version must be known AND <= 1.0.0-rc6. When "
                        "the enumerator can't detect runc version (field is "
                        "None), we drop the match entirely rather than fire "
                        "speculatively — modern container runtimes (Docker "
                        ">= 18.09.2, kind, EKS, GKE, AKS) ship patched runc. "
                        "Improving runc version detection in the enumerator "
                        "is tracked separately."
                    ),
                    confidence_if_absent=0.0,
                ),
            ],
            mitre_attack=["T1611"],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2019-5736",
                "https://blog.dragonsector.pl/2019/02/cve-2019-5736-escape-from-docker-and.html",
            ],
            cve="CVE-2019-5736",
            reliability=0.65,
            stealth=0.3,
            remediation="Update runc to >= 1.0.0-rc6",
        ),
        EscapeTechnique(
            id="cloud_metadata_ssrf",
            name="Cloud metadata service access",
            category=TechniqueCategory.RUNTIME,
            severity=Severity.HIGH,
            description=(
                "Cloud instance metadata endpoint (169.254.169.254) is "
                "reachable, potentially exposing IAM credentials and secrets."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="network.can_reach_metadata",
                    check_type="equals",
                    check_value=True,
                    description="Metadata endpoint must be reachable",
                ),
            ],
            # T1552.005 is the specific sub-technique for cloud instance
            # metadata API abuse (vs. the parent T1552 "Unsecured Credentials").
            mitre_attack=["T1552.005"],
            references=[
                "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html",
            ],
            reliability=0.9,
            stealth=0.8,
            remediation="Block 169.254.169.254 via network policy",
            verify_command="command -v curl >/dev/null 2>&1 && curl -sf --max-time 2 http://169.254.169.254/ >/dev/null",
        ),
        EscapeTechnique(
            id="lsm_apparmor_unconfined",
            name="AppArmor unconfined profile",
            category=TechniqueCategory.RUNTIME,
            severity=Severity.HIGH,
            description=(
                "Container runs without AppArmor confinement, removing "
                "mandatory access control restrictions on system calls "
                "and file access."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="security.apparmor",
                    check_type="equals",
                    check_value="unconfined",
                    description=(
                        "AppArmor must be KNOWN-unconfined. A null/unknown value "
                        "(enumerator could not read the profile, or the PodSpec "
                        "importer cannot determine it) is NOT treated as "
                        "unconfined — that produced a false positive on every "
                        "static/unknown posture."
                    ),
                ),
            ],
            mitre_attack=["T1611"],
            references=[
                "https://docs.docker.com/engine/security/apparmor/",
            ],
            reliability=0.7,
            stealth=0.5,
            remediation="Apply AppArmor profile: --security-opt apparmor=docker-default",
            cli_flag="--security-opt apparmor=docker-default",
            verify_command="[ ! -f /proc/self/attr/current ] || grep -q 'unconfined' /proc/self/attr/current 2>/dev/null",
        ),
        EscapeTechnique(
            id="lsm_selinux_unconfined",
            name="SELinux disabled/unconfined",
            category=TechniqueCategory.RUNTIME,
            severity=Severity.LOW,
            description=(
                "SELinux is disabled or set to unconfined, removing the "
                "mandatory-access-control layer that would otherwise restrict "
                "container access to host resources. This is host-posture "
                "context, not a per-pod escape — it amplifies other primitives "
                "(privileged, capability adds, hostPath mounts) by removing "
                "the LSM safety net. On hosts with no SELinux at all (WSL2, "
                "Docker Desktop, most non-RHEL distros) this fires on every "
                "scan and is informational; pair with another finding for "
                "actionable risk."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="security.selinux",
                    check_type="equals",
                    check_value=None,
                    description="SELinux must be disabled or unconfined",
                    confidence_if_absent=0.0,
                ),
                Prerequisite(
                    check_field="runtime.privileged",
                    check_type="equals",
                    check_value=True,
                    description=(
                        "Only meaningful when combined with another escape "
                        "primitive — pure absence of SELinux on a hardened "
                        "non-privileged pod doesn't yield host access"
                    ),
                    confidence_if_absent=0.1,
                ),
            ],
            mitre_attack=["T1611"],
            references=[
                "https://docs.docker.com/engine/security/selinux/",
            ],
            reliability=0.7,
            stealth=0.5,
            remediation="Enable SELinux: --security-opt label=type:container_t",
            cli_flag="--security-opt label=type:container_t",
            verify_command="[ ! -f /sys/fs/selinux/enforce ] || ! grep -q '1' /sys/fs/selinux/enforce 2>/dev/null",
        ),
        EscapeTechnique(
            id="k8s_node_proxy",
            name="Kubelet node proxy abuse",
            category=TechniqueCategory.RUNTIME,
            severity=Severity.HIGH,
            description=("Abuse kubelet proxy endpoint to forward traffic to other pods and services on the node."),
            prerequisites=[
                Prerequisite(
                    check_field="runtime.orchestrator",
                    check_type="equals",
                    check_value="kubernetes",
                    description="Must be running under Kubernetes",
                ),
                Prerequisite(
                    check_field="credentials.service_account_token",
                    check_type="equals",
                    check_value=True,
                    description="Service account token must be present",
                ),
            ],
            mitre_attack=["T1090"],
            references=[
                "https://kubernetes.io/docs/reference/command-line-tools-reference/kubelet/",
            ],
            reliability=0.65,
            stealth=0.6,
            remediation="Restrict kubelet proxy access via RBAC",
            # Kubelet proxy abuse requires a usable SA token AND curl-class
            # tooling to make the API call. Probes both prerequisites.
            verify_command="[ -r /var/run/secrets/kubernetes.io/serviceaccount/token ] && command -v curl >/dev/null 2>&1",
        ),
        EscapeTechnique(
            id="cve_2025_23266",
            name="NVIDIAScape OCI Hook Escape (CVE-2025-23266)",
            category=TechniqueCategory.RUNTIME,
            severity=Severity.CRITICAL,
            description=(
                "Container escape via LD_PRELOAD manipulation of NVIDIA Container Toolkit "
                "OCI hooks. The createContainer hook inherits environment variables from the "
                "container image, allowing a malicious container to force the privileged "
                "nvidia-ctk process to load an arbitrary shared library."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="gpu.nvidia_devices",
                    check_type="not_empty",
                    check_value=None,
                    description="NVIDIA GPU devices must be present",
                ),
                Prerequisite(
                    check_field="gpu.nvidia_toolkit_version",
                    check_type="version_lte",
                    check_value="1.17.7",
                    description="NVIDIA Container Toolkit <= 1.17.7 is vulnerable",
                    confidence_if_absent=0.3,
                ),
            ],
            mitre_attack=["T1611", "T1068"],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2025-23266"],
            cve="CVE-2025-23266",
            reliability=0.9,
            stealth=0.4,
            remediation="Upgrade NVIDIA Container Toolkit to >= 1.17.8 or GPU Operator to >= 25.3.1.",
            # NVIDIAScape needs the NVIDIA Container Toolkit to be the
            # one launching this container. Probe for NVIDIA device
            # presence — the necessary precondition for the OCI hook
            # to have run.
            verify_command="[ -c /dev/nvidiactl ] || [ -c /dev/nvidia0 ] || [ -c /dev/nvidia-uvm ]",
        ),
        EscapeTechnique(
            id="cve_2024_0132",
            name="NVIDIA Container Toolkit Escape (CVE-2024-0132)",
            category=TechniqueCategory.RUNTIME,
            severity=Severity.CRITICAL,
            description=(
                "Vulnerability in NVIDIA Container Toolkit allows a specially crafted "
                "container image to gain access to the host filesystem, enabling full "
                "host takeover."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="gpu.nvidia_devices",
                    check_type="not_empty",
                    check_value=None,
                    description="NVIDIA GPU devices must be present",
                ),
                Prerequisite(
                    check_field="gpu.nvidia_toolkit_version",
                    check_type="version_lte",
                    check_value="1.16.1",
                    description="NVIDIA Container Toolkit <= 1.16.1 is vulnerable",
                    confidence_if_absent=0.3,
                ),
            ],
            mitre_attack=["T1611"],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2024-0132"],
            cve="CVE-2024-0132",
            reliability=0.8,
            stealth=0.3,
            remediation="Upgrade NVIDIA Container Toolkit to >= 1.16.2.",
            # Same precondition as CVE-2025-23266: NVIDIA Container Toolkit
            # must have been the launcher. Probe device presence.
            verify_command="[ -c /dev/nvidiactl ] || [ -c /dev/nvidia0 ] || [ -c /dev/nvidia-uvm ]",
        ),
        EscapeTechnique(
            id="cve_2024_0133",
            name="NVIDIA Container Toolkit Symlink Escape (CVE-2024-0133)",
            category=TechniqueCategory.RUNTIME,
            severity=Severity.HIGH,
            description=(
                "Companion to CVE-2024-0132: a crafted container image can use a "
                "symlink to cause the NVIDIA Container Toolkit to create files on "
                "the host filesystem, enabling tampering that escalates to host "
                "compromise. Same scope — only GPU workloads launched by the "
                "vulnerable toolkit are affected."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="gpu.nvidia_devices",
                    check_type="not_empty",
                    check_value=None,
                    description="NVIDIA GPU devices must be present",
                ),
                Prerequisite(
                    check_field="gpu.nvidia_toolkit_version",
                    check_type="version_lte",
                    check_value="1.16.1",
                    description="NVIDIA Container Toolkit <= 1.16.1 is vulnerable",
                    confidence_if_absent=0.3,
                ),
            ],
            mitre_attack=["T1611"],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2024-0133"],
            cve="CVE-2024-0133",
            reliability=0.6,
            stealth=0.4,
            remediation="Upgrade NVIDIA Container Toolkit to >= 1.16.2.",
            # Precondition only: device presence proves a GPU workload, not the
            # toolkit version — classified in _PRECONDITION_ONLY_VERIFIERS.
            verify_command="[ -c /dev/nvidiactl ] || [ -c /dev/nvidia0 ] || [ -c /dev/nvidia-uvm ]",
        ),
        EscapeTechnique(
            id="cve_2025_1974",
            name="IngressNightmare Admission Webhook RCE (CVE-2025-1974)",
            category=TechniqueCategory.RUNTIME,
            severity=Severity.CRITICAL,
            description=(
                "Unauthenticated RCE in ingress-nginx admission webhook. Any pod on the "
                "cluster network can exploit configuration injection to gain access to all "
                "secrets across all namespaces and achieve full cluster takeover. "
                "Requires ingress-nginx to actually be deployed in the cluster — many "
                "clusters use Traefik, HAProxy, Cilium, or no ingress controller at all."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="runtime.orchestrator",
                    check_type="equals",
                    check_value="kubernetes",
                    description="Must be running in Kubernetes",
                    confidence_if_absent=0.0,
                ),
                Prerequisite(
                    check_field="kubernetes.cluster_components",
                    check_type="contains",
                    check_value="ingress-nginx",
                    description=(
                        "ingress-nginx controller must be deployed in the cluster. "
                        "When the enumerator can't query the API (no SA token, no "
                        "list-pods permission), confidence_if_absent keeps the "
                        "technique visible at low priority rather than dropping it."
                    ),
                    confidence_if_absent=0.2,
                ),
            ],
            mitre_attack=["T1611", "T1190"],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2025-1974"],
            cve="CVE-2025-1974",
            reliability=0.7,
            stealth=0.3,
            remediation="Upgrade ingress-nginx to >= 1.12.1 or >= 1.11.5. Restrict network access to admission webhook.",
            # IngressNightmare requires the ingress-nginx admission webhook
            # to be network-reachable from the container. Probe DNS for
            # the canonical webhook service name in its default namespace
            # — if it resolves, the cluster has ingress-nginx installed
            # AND the pod's NetworkPolicy permits east-west DNS to it.
            # Tries both `getent hosts` (glibc) and `nslookup` (busybox /
            # musl) so the probe works in Alpine-based containers too.
            verify_command=(
                "getent hosts "
                "ingress-nginx-controller-admission.ingress-nginx.svc.cluster.local "
                "2>/dev/null || "
                "nslookup "
                "ingress-nginx-controller-admission.ingress-nginx.svc.cluster.local "
                "2>/dev/null | grep -qi address"
            ),
        ),
        EscapeTechnique(
            id="cve_2025_9074",
            name="Docker Desktop Container Escape (CVE-2025-9074)",
            category=TechniqueCategory.RUNTIME,
            severity=Severity.CRITICAL,
            description=(
                "Critical container escape in Docker Desktop for Windows and macOS allowing "
                "containers to escape isolation and compromise the host system."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="runtime.runtime",
                    check_type="equals",
                    check_value="docker",
                    description="Requires Docker runtime",
                ),
                Prerequisite(
                    check_field="runtime.runtime_version",
                    check_type="version_lte",
                    check_value="4.44.2",
                    confidence_if_absent=0.0,
                    description=(
                        "Docker Desktop <= 4.44.2 is vulnerable (fixed in 4.44.3). "
                        "The host Docker Desktop version is NOT observable from "
                        "inside a container, so confidence_if_absent=0.0: this CVE "
                        "does NOT fire from default in-container enumeration "
                        "(claiming it on every Docker container regardless of "
                        "version was a false positive). It fires only when a "
                        "posture supplies a known-vulnerable runtime_version."
                    ),
                ),
            ],
            mitre_attack=["T1611"],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2025-9074"],
            cve="CVE-2025-9074",
            reliability=0.6,
            stealth=0.3,
            remediation="Upgrade Docker Desktop to the latest patched version.",
            # Docker Desktop-specific markers: /run/host-services mount
            # (Docker Desktop's host bridge) or 'docker-desktop' in the
            # kernel version string (LinuxKit-based VM).
            verify_command="[ -d /run/host-services ] || grep -q -i 'docker.desktop\\|linuxkit' /proc/version 2>/dev/null",
        ),
        # ── COMBINATORIAL (6) ────────────────────────────────────────
        EscapeTechnique(
            id="cap_sys_admin_no_seccomp",
            name="SYS_ADMIN + no seccomp — multiple paths",
            category=TechniqueCategory.COMBINATORIAL,
            severity=Severity.CRITICAL,
            description=(
                "CAP_SYS_ADMIN without seccomp filtering enables mount, "
                "cgroup, BPF, and numerous other kernel-level escape paths."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="capabilities.effective",
                    check_type="contains",
                    check_value="CAP_SYS_ADMIN",
                    description="Requires CAP_SYS_ADMIN capability",
                ),
                Prerequisite(
                    check_field="security.seccomp",
                    check_type="equals",
                    check_value="disabled",
                    description="Seccomp must be disabled",
                ),
            ],
            mitre_attack=["T1611"],
            references=[
                "https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/",
            ],
            reliability=0.95,
            stealth=0.3,
            remediation="--cap-drop=ALL --security-opt seccomp=default",
            cli_flag="--cap-drop=SYS_ADMIN",
            # Combination: CAP_SYS_ADMIN present (CapEff ends in 'ffffff')
            # AND seccomp disabled (Seccomp: 0 in /proc/self/status).
            verify_command="grep -q 'CapEff:.*[fF][fF][fF][fF][fF][fF]' /proc/self/status 2>/dev/null && grep -qE 'Seccomp:[[:space:]]*0' /proc/self/status 2>/dev/null",
        ),
        EscapeTechnique(
            id="privileged_docker_sock",
            name="Privileged + docker.sock — trivial escape",
            category=TechniqueCategory.COMBINATORIAL,
            severity=Severity.CRITICAL,
            description=(
                "A privileged container with Docker socket access provides trivial, near-guaranteed escape to the host."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="runtime.privileged",
                    check_type="equals",
                    check_value=True,
                    description="Container must be running in privileged mode",
                ),
                Prerequisite(
                    check_field="network.can_reach_docker_sock",
                    check_type="equals",
                    check_value=True,
                    description="Docker socket must be reachable",
                ),
            ],
            mitre_attack=["T1611"],
            references=[
                "https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation",
            ],
            reliability=0.98,
            stealth=0.1,
            remediation="Never run privileged with Docker socket",
            # Combination: writable Docker socket AND the all-caps marker
            # (CapEff:.*ffffff) of a privileged container.
            verify_command="[ -S /var/run/docker.sock ] && [ -w /var/run/docker.sock ] && grep -q 'CapEff:.*[fF][fF][fF][fF][fF][fF]' /proc/self/status 2>/dev/null",
        ),
        EscapeTechnique(
            id="cap_net_raw_metadata",
            name="NET_RAW + metadata access — credential theft",
            category=TechniqueCategory.COMBINATORIAL,
            severity=Severity.HIGH,
            description=(
                "CAP_NET_RAW with metadata endpoint access enables ARP "
                "spoofing to intercept cloud credentials from other pods."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="capabilities.effective",
                    check_type="contains",
                    check_value="CAP_NET_RAW",
                    description="Requires CAP_NET_RAW capability",
                ),
                Prerequisite(
                    check_field="network.can_reach_metadata",
                    check_type="equals",
                    check_value=True,
                    description="Metadata endpoint must be reachable",
                ),
            ],
            # T1557 (Adversary-in-the-Middle) for the ARP-spoof primitive;
            # T1552.005 (Cloud Instance Metadata API) for the goal —
            # intercepting credentials from the IMDS reply path.
            mitre_attack=["T1557", "T1552.005"],
            references=[
                "https://blog.champtar.fr/Metadata_MITM_root_EKS_GKE/",
            ],
            reliability=0.85,
            stealth=0.7,
            remediation="--cap-drop=NET_RAW, block metadata endpoint",
            cli_flag="--cap-drop=NET_RAW",
            # Combination: metadata endpoint reachable AND a network-capable
            # binary available to actually mount the ARP-spoof / IMDS read.
            verify_command="command -v curl >/dev/null 2>&1 && curl -sf --max-time 2 http://169.254.169.254/ >/dev/null 2>&1",
        ),
        EscapeTechnique(
            id="writable_proc_privileged",
            name="Writable procfs + privileged — kernel manipulation",
            category=TechniqueCategory.COMBINATORIAL,
            severity=Severity.CRITICAL,
            description=(
                "Privileged container with writable /proc/sys/kernel allows "
                "core_pattern abuse and other kernel parameter manipulation."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="runtime.privileged",
                    check_type="equals",
                    check_value=True,
                    description="Container must be running in privileged mode",
                ),
                Prerequisite(
                    check_field="writable_paths",
                    check_type="contains",
                    check_value="/proc/sys/kernel/core_pattern",
                    description="/proc/sys/kernel/core_pattern must be writable",
                ),
            ],
            mitre_attack=["T1611"],
            references=[
                "https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation",
            ],
            reliability=0.9,
            stealth=0.2,
            remediation="--privileged=false, mount /proc read-only",
            cli_flag="--privileged=false",
            # Combination: writable core_pattern AND CAP_SYS_ADMIN (the
            # kernel rejects writes to /proc/sys/kernel/* without it,
            # even when DAC allows). Open-for-append, no actual write.
            verify_command="exec 3>>/proc/sys/kernel/core_pattern 2>/dev/null && exec 3>&- && grep -q 'CapEff:.*[fF][fF][fF][fF][fF][fF]' /proc/self/status 2>/dev/null",
        ),
        EscapeTechnique(
            id="user_ns_kernel_exploit",
            name="User namespace + kernel CVE — unprivileged exploit",
            category=TechniqueCategory.COMBINATORIAL,
            severity=Severity.HIGH,
            description=(
                "User namespaces combined with a vulnerable kernel allow "
                "unprivileged users to trigger kernel exploits for escape."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="namespaces.user",
                    check_type="equals",
                    check_value=True,
                    description="User namespaces must be enabled",
                ),
                Prerequisite(
                    check_field="kernel.version",
                    check_type="kernel_lte",
                    check_value="5.16.11",
                    description="Kernel <= 5.16.11 (vulnerable range)",
                ),
            ],
            mitre_attack=["T1068"],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2022-0185",
            ],
            reliability=0.6,
            stealth=0.6,
            remediation="Update kernel, disable user namespaces if not needed",
            # `unshare -U -r` attempts user-namespace creation with the
            # invoking uid mapped to root inside. Returns 0 if the kernel
            # permits unprivileged user-ns creation — the prerequisite
            # for triggering kernel exploits from an unprivileged context.
            # Non-destructive: spawns and exits true immediately.
            verify_command="command -v unshare >/dev/null 2>&1 && unshare -U -r true 2>/dev/null",
        ),
        EscapeTechnique(
            id="cap_sys_admin_apparmor_unconfined",
            name="SYS_ADMIN + no AppArmor — unrestricted",
            category=TechniqueCategory.COMBINATORIAL,
            severity=Severity.CRITICAL,
            description=(
                "CAP_SYS_ADMIN without AppArmor confinement removes the last "
                "safety net, enabling unrestricted kernel feature abuse."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="capabilities.effective",
                    check_type="contains",
                    check_value="CAP_SYS_ADMIN",
                    description="Requires CAP_SYS_ADMIN capability",
                ),
                Prerequisite(
                    check_field="security.apparmor",
                    check_type="equals",
                    check_value=None,
                    description="AppArmor must not be set (unconfined)",
                ),
            ],
            mitre_attack=["T1611"],
            references=[
                "https://docs.docker.com/engine/security/apparmor/",
            ],
            reliability=0.9,
            stealth=0.3,
            remediation="Apply AppArmor profile: --security-opt apparmor=docker-default",
            cli_flag="--security-opt apparmor=docker-default",
            # Combination: CAP_SYS_ADMIN held AND no AppArmor profile
            # (unconfined or AppArmor not loaded on host).
            verify_command="grep -q 'CapEff:.*[fF][fF][fF][fF][fF][fF]' /proc/self/status 2>/dev/null && ([ ! -f /proc/self/attr/current ] || grep -q 'unconfined' /proc/self/attr/current 2>/dev/null)",
        ),
        # ── INFO_DISCLOSURE (4) ───────────────────────────────────────
        EscapeTechnique(
            id="env_secret_leak",
            name="Secrets in environment variables",
            category=TechniqueCategory.INFO_DISCLOSURE,
            severity=Severity.MEDIUM,
            description=(
                "Sensitive credentials found in environment variables, accessible to any process in the container."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="credentials.environment_secrets",
                    check_type="not_empty",
                    description="Environment secrets must be present",
                ),
            ],
            # Env-var secrets are awkward to sub-categorize: T1552.001 is
            # "Credentials In Files" (close but not quite — env vars live
            # in /proc/<pid>/environ which is a file-like view of process
            # memory). Use it as the closest match, plus the parent T1552.
            mitre_attack=["T1552", "T1552.001"],
            references=[
                "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html",
            ],
            reliability=0.95,
            stealth=0.9,
            remediation="Use secrets management (Vault, K8s secrets), not env vars",
            # Greps /proc/self/environ (NUL-separated env var blob) for
            # the common secret-pattern var names. Uses tr to convert NULs
            # to newlines so grep matches per-variable. Confirms an
            # in-process secret-shaped env var is present right now.
            verify_command="[ -r /proc/self/environ ] && tr '\\0' '\\n' < /proc/self/environ | grep -qiE '^(.*(PASSWORD|SECRET|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY|CREDENTIAL|AWS_SECRET|AWS_ACCESS|GH[_-]?TOKEN|GITHUB[_-]?TOKEN))='",
        ),
        EscapeTechnique(
            id="cloud_metadata_creds",
            name="Cloud instance credentials via metadata",
            category=TechniqueCategory.INFO_DISCLOSURE,
            severity=Severity.HIGH,
            description=(
                "Cloud metadata service exposes IAM credentials, instance identity tokens, and other sensitive data."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="credentials.cloud_metadata_available",
                    check_type="equals",
                    check_value=True,
                    description="Cloud metadata must be available",
                ),
            ],
            mitre_attack=["T1552.005"],
            references=[
                "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",
            ],
            reliability=0.9,
            stealth=0.8,
            remediation="IMDSv2 with hop limit, block metadata endpoint",
            verify_command="command -v curl >/dev/null 2>&1 && curl -sf --max-time 2 http://169.254.169.254/ >/dev/null",
        ),
        EscapeTechnique(
            id="k8s_configmap_secrets",
            name="K8s secrets mounted as volumes",
            category=TechniqueCategory.INFO_DISCLOSURE,
            severity=Severity.MEDIUM,
            description=(
                "Kubernetes secrets and configmaps mounted in the pod can be "
                "read by the service account token via the API server."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="credentials.service_account_token",
                    check_type="equals",
                    check_value=True,
                    description="Service account token must be present",
                ),
                Prerequisite(
                    check_field="runtime.orchestrator",
                    check_type="equals",
                    check_value="kubernetes",
                    description="Must be running under Kubernetes",
                ),
            ],
            # T1552.007 is the specific sub-technique for Container API
            # credential exposure (Kubernetes API server, kubelet etc.).
            mitre_attack=["T1552.007"],
            references=[
                "https://kubernetes.io/docs/concepts/configuration/secret/",
            ],
            reliability=0.85,
            stealth=0.8,
            remediation="Least-privilege RBAC, encrypt secrets at rest",
            verify_command="[ -r /var/run/secrets/kubernetes.io/serviceaccount/token ]",
        ),
        EscapeTechnique(
            id="docker_env_inspection",
            name="Container env leakage via Docker API",
            category=TechniqueCategory.INFO_DISCLOSURE,
            severity=Severity.MEDIUM,
            description=(
                "Docker API access allows inspecting environment variables "
                "of all containers, potentially leaking secrets."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="network.can_reach_docker_sock",
                    check_type="equals",
                    check_value=True,
                    description="Docker socket/API must be reachable",
                ),
            ],
            # T1552.007 (Container API) is the precise sub-technique for
            # leaking creds via the Docker API.
            mitre_attack=["T1552.007"],
            references=[
                "https://docs.docker.com/engine/api/v1.41/#operation/ContainerInspect",
            ],
            reliability=0.9,
            stealth=0.6,
            remediation="Don't expose Docker socket, use secrets",
            # Probes whether the Docker socket is reachable for the kinds
            # of /containers/json/{id}/json calls that leak other containers'
            # env vars. Reachable socket = primitive works.
            verify_command="command -v curl >/dev/null 2>&1 && [ -S /var/run/docker.sock ] && curl -sf --max-time 2 --unix-socket /var/run/docker.sock http://localhost/_ping >/dev/null 2>&1",
        ),
    ]


def get_all_techniques() -> list[EscapeTechnique]:
    """Return all 65 escape techniques.

    Returns a deep copy of the lazily-built singleton so that callers
    mutating a returned technique (test fixtures, SDK consumers that
    monkey-patch a `cli_flag` or `verify_command` for sandboxed runs)
    don't silently corrupt subsequent callers in the same process. The
    deep-copy cost is ~65 model clones per call — sub-millisecond,
    invisible to the analyze pipeline.
    """
    global _TECHNIQUES
    if _TECHNIQUES is None:
        with _TECHNIQUES_LOCK:
            # Re-check inside the lock: another thread may have built it
            # while we were blocked acquiring the lock.
            if _TECHNIQUES is None:
                _TECHNIQUES = _build_techniques()
    return copy.deepcopy(_TECHNIQUES)


def get_techniques_by_category(category: TechniqueCategory) -> list[EscapeTechnique]:
    """Return all techniques in a given category."""
    return [t for t in get_all_techniques() if t.category == category]


def get_technique_by_id(technique_id: str) -> EscapeTechnique | None:
    """Return a single technique by its ID, or None if not found."""
    for t in get_all_techniques():
        if t.id == technique_id:
            return t
    return None
