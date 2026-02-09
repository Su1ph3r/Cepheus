"""Complete database of 44 container escape techniques."""

from __future__ import annotations

from cepheus.models.technique import (
    EscapeTechnique,
    Prerequisite,
    Severity,
    TechniqueCategory,
)

_TECHNIQUES: list[EscapeTechnique] | None = None


def _build_techniques() -> list[EscapeTechnique]:
    """Build and return all 44 escape techniques."""
    return [
        # ── CAPABILITY (8) ───────────────────────────────────────────
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
        ),
        EscapeTechnique(
            id="cap_sys_admin_cgroup_escape",
            name="cgroup release_agent escape",
            category=TechniqueCategory.CAPABILITY,
            severity=Severity.CRITICAL,
            description=(
                "Abuse cgroup v1 release_agent to execute commands on the host "
                "when a cgroup becomes empty."
            ),
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
        ),
        EscapeTechnique(
            id="cap_sys_ptrace",
            name="Ptrace host processes",
            category=TechniqueCategory.CAPABILITY,
            severity=Severity.HIGH,
            description=(
                "With CAP_SYS_PTRACE and a shared PID namespace, attach to host "
                "processes and inject code for escape."
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
            mitre_attack=["T1055"],
            references=[
                "https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts",
            ],
            reliability=0.8,
            stealth=0.5,
            remediation="--cap-drop=SYS_PTRACE --pid=container",
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
            mitre_attack=["T1005"],
            references=[
                "https://man7.org/linux/man-pages/man7/capabilities.7.html",
            ],
            reliability=0.95,
            stealth=0.7,
            remediation="--cap-drop=DAC_READ_SEARCH",
        ),
        EscapeTechnique(
            id="cap_dac_override",
            name="Write arbitrary host files",
            category=TechniqueCategory.CAPABILITY,
            severity=Severity.CRITICAL,
            description=(
                "CAP_DAC_OVERRIDE bypasses file write permission checks, "
                "enabling writes to any host file accessible from the mount namespace."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="capabilities.effective",
                    check_type="contains",
                    check_value="CAP_DAC_OVERRIDE",
                    description="Requires CAP_DAC_OVERRIDE capability",
                ),
            ],
            mitre_attack=["T1565"],
            references=[
                "https://man7.org/linux/man-pages/man7/capabilities.7.html",
            ],
            reliability=0.95,
            stealth=0.4,
            remediation="--cap-drop=DAC_OVERRIDE",
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
            mitre_attack=["T1006"],
            references=[
                "https://man7.org/linux/man-pages/man7/capabilities.7.html",
            ],
            reliability=0.75,
            stealth=0.2,
            remediation="--cap-drop=SYS_RAWIO",
        ),
        # ── MOUNT (8) ────────────────────────────────────────────────
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
                Prerequisite(
                    check_field="available_tools",
                    check_type="contains",
                    check_value="curl",
                    confidence_if_absent=0.5,
                    description="curl or similar HTTP client available",
                ),
            ],
            mitre_attack=["T1611"],
            references=[
                "https://book.hacktricks.xyz/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation",
            ],
            reliability=0.95,
            stealth=0.2,
            remediation="Never mount Docker socket into containers",
        ),
        EscapeTechnique(
            id="procfs_core_pattern",
            name="Write to /proc/sys/kernel/core_pattern",
            category=TechniqueCategory.MOUNT,
            severity=Severity.CRITICAL,
            description=(
                "If /proc/sys/kernel/core_pattern is writable, an attacker can "
                "set it to a pipe command that executes on the host when a core "
                "dump is triggered."
            ),
            prerequisites=[
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
            reliability=0.85,
            stealth=0.3,
            remediation="Mount /proc read-only or use seccomp",
        ),
        EscapeTechnique(
            id="procfs_sysrq",
            name="/proc/sysrq-trigger abuse",
            category=TechniqueCategory.MOUNT,
            severity=Severity.HIGH,
            description=(
                "Writing to /proc/sysrq-trigger can crash or reboot the host "
                "kernel, causing denial of service."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="writable_paths",
                    check_type="contains",
                    check_value="/proc/sysrq-trigger",
                    description="/proc/sysrq-trigger must be writable",
                ),
            ],
            mitre_attack=["T1529"],
            references=[
                "https://docs.kernel.org/admin-guide/sysrq.html",
            ],
            reliability=0.9,
            stealth=0.1,
            remediation="Mount /proc read-only",
        ),
        EscapeTechnique(
            id="sysfs_hugepages",
            name="sysfs writeback exploitation",
            category=TechniqueCategory.MOUNT,
            severity=Severity.HIGH,
            description=(
                "Writable /sys filesystem allows manipulation of kernel "
                "parameters including hugepages, device settings, and more."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="writable_paths",
                    check_type="contains",
                    check_value="/sys",
                    description="/sys must be writable",
                ),
            ],
            mitre_attack=["T1611"],
            references=[
                "https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts",
            ],
            reliability=0.6,
            stealth=0.4,
            remediation="Mount /sys read-only",
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
        ),
        # ── KERNEL (10) ──────────────────────────────────────────────
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
        ),
        EscapeTechnique(
            id="cve_2022_2588",
            name="route4 use-after-free",
            category=TechniqueCategory.KERNEL,
            severity=Severity.CRITICAL,
            description=(
                "Use-after-free in net/sched/cls_route.c allows privilege "
                "escalation from container to host."
            ),
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
        ),
        EscapeTechnique(
            id="cve_2024_1086",
            name="nf_tables double-free",
            category=TechniqueCategory.KERNEL,
            severity=Severity.CRITICAL,
            description=(
                "Double-free in nf_tables verdict handling enables arbitrary "
                "code execution and container escape."
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
                    check_type="contains",
                    check_value="CAP_SYS_ADMIN",
                    description="Requires CAP_SYS_ADMIN or CAP_BPF",
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
        ),
        # ── RUNTIME (8) ──────────────────────────────────────────────
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
        ),
        EscapeTechnique(
            id="k8s_kubelet_api",
            name="Direct kubelet API access",
            category=TechniqueCategory.RUNTIME,
            severity=Severity.HIGH,
            description=(
                "Direct access to the kubelet API (port 10250) allows "
                "executing commands in any pod on the node."
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
        ),
        EscapeTechnique(
            id="k8s_etcd_access",
            name="Direct etcd access",
            category=TechniqueCategory.RUNTIME,
            severity=Severity.CRITICAL,
            description=(
                "Direct access to etcd (port 2379) exposes all Kubernetes "
                "secrets, configurations, and cluster state."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="runtime.orchestrator",
                    check_type="equals",
                    check_value="kubernetes",
                    description="Must be running under Kubernetes",
                ),
            ],
            mitre_attack=["T1005"],
            references=[
                "https://book.hacktricks.xyz/pentesting/pentesting-kubernetes/kubernetes-enumeration",
            ],
            reliability=0.6,
            stealth=0.3,
            remediation="Restrict etcd access with TLS client certs",
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
        ),
        EscapeTechnique(
            id="containerd_shim_escape",
            name="containerd shim vulnerability",
            category=TechniqueCategory.RUNTIME,
            severity=Severity.HIGH,
            description=(
                "Exploit vulnerabilities in containerd-shim to gain host "
                "access via the container runtime interface."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="runtime.runtime",
                    check_type="equals",
                    check_value="containerd",
                    description="Runtime must be containerd",
                ),
            ],
            mitre_attack=["T1611"],
            references=[
                "https://nvd.nist.gov/vuln/detail/CVE-2020-15257",
            ],
            reliability=0.5,
            stealth=0.4,
            remediation="Update containerd to latest",
        ),
        EscapeTechnique(
            id="runc_cve_2019_5736",
            name="runc overwrite (/proc/self/exe)",
            category=TechniqueCategory.RUNTIME,
            severity=Severity.CRITICAL,
            description=(
                "Overwrite the host runc binary via /proc/self/exe to gain "
                "code execution on the host when runc is next invoked."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="runtime.runtime",
                    check_type="regex",
                    check_value="^(docker|containerd)$",
                    description="Runtime uses runc (Docker or containerd)",
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
            mitre_attack=["T1552"],
            references=[
                "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html",
            ],
            reliability=0.9,
            stealth=0.8,
            remediation="Block 169.254.169.254 via network policy",
        ),
        EscapeTechnique(
            id="k8s_node_proxy",
            name="Kubelet node proxy abuse",
            category=TechniqueCategory.RUNTIME,
            severity=Severity.HIGH,
            description=(
                "Abuse kubelet proxy endpoint to forward traffic to other "
                "pods and services on the node."
            ),
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
        ),
        EscapeTechnique(
            id="privileged_docker_sock",
            name="Privileged + docker.sock — trivial escape",
            category=TechniqueCategory.COMBINATORIAL,
            severity=Severity.CRITICAL,
            description=(
                "A privileged container with Docker socket access provides "
                "trivial, near-guaranteed escape to the host."
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
            mitre_attack=["T1552"],
            references=[
                "https://blog.champtar.fr/Metadata_MITM_root_EKS_GKE/",
            ],
            reliability=0.85,
            stealth=0.7,
            remediation="--cap-drop=NET_RAW, block metadata endpoint",
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
        ),
        # ── INFO_DISCLOSURE (4) ───────────────────────────────────────
        EscapeTechnique(
            id="env_secret_leak",
            name="Secrets in environment variables",
            category=TechniqueCategory.INFO_DISCLOSURE,
            severity=Severity.MEDIUM,
            description=(
                "Sensitive credentials found in environment variables, "
                "accessible to any process in the container."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="credentials.environment_secrets",
                    check_type="not_empty",
                    description="Environment secrets must be present",
                ),
            ],
            mitre_attack=["T1552"],
            references=[
                "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html",
            ],
            reliability=0.95,
            stealth=0.9,
            remediation="Use secrets management (Vault, K8s secrets), not env vars",
        ),
        EscapeTechnique(
            id="cloud_metadata_creds",
            name="Cloud instance credentials via metadata",
            category=TechniqueCategory.INFO_DISCLOSURE,
            severity=Severity.HIGH,
            description=(
                "Cloud metadata service exposes IAM credentials, instance "
                "identity tokens, and other sensitive data."
            ),
            prerequisites=[
                Prerequisite(
                    check_field="credentials.cloud_metadata_available",
                    check_type="equals",
                    check_value=True,
                    description="Cloud metadata must be available",
                ),
            ],
            mitre_attack=["T1552"],
            references=[
                "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",
            ],
            reliability=0.9,
            stealth=0.8,
            remediation="IMDSv2 with hop limit, block metadata endpoint",
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
            mitre_attack=["T1552"],
            references=[
                "https://kubernetes.io/docs/concepts/configuration/secret/",
            ],
            reliability=0.85,
            stealth=0.8,
            remediation="Least-privilege RBAC, encrypt secrets at rest",
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
            mitre_attack=["T1552"],
            references=[
                "https://docs.docker.com/engine/api/v1.41/#operation/ContainerInspect",
            ],
            reliability=0.9,
            stealth=0.6,
            remediation="Don't expose Docker socket, use secrets",
        ),
    ]


def get_all_techniques() -> list[EscapeTechnique]:
    """Return all 44 escape techniques."""
    global _TECHNIQUES
    if _TECHNIQUES is None:
        _TECHNIQUES = _build_techniques()
    return list(_TECHNIQUES)


def get_techniques_by_category(category: TechniqueCategory) -> list[EscapeTechnique]:
    """Return all techniques in a given category."""
    return [t for t in get_all_techniques() if t.category == category]


def get_technique_by_id(technique_id: str) -> EscapeTechnique | None:
    """Return a single technique by its ID, or None if not found."""
    for t in get_all_techniques():
        if t.id == technique_id:
            return t
    return None
