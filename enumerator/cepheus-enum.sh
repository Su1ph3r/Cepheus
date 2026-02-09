#!/bin/sh
# cepheus-enum.sh — Zero-dependency POSIX shell container security enumerator.
# Outputs a JSON blob (ContainerPosture schema) to stdout.
# Works in Alpine (busybox sh), Debian (dash), and distroless (if copied in).
# Usage: sh cepheus-enum.sh

ENUM_VERSION="0.1.0"

# ---------------------------------------------------------------------------
# JSON helpers
# ---------------------------------------------------------------------------

json_str() { printf '"%s"' "$(echo "$1" | sed 's/\\/\\\\/g; s/"/\\"/g')"; }
json_int() { printf '%d' "$1"; }
json_bool() { if [ "$1" = "true" ]; then printf 'true'; else printf 'false'; fi; }
json_null() { printf 'null'; }
json_array() { printf '[%s]' "$1"; }
json_str_or_null() { if [ -n "$1" ]; then json_str "$1"; else json_null; fi; }

# Append to a comma-separated list (used to build JSON arrays incrementally).
# Usage: list=$(list_append "$list" "\"item\"")
list_append() {
    if [ -n "$1" ]; then
        printf '%s, %s' "$1" "$2"
    else
        printf '%s' "$2"
    fi
}

# ---------------------------------------------------------------------------
# Timestamp
# ---------------------------------------------------------------------------

get_timestamp() {
    if date -u '+%Y-%m-%dT%H:%M:%SZ' >/dev/null 2>&1; then
        date -u '+%Y-%m-%dT%H:%M:%SZ'
    else
        echo "1970-01-01T00:00:00Z"
    fi
}

# ---------------------------------------------------------------------------
# Kernel info
# ---------------------------------------------------------------------------

get_kernel_version() {
    uname -r 2>/dev/null || echo "unknown"
}

parse_kernel_major() { echo "$1" | cut -d. -f1 | cut -d- -f1; }
parse_kernel_minor() { echo "$1" | cut -d. -f2 | cut -d- -f1; }
parse_kernel_patch() {
    p=$(echo "$1" | cut -d. -f3 | cut -d- -f1)
    if [ -z "$p" ]; then echo 0; else echo "$p"; fi
}

# ---------------------------------------------------------------------------
# Capability decoding
# ---------------------------------------------------------------------------

cap_num_to_name() {
    case "$1" in
        0)  echo "CAP_CHOWN" ;;
        1)  echo "CAP_DAC_OVERRIDE" ;;
        2)  echo "CAP_DAC_READ_SEARCH" ;;
        3)  echo "CAP_FOWNER" ;;
        4)  echo "CAP_FSETID" ;;
        5)  echo "CAP_KILL" ;;
        6)  echo "CAP_SETGID" ;;
        7)  echo "CAP_SETUID" ;;
        8)  echo "CAP_SETPCAP" ;;
        9)  echo "CAP_LINUX_IMMUTABLE" ;;
        10) echo "CAP_NET_BIND_SERVICE" ;;
        11) echo "CAP_NET_BROADCAST" ;;
        12) echo "CAP_NET_ADMIN" ;;
        13) echo "CAP_NET_RAW" ;;
        14) echo "CAP_IPC_LOCK" ;;
        15) echo "CAP_IPC_OWNER" ;;
        16) echo "CAP_SYS_MODULE" ;;
        17) echo "CAP_SYS_RAWIO" ;;
        18) echo "CAP_SYS_CHROOT" ;;
        19) echo "CAP_SYS_PTRACE" ;;
        20) echo "CAP_SYS_PACCT" ;;
        21) echo "CAP_SYS_ADMIN" ;;
        22) echo "CAP_SYS_BOOT" ;;
        23) echo "CAP_SYS_NICE" ;;
        24) echo "CAP_SYS_RESOURCE" ;;
        25) echo "CAP_SYS_TIME" ;;
        26) echo "CAP_SYS_TTY_CONFIG" ;;
        27) echo "CAP_MKNOD" ;;
        28) echo "CAP_LEASE" ;;
        29) echo "CAP_AUDIT_WRITE" ;;
        30) echo "CAP_AUDIT_CONTROL" ;;
        31) echo "CAP_SETFCAP" ;;
        32) echo "CAP_MAC_OVERRIDE" ;;
        33) echo "CAP_MAC_ADMIN" ;;
        34) echo "CAP_SYSLOG" ;;
        35) echo "CAP_WAKE_ALARM" ;;
        36) echo "CAP_BLOCK_SUSPEND" ;;
        37) echo "CAP_AUDIT_READ" ;;
        38) echo "CAP_PERFMON" ;;
        39) echo "CAP_BPF" ;;
        40) echo "CAP_CHECKPOINT_RESTORE" ;;
        *)  echo "" ;;
    esac
}

hex_char_to_dec() {
    case "$1" in
        0) echo 0 ;; 1) echo 1 ;; 2) echo 2 ;; 3) echo 3 ;;
        4) echo 4 ;; 5) echo 5 ;; 6) echo 6 ;; 7) echo 7 ;;
        8) echo 8 ;; 9) echo 9 ;;
        a|A) echo 10 ;; b|B) echo 11 ;; c|C) echo 12 ;; d|D) echo 13 ;;
        e|E) echo 14 ;; f|F) echo 15 ;;
        *) echo 0 ;;
    esac
}

# decode_caps <hex_string>
# Outputs comma-separated quoted capability names, e.g. "CAP_CHOWN", "CAP_KILL"
decode_caps() {
    _hex="$1"
    _caps=""
    _len=${#_hex}
    _i=$((_len - 1))
    _bit_offset=0
    while [ "$_i" -ge 0 ]; do
        _pos=$((_i + 1))
        _char=$(echo "$_hex" | cut -c"$_pos")
        _val=$(hex_char_to_dec "$_char")
        _b=0
        while [ "$_b" -lt 4 ]; do
            _bit_val=$((1 << _b))
            if [ $((_val & _bit_val)) -ne 0 ]; then
                _cap_num=$((_bit_offset + _b))
                _cap_name=$(cap_num_to_name "$_cap_num")
                if [ -n "$_cap_name" ]; then
                    _caps=$(list_append "$_caps" "\"$_cap_name\"")
                fi
            fi
            _b=$((_b + 1))
        done
        _bit_offset=$((_bit_offset + 4))
        _i=$((_i - 1))
    done
    echo "$_caps"
}

read_cap_hex() {
    # $1 = field name, e.g. "CapEff"
    if [ -f /proc/self/status ]; then
        _line=$(grep "^${1}:" /proc/self/status 2>/dev/null | head -1)
        echo "$_line" | sed 's/.*:[[:space:]]*//' | tr -d '[:space:]'
    fi
}

collect_capabilities() {
    _cap_eff_hex=$(read_cap_hex "CapEff")
    _cap_bnd_hex=$(read_cap_hex "CapBnd")
    _cap_prm_hex=$(read_cap_hex "CapPrm")

    CAP_EFF=$(decode_caps "$_cap_eff_hex")
    CAP_BND=$(decode_caps "$_cap_bnd_hex")
    CAP_PRM=$(decode_caps "$_cap_prm_hex")

    # Store raw effective hex for privileged detection later
    CAP_EFF_HEX="$_cap_eff_hex"
}

# ---------------------------------------------------------------------------
# Mounts
# ---------------------------------------------------------------------------

collect_mounts() {
    MOUNTS_JSON=""
    if [ -f /proc/mounts ]; then
        while IFS= read -r _line; do
            _src=$(echo "$_line" | awk '{print $1}')
            _dst=$(echo "$_line" | awk '{print $2}')
            _fs=$(echo "$_line" | awk '{print $3}')
            _raw_opts=$(echo "$_line" | awk '{print $4}')
            # Convert comma-separated options to JSON array
            _opts_json=""
            _old_ifs="$IFS"
            IFS=','
            for _o in $_raw_opts; do
                _opts_json=$(list_append "$_opts_json" "\"$_o\"")
            done
            IFS="$_old_ifs"
            _entry=$(printf '{"source": %s, "destination": %s, "fstype": %s, "options": [%s]}' \
                "$(json_str "$_src")" "$(json_str "$_dst")" "$(json_str "$_fs")" "$_opts_json")
            MOUNTS_JSON=$(list_append "$MOUNTS_JSON" "$_entry")
        done < /proc/mounts
    fi
}

# ---------------------------------------------------------------------------
# Namespaces
# ---------------------------------------------------------------------------

collect_namespaces() {
    # Default: assume isolated (true) — standard for containers.
    NS_PID="true"; NS_NET="true"; NS_MNT="true"; NS_USER="true"
    NS_UTS="true"; NS_IPC="true"; NS_CGROUP="true"

    # Inside a container, /proc/1/ns and /proc/self/ns always match
    # (both are inside the container's namespace). To detect host-sharing
    # (e.g. --pid=host), we use heuristics per namespace type.

    if [ -f /proc/1/comm ]; then
        _pid1_comm=$(cat /proc/1/comm 2>/dev/null)
        # If PID 1 is a host init system, PID namespace is shared
        case "$_pid1_comm" in
            systemd|init|initd|launchd|sysvinit|upstart|openrc-init) NS_PID="false" ;;
        esac
    fi

    # UTS: if hostname matches a known host pattern (not a container hash)
    # We can't reliably detect this, keep default true.

    # Net: if we can see many host interfaces (>5), likely sharing host net
    _iface_count=0
    if [ -d /sys/class/net ]; then
        for _i in /sys/class/net/*; do
            _iface_count=$((_iface_count + 1))
        done
    fi
    # Typical container has 2-3 interfaces (lo, eth0). Host has many more.
    # This is a heuristic — not definitive.

    # User: check if user namespace is active (uid_map non-trivial)
    if [ -f /proc/self/uid_map ]; then
        _uid_map=$(cat /proc/self/uid_map 2>/dev/null | head -1 | awk '{print $3}')
        # If the range covers all UIDs (4294967295), user ns is not isolated
        case "$_uid_map" in
            4294967295|429496729*) NS_USER="false" ;;
        esac
    fi

    # If not on Linux (no /proc/1/ns), report all as true (unknown/isolated)
}

# ---------------------------------------------------------------------------
# Security profiles (seccomp, apparmor, selinux)
# ---------------------------------------------------------------------------

collect_security() {
    # Seccomp
    SECCOMP="disabled"
    if [ -f /proc/self/status ]; then
        _sc=$(grep "^Seccomp:" /proc/self/status 2>/dev/null | awk '{print $2}')
        case "$_sc" in
            0) SECCOMP="disabled" ;;
            1) SECCOMP="strict" ;;
            2) SECCOMP="filtering" ;;
        esac
    fi

    # AppArmor
    APPARMOR=""
    if [ -f /proc/self/attr/current ]; then
        _aa=$(cat /proc/self/attr/current 2>/dev/null | tr -d '\000')
        case "$_aa" in
            ""| "unconfined") APPARMOR="" ;;
            *) APPARMOR="$_aa" ;;
        esac
    fi

    # SELinux
    SELINUX=""
    if command -v getenforce >/dev/null 2>&1; then
        _se=$(getenforce 2>/dev/null)
        if [ "$_se" != "Disabled" ]; then
            SELINUX=$(cat /proc/self/attr/current 2>/dev/null | tr -d '\000')
        fi
    elif [ -f /sys/fs/selinux/enforce ]; then
        SELINUX=$(cat /proc/self/attr/current 2>/dev/null | tr -d '\000')
    fi
}

# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------

collect_network() {
    # Interfaces
    IFACES_JSON=""
    if [ -d /sys/class/net ]; then
        for _iface in /sys/class/net/*; do
            _name=$(basename "$_iface")
            IFACES_JSON=$(list_append "$IFACES_JSON" "\"$_name\"")
        done
    elif command -v ip >/dev/null 2>&1; then
        for _name in $(ip -o link show 2>/dev/null | awk -F': ' '{print $2}'); do
            IFACES_JSON=$(list_append "$IFACES_JSON" "\"$_name\"")
        done
    fi

    # Metadata service (curl preferred — more reliable timeout handling)
    CAN_REACH_METADATA="false"
    if command -v curl >/dev/null 2>&1; then
        if curl -sf --connect-timeout 2 --max-time 2 http://169.254.169.254/ >/dev/null 2>&1; then
            CAN_REACH_METADATA="true"
        fi
    elif command -v wget >/dev/null 2>&1; then
        if wget -q -O /dev/null -T 2 http://169.254.169.254/ 2>/dev/null; then
            CAN_REACH_METADATA="true"
        fi
    fi

    # Docker socket
    CAN_REACH_DOCKER_SOCK="false"
    if [ -S /var/run/docker.sock ]; then
        CAN_REACH_DOCKER_SOCK="true"
    fi

    # Containerd socket
    CAN_REACH_CONTAINERD_SOCK="false"
    if [ -S /run/containerd/containerd.sock ]; then
        CAN_REACH_CONTAINERD_SOCK="true"
    elif [ -S /var/run/containerd/containerd.sock ]; then
        CAN_REACH_CONTAINERD_SOCK="true"
    fi

    # CRI-O socket
    CAN_REACH_CRIO_SOCK="false"
    if [ -S /var/run/crio/crio.sock ]; then
        CAN_REACH_CRIO_SOCK="true"
    elif [ -S /run/crio/crio.sock ]; then
        CAN_REACH_CRIO_SOCK="true"
    fi

    # Listening ports from /proc/net/tcp
    LISTENING_PORTS=""
    if [ -f /proc/net/tcp ]; then
        # State 0A = LISTEN; local_address is field 2 (hex ip:port)
        while IFS= read -r _tcpline; do
            _state=$(echo "$_tcpline" | awk '{print $4}')
            if [ "$_state" = "0A" ]; then
                _hex_port=$(echo "$_tcpline" | awk '{print $2}' | cut -d: -f2)
                # Convert hex port to decimal using printf
                _port=$(printf '%d' "0x$_hex_port" 2>/dev/null || echo 0)
                if [ "$_port" -gt 0 ]; then
                    LISTENING_PORTS=$(list_append "$LISTENING_PORTS" "$_port")
                fi
            fi
        done < /proc/net/tcp
    fi
    # Also check tcp6
    if [ -f /proc/net/tcp6 ]; then
        while IFS= read -r _tcpline; do
            _state=$(echo "$_tcpline" | awk '{print $4}')
            if [ "$_state" = "0A" ]; then
                _hex_port=$(echo "$_tcpline" | awk '{print $2}' | cut -d: -f2)
                _port=$(printf '%d' "0x$_hex_port" 2>/dev/null || echo 0)
                if [ "$_port" -gt 0 ]; then
                    LISTENING_PORTS=$(list_append "$LISTENING_PORTS" "$_port")
                fi
            fi
        done < /proc/net/tcp6
    fi
}

# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------

collect_credentials() {
    # Kubernetes service account token
    SA_TOKEN="false"
    if [ -f /var/run/secrets/kubernetes.io/serviceaccount/token ]; then
        SA_TOKEN="true"
    fi

    # Environment secrets — output names only, never values
    ENV_SECRETS=""
    _secrets_file=$(mktemp /tmp/_cepheus_secrets_XXXXXX 2>/dev/null || echo "/tmp/_cepheus_secrets$$")
    env | while IFS='=' read -r _name _val; do
        case "$_name" in
            *PASSWORD*|*SECRET*|*TOKEN*|*KEY*|*CREDENTIAL*)
                # Print name for collection below
                echo "$_name"
                ;;
        esac
    done > "$_secrets_file" 2>/dev/null || true
    if [ -f "$_secrets_file" ]; then
        while IFS= read -r _sname; do
            if [ -n "$_sname" ]; then
                ENV_SECRETS=$(list_append "$ENV_SECRETS" "\"$_sname\"")
            fi
        done < "$_secrets_file"
        rm -f "$_secrets_file"
    fi

    CLOUD_META="$CAN_REACH_METADATA"
}

# ---------------------------------------------------------------------------
# Runtime detection
# ---------------------------------------------------------------------------

collect_runtime() {
    RUNTIME="unknown"
    RUNTIME_VERSION=""
    ORCHESTRATOR=""
    PRIVILEGED="false"
    PID_ONE="unknown"
    RUNC_VERSION=""

    # PID 1 command
    if [ -f /proc/1/comm ]; then
        PID_ONE=$(cat /proc/1/comm 2>/dev/null || echo "unknown")
    elif [ -d /proc/1 ]; then
        PID_ONE=$(cat /proc/1/cmdline 2>/dev/null | tr '\000' ' ' | awk '{print $1}' || echo "unknown")
    fi

    # Runtime detection
    if [ -f /.dockerenv ]; then
        RUNTIME="docker"
    elif [ -d /run/containerd ]; then
        RUNTIME="containerd"
    fi
    if [ -f /proc/1/cgroup ]; then
        _cg=$(cat /proc/1/cgroup 2>/dev/null)
        case "$_cg" in
            *docker*)   RUNTIME="docker" ;;
            *containerd*) RUNTIME="containerd" ;;
            *cri-o*)    RUNTIME="cri-o" ;;
        esac
    fi

    # Runtime version detection
    if [ "$RUNTIME" = "docker" ]; then
        if command -v docker >/dev/null 2>&1; then
            RUNTIME_VERSION=$(docker version --format '{{.Server.Version}}' 2>/dev/null || true)
        elif [ -S /var/run/docker.sock ] && command -v curl >/dev/null 2>&1; then
            RUNTIME_VERSION=$(curl -sf --unix-socket /var/run/docker.sock http://localhost/version 2>/dev/null \
                | sed -n 's/.*"Version":"\([^"]*\)".*/\1/p' || true)
        fi
    elif [ "$RUNTIME" = "containerd" ]; then
        if command -v containerd >/dev/null 2>&1; then
            RUNTIME_VERSION=$(containerd --version 2>/dev/null | awk '{print $3}' | sed 's/^v//' || true)
        elif command -v ctr >/dev/null 2>&1; then
            RUNTIME_VERSION=$(ctr version 2>/dev/null | grep "Version" | awk '{print $2}' || true)
        fi
    elif [ "$RUNTIME" = "cri-o" ]; then
        if command -v crio >/dev/null 2>&1; then
            RUNTIME_VERSION=$(crio --version 2>/dev/null | head -1 | awk '{print $NF}' || true)
        fi
    fi

    # runc version (always attempt)
    if command -v runc >/dev/null 2>&1; then
        RUNC_VERSION=$(runc --version 2>/dev/null | head -1 | awk '{print $NF}' || true)
    fi

    # Orchestrator
    if [ -n "${KUBERNETES_SERVICE_HOST:-}" ]; then
        ORCHESTRATOR="kubernetes"
    fi

    # Privileged detection
    # Method 1: full cap set (all 41 caps = 0x1ffffffffff)
    if [ -n "$CAP_EFF_HEX" ]; then
        # Remove leading zeros
        _trimmed=$(echo "$CAP_EFF_HEX" | sed 's/^0*//')
        case "$_trimmed" in
            1ffffffffff|3ffffffffff|7ffffffffff|ffffffffff|1ffffffffff*)
                PRIVILEGED="true" ;;
        esac
    fi
    # Method 2: device access
    if [ "$PRIVILEGED" = "false" ]; then
        if [ -r /dev/sda ] || [ -r /dev/nvme0 ] || [ -r /dev/vda ]; then
            PRIVILEGED="true"
        fi
    fi
}

# ---------------------------------------------------------------------------
# Cgroup version
# ---------------------------------------------------------------------------

detect_cgroup_version() {
    if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
        CGROUP_VERSION=2
    else
        CGROUP_VERSION=1
    fi
}

# ---------------------------------------------------------------------------
# Writable paths
# ---------------------------------------------------------------------------

collect_writable_paths() {
    WRITABLE_PATHS=""
    for _p in \
        /proc/sysrq-trigger \
        /proc/sys/kernel/core_pattern \
        /sys \
        /sys/fs/cgroup \
        /dev \
        /dev/shm \
        /host \
        /host/etc \
        /var/run/docker.sock \
        /run/containerd/containerd.sock \
        /var/run/crio/crio.sock \
        /proc/acpi/alarm \
        /proc/sys/vm \
        /proc/self/fd \
        /sys/kernel/security \
        /sys/kernel/uevent_helper \
        /sys/devices/virtual/misc/device-mapper/dev; do
        if [ -w "$_p" ] 2>/dev/null; then
            WRITABLE_PATHS=$(list_append "$WRITABLE_PATHS" "\"$_p\"")
        fi
    done
    # Check /proc/self/fd symlink traversal
    if [ -d /proc/self/fd ]; then
        for _fd in /proc/self/fd/*; do
            _target=$(readlink "$_fd" 2>/dev/null || true)
            case "$_target" in
                /host*|/etc/shadow|/etc/passwd)
                    if [ -z "$_symlink_checked" ]; then
                        WRITABLE_PATHS=$(list_append "$WRITABLE_PATHS" "\"/proc/self/fd\"")
                        _symlink_checked=1
                    fi
                    ;;
            esac
        done
    fi
}

# ---------------------------------------------------------------------------
# Kubernetes enumeration
# ---------------------------------------------------------------------------

collect_kubernetes() {
    K8S_RBAC_PERMS=""
    K8S_PSS=""
    K8S_HAS_SIDECAR="false"
    K8S_SIDECAR_TYPE=""
    K8S_NODE_ACCESS=""
    K8S_NAMESPACE=""
    K8S_POD_NAME=""
    K8S_NODE_NAME=""

    # Only collect if running under Kubernetes
    if [ -z "${KUBERNETES_SERVICE_HOST:-}" ]; then
        return
    fi

    # Namespace
    if [ -f /var/run/secrets/kubernetes.io/serviceaccount/namespace ]; then
        K8S_NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace 2>/dev/null || true)
    fi

    # Pod name from downward API or hostname
    K8S_POD_NAME="${POD_NAME:-}"
    if [ -z "$K8S_POD_NAME" ]; then
        K8S_POD_NAME="${HOSTNAME:-}"
    fi

    # Node name from downward API
    K8S_NODE_NAME="${NODE_NAME:-}"
    if [ -z "$K8S_NODE_NAME" ] && [ -n "${KUBERNETES_NODE_NAME:-}" ]; then
        K8S_NODE_NAME="$KUBERNETES_NODE_NAME"
    fi

    # RBAC permissions
    if command -v kubectl >/dev/null 2>&1; then
        _perms=$(kubectl auth can-i --list 2>/dev/null | tail -n +2 | awk '{print $1 "/" $2}' || true)
        for _perm in $_perms; do
            K8S_RBAC_PERMS=$(list_append "$K8S_RBAC_PERMS" "$(json_str "$_perm")")
        done
    elif [ -f /var/run/secrets/kubernetes.io/serviceaccount/token ]; then
        _token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null || true)
        if [ -n "$_token" ] && command -v curl >/dev/null 2>&1; then
            # Write auth header to temp file to avoid token in process args
            _hdr_file=$(mktemp /tmp/_cepheus_hdr_XXXXXX 2>/dev/null || echo "/tmp/_cepheus_hdr$$")
            printf 'Authorization: Bearer %s' "$_token" > "$_hdr_file"
            chmod 600 "$_hdr_file"
            # Use K8s CA cert for TLS when available
            _cacert=""
            if [ -f /var/run/secrets/kubernetes.io/serviceaccount/ca.crt ]; then
                _cacert="--cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
            else
                _cacert="-k"
            fi
            _ns="${K8S_NAMESPACE:-default}"
            _api_resp=$(curl -sf --max-time 3 $_cacert \
                -H @"$_hdr_file" \
                "https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT:-443}/apis/authorization.k8s.io/v1/selfsubjectrulesreviews" \
                -X POST -H "Content-Type: application/json" \
                -d "{\"apiVersion\":\"authorization.k8s.io/v1\",\"kind\":\"SelfSubjectRulesReview\",\"spec\":{\"namespace\":\"$_ns\"}}" \
                2>/dev/null || true)
            rm -f "$_hdr_file"
            # Basic extraction — look for resource/verb pairs
            if [ -n "$_api_resp" ]; then
                K8S_RBAC_PERMS=$(list_append "$K8S_RBAC_PERMS" "\"selfsubjectrulesreview/available\"")
            fi
        fi
    fi

    # Pod security standard heuristic
    if [ "$PRIVILEGED" = "true" ]; then
        K8S_PSS="privileged"
    elif [ "$SECCOMP" = "disabled" ]; then
        K8S_PSS="baseline"
    else
        K8S_PSS="restricted"
    fi

    # Sidecar detection
    if [ -n "${ISTIO_META_MESH_ID:-}" ] || [ -n "${ISTIO_PROXY_VERSION:-}" ]; then
        K8S_HAS_SIDECAR="true"
        K8S_SIDECAR_TYPE="istio"
    elif [ -n "${LINKERD_PROXY_VERSION:-}" ] || [ -n "${LINKERD2_PROXY_LOG:-}" ]; then
        K8S_HAS_SIDECAR="true"
        K8S_SIDECAR_TYPE="linkerd"
    fi
    # Scan /proc for envoy or linkerd-proxy processes if not already found
    if [ "$K8S_HAS_SIDECAR" = "false" ] && [ -d /proc ]; then
        for _pid_dir in /proc/[0-9]*; do
            _comm=$(cat "$_pid_dir/comm" 2>/dev/null || true)
            case "$_comm" in
                envoy|pilot-agent)
                    K8S_HAS_SIDECAR="true"
                    K8S_SIDECAR_TYPE="istio"
                    break ;;
                linkerd2-proxy|linkerd-proxy)
                    K8S_HAS_SIDECAR="true"
                    K8S_SIDECAR_TYPE="linkerd"
                    break ;;
            esac
        done
    fi

    # Node access indicators
    if [ "$NS_PID" = "false" ]; then
        K8S_NODE_ACCESS=$(list_append "$K8S_NODE_ACCESS" "\"hostPID\"")
    fi
    # hostNetwork — if we see many interfaces or docker0/cbr0
    if [ -d /sys/class/net/docker0 ] || [ -d /sys/class/net/cbr0 ]; then
        K8S_NODE_ACCESS=$(list_append "$K8S_NODE_ACCESS" "\"hostNetwork\"")
    fi
    # hostPath — check for host mount indicators
    if [ -d /host ] || [ -d /hostfs ]; then
        K8S_NODE_ACCESS=$(list_append "$K8S_NODE_ACCESS" "\"hostPath\"")
    fi
}

# ---------------------------------------------------------------------------
# Available tools
# ---------------------------------------------------------------------------

collect_tools() {
    TOOLS_JSON=""
    for _t in \
        curl wget python python3 gcc make mount umount nsenter \
        ip ss nmap nc ncat socat perl ruby gdb strace ltrace \
        capsh apt apk yum dpkg pip pip3 bash sh tar gzip \
        awk sed grep find xargs crontab at \
        docker containerd ctr runc crio crictl kubectl; do
        if command -v "$_t" >/dev/null 2>&1; then
            TOOLS_JSON=$(list_append "$TOOLS_JSON" "\"$_t\"")
        fi
    done
}

# ---------------------------------------------------------------------------
# Main — collect everything and emit JSON
# ---------------------------------------------------------------------------

main() {
    TIMESTAMP=$(get_timestamp)
    HOSTNAME=$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || echo "unknown")
    KVER=$(get_kernel_version)
    KMAJOR=$(parse_kernel_major "$KVER")
    KMINOR=$(parse_kernel_minor "$KVER")
    KPATCH=$(parse_kernel_patch "$KVER")

    collect_capabilities
    collect_mounts
    collect_namespaces
    collect_security
    collect_network
    collect_credentials
    collect_runtime
    detect_cgroup_version
    collect_writable_paths
    collect_kubernetes
    collect_tools

    # Emit JSON
    printf '{\n'
    printf '  "enumeration_version": %s,\n' "$(json_str "$ENUM_VERSION")"
    printf '  "timestamp": %s,\n' "$(json_str "$TIMESTAMP")"
    printf '  "hostname": %s,\n' "$(json_str "$HOSTNAME")"

    # kernel
    printf '  "kernel": {\n'
    printf '    "version": %s,\n' "$(json_str "$KVER")"
    printf '    "major": %s,\n' "$(json_int "$KMAJOR")"
    printf '    "minor": %s,\n' "$(json_int "$KMINOR")"
    printf '    "patch": %s\n' "$(json_int "$KPATCH")"
    printf '  },\n'

    # capabilities
    printf '  "capabilities": {\n'
    printf '    "effective": [%s],\n' "$CAP_EFF"
    printf '    "bounding": [%s],\n' "$CAP_BND"
    printf '    "permitted": [%s]\n' "$CAP_PRM"
    printf '  },\n'

    # mounts
    printf '  "mounts": [%s],\n' "$MOUNTS_JSON"

    # namespaces
    printf '  "namespaces": {\n'
    printf '    "pid": %s,\n' "$(json_bool "$NS_PID")"
    printf '    "net": %s,\n' "$(json_bool "$NS_NET")"
    printf '    "mnt": %s,\n' "$(json_bool "$NS_MNT")"
    printf '    "user": %s,\n' "$(json_bool "$NS_USER")"
    printf '    "uts": %s,\n' "$(json_bool "$NS_UTS")"
    printf '    "ipc": %s,\n' "$(json_bool "$NS_IPC")"
    printf '    "cgroup": %s\n' "$(json_bool "$NS_CGROUP")"
    printf '  },\n'

    # security
    printf '  "security": {\n'
    printf '    "seccomp": %s,\n' "$(json_str "$SECCOMP")"
    printf '    "apparmor": %s,\n' "$(json_str_or_null "$APPARMOR")"
    printf '    "selinux": %s\n' "$(json_str_or_null "$SELINUX")"
    printf '  },\n'

    # network
    printf '  "network": {\n'
    printf '    "interfaces": [%s],\n' "$IFACES_JSON"
    printf '    "can_reach_metadata": %s,\n' "$(json_bool "$CAN_REACH_METADATA")"
    printf '    "can_reach_docker_sock": %s,\n' "$(json_bool "$CAN_REACH_DOCKER_SOCK")"
    printf '    "can_reach_containerd_sock": %s,\n' "$(json_bool "$CAN_REACH_CONTAINERD_SOCK")"
    printf '    "can_reach_crio_sock": %s,\n' "$(json_bool "$CAN_REACH_CRIO_SOCK")"
    printf '    "listening_ports": [%s]\n' "$LISTENING_PORTS"
    printf '  },\n'

    # credentials
    printf '  "credentials": {\n'
    printf '    "service_account_token": %s,\n' "$(json_bool "$SA_TOKEN")"
    printf '    "environment_secrets": [%s],\n' "$ENV_SECRETS"
    printf '    "cloud_metadata_available": %s\n' "$(json_bool "$CLOUD_META")"
    printf '  },\n'

    # runtime
    printf '  "runtime": {\n'
    printf '    "runtime": %s,\n' "$(json_str "$RUNTIME")"
    printf '    "runtime_version": %s,\n' "$(json_str_or_null "$RUNTIME_VERSION")"
    printf '    "orchestrator": %s,\n' "$(json_str_or_null "$ORCHESTRATOR")"
    printf '    "privileged": %s,\n' "$(json_bool "$PRIVILEGED")"
    printf '    "pid_one": %s,\n' "$(json_str "$PID_ONE")"
    printf '    "runc_version": %s\n' "$(json_str_or_null "$RUNC_VERSION")"
    printf '  },\n'

    # kubernetes
    printf '  "kubernetes": {\n'
    printf '    "rbac_permissions": [%s],\n' "$K8S_RBAC_PERMS"
    printf '    "pod_security_standard": %s,\n' "$(json_str_or_null "$K8S_PSS")"
    printf '    "has_sidecar": %s,\n' "$(json_bool "$K8S_HAS_SIDECAR")"
    printf '    "sidecar_type": %s,\n' "$(json_str_or_null "$K8S_SIDECAR_TYPE")"
    printf '    "node_access_indicators": [%s],\n' "$K8S_NODE_ACCESS"
    printf '    "namespace": %s,\n' "$(json_str_or_null "$K8S_NAMESPACE")"
    printf '    "pod_name": %s,\n' "$(json_str_or_null "$K8S_POD_NAME")"
    printf '    "node_name": %s\n' "$(json_str_or_null "$K8S_NODE_NAME")"
    printf '  },\n'

    printf '  "cgroup_version": %s,\n' "$(json_int "$CGROUP_VERSION")"
    printf '  "writable_paths": [%s],\n' "$WRITABLE_PATHS"
    printf '  "available_tools": [%s]\n' "$TOOLS_JSON"
    printf '}\n'
}

main
