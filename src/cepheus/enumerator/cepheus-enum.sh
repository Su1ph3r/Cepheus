#!/bin/sh
# cepheus-enum.sh — Zero-dependency POSIX shell container security enumerator.
# Outputs a JSON blob (ContainerPosture schema) to stdout.
# Works in Alpine (busybox sh), Debian (dash), and distroless (if copied in).
# Usage: sh cepheus-enum.sh

ENUM_VERSION="0.1.0"

# ---------------------------------------------------------------------------
# JSON helpers
# ---------------------------------------------------------------------------

json_str() { printf '"%s"' "$(printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr '\t' ' ' | tr '\n' ' ' | tr -d '\r')"; }
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
# TCP reachability probe
# ---------------------------------------------------------------------------
#
# Returns 0 (true) if host:port is TCP-reachable within $3 seconds (default
# 1s), non-zero otherwise. Used to confirm whether vulnerable components
# (etcd, kubelet API, ingress webhooks) are actually reachable from this
# pod, not just hypothetically "in the cluster". Tries multiple probe
# methods because distroless / busybox containers may lack any one of
# them — graceful degradation when nothing works (returns non-zero).
#
# Usage:
#   if tcp_probe etcd.kube-system.svc 2379; then ... fi
#   if tcp_probe 127.0.0.1 10250 2; then ... fi   # 2-second timeout

tcp_probe() {
    _host=$1
    _port=$2
    _to=${3:-1}
    # Methods are ordered by timeout reliability. Each method has an
    # explicit per-attempt timeout so a single hung probe can't blow
    # past kubectl exec's outer deadline (default 60s).
    #
    # Method 1: nc (netcat) with -z (scan only) + -w (timeout) — both
    # busybox and OpenBSD nc support this. Preferred when present.
    if command -v nc >/dev/null 2>&1; then
        if nc -z -w "$_to" "$_host" "$_port" >/dev/null 2>&1; then
            return 0
        fi
        return 1
    fi
    # Method 2: curl on bare TCP. `--connect-timeout` bounds DNS+SYN,
    # `--max-time` bounds the whole call. Works in every K8s pod that
    # has curl, which is most of them.
    if command -v curl >/dev/null 2>&1; then
        if curl -sf --connect-timeout "$_to" --max-time "$_to" \
            "telnet://$_host:$_port" >/dev/null 2>&1; then
            return 0
        fi
        return 1
    fi
    # Method 3: python3 socket — present on most K8s workloads.
    if command -v python3 >/dev/null 2>&1; then
        if python3 -c "import socket,sys; s=socket.socket(); s.settimeout($_to); s.connect(('$_host',$_port)); s.close()" >/dev/null 2>&1; then
            return 0
        fi
        return 1
    fi
    # Method 4: last-resort bash /dev/tcp. NO native timeout — fall
    # through only if everything else is missing. Wrap with `timeout`
    # if available; otherwise skip rather than risk a 60s OS-level
    # connect timeout.
    if command -v bash >/dev/null 2>&1 && command -v timeout >/dev/null 2>&1; then
        if timeout "$_to" bash -c "exec 3<>/dev/tcp/$_host/$_port" >/dev/null 2>&1; then
            return 0
        fi
    fi
    return 1
}

# ---------------------------------------------------------------------------
# Kubernetes API call helper
# ---------------------------------------------------------------------------
#
# Make an authenticated request to the in-cluster K8s API using the pod's
# SA token. Echoes the response body on stdout, returns non-zero on
# failure (missing token, no curl, HTTP error, timeout). Path argument
# should start with /; full URL is constructed against $KUBERNETES_SERVICE_HOST.
#
# Token is passed via curl's -H @file (not -H "Authorization: ..." inline)
# to avoid leaking it via `ps aux` while curl is running.
#
# Usage:
#   resp=$(k8s_api_get /api/v1/namespaces/$NS/pods/$POD)
#   resp=$(k8s_api_post /apis/.../selfsubjectrulesreviews "$body")

_k8s_api_call() {
    _method=$1
    _path=$2
    _body=${3:-}
    [ -z "${KUBERNETES_SERVICE_HOST:-}" ] && return 1
    command -v curl >/dev/null 2>&1 || return 1
    [ -f /var/run/secrets/kubernetes.io/serviceaccount/token ] || return 1

    _token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token 2>/dev/null || true)
    [ -n "$_token" ] || return 1

    _hdr_file=$(mktemp /tmp/_cepheus_hdr_XXXXXX 2>/dev/null || echo "/tmp/_cepheus_hdr$$")
    printf 'Authorization: Bearer %s' "$_token" > "$_hdr_file"
    chmod 600 "$_hdr_file" 2>/dev/null

    _cacert="-k"
    if [ -f /var/run/secrets/kubernetes.io/serviceaccount/ca.crt ]; then
        _cacert="--cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
    fi

    _port=${KUBERNETES_SERVICE_PORT:-443}
    _url="https://${KUBERNETES_SERVICE_HOST}:${_port}${_path}"
    _curl_rc=0
    if [ "$_method" = "GET" ]; then
        # shellcheck disable=SC2086  # _cacert holds two tokens by design
        curl -sf --max-time 3 $_cacert -H @"$_hdr_file" "$_url" 2>/dev/null || _curl_rc=$?
    else
        # shellcheck disable=SC2086
        curl -sf --max-time 3 $_cacert -H @"$_hdr_file" \
            -X "$_method" -H "Content-Type: application/json" \
            -d "$_body" "$_url" 2>/dev/null || _curl_rc=$?
    fi
    rm -f "$_hdr_file"
    return $_curl_rc
}

k8s_api_get()  { _k8s_api_call GET  "$1"; }
k8s_api_post() { _k8s_api_call POST "$1" "$2"; }

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
                # Use json_str to escape backslashes / quotes / control chars —
                # WSL DrvFS exposes options like `path=C:\;...` which break the
                # JSON output if embedded verbatim.
                _opts_json=$(list_append "$_opts_json" "$(json_str "$_o")")
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

    # AppArmor. Distinguish three states for the matcher:
    #   "unconfined"  -> AppArmor IS active on the host but this container opted
    #                    out (a real finding).
    #   "<profile>"   -> confined (no finding).
    #   ""  (-> null) -> UNKNOWN: the attr file is absent (host has no AppArmor
    #                    LSM, e.g. Docker Desktop/WSL2) or unreadable. Reporting
    #                    "unconfined" here was a false positive on every such
    #                    host, so we leave it null and the technique does not fire.
    APPARMOR=""
    if [ -f /proc/self/attr/current ]; then
        _aa=$(cat /proc/self/attr/current 2>/dev/null | tr -d '\000')
        case "$_aa" in
            "") APPARMOR="" ;;
            "unconfined") APPARMOR="unconfined" ;;
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

    # ── component-presence TCP probes ────────────────────────────────
    # These populate fields the matcher (v0.3.1+) uses to gate techniques
    # on actual reachability. They are best-effort; failures or missing
    # probe tools leave the field at the model default (None / False).
    CAN_REACH_ETCD="null"
    CAN_REACH_KUBELET_API="null"
    COMPONENT_REACHABILITY=""

    if [ -n "${KUBERNETES_SERVICE_HOST:-}" ]; then
        # Only run cluster-internal probes when there's an API server. On
        # non-K8s hosts the etcd/kubelet probes would be noise.

        # etcd — typical control-plane port 2379. Try several locations:
        # the API-server host (often the same node on single-node kind /
        # k3s clusters) and the in-cluster `etcd` service.
        if tcp_probe "${KUBERNETES_SERVICE_HOST}" 2379 \
            || tcp_probe etcd.kube-system.svc.cluster.local 2379; then
            CAN_REACH_ETCD="true"
        else
            CAN_REACH_ETCD="false"
        fi

        # kubelet API — listens on the node IP on 10250 (auth) and 10255
        # (legacy read-only, often disabled). The node IP is the default
        # gateway from inside the pod's network namespace.
        _node_ip=""
        if [ -f /proc/net/route ]; then
            # Field 3 is gateway in hex, little-endian. Pick the line whose
            # destination is 00000000 (default route).
            _hex_gw=$(awk '$2=="00000000" {print $3; exit}' /proc/net/route 2>/dev/null)
            if [ -n "$_hex_gw" ] && [ ${#_hex_gw} -eq 8 ]; then
                # Convert little-endian hex (e.g. 010110AC) to dotted quad
                # by reading byte pairs right-to-left.
                _o1=$(printf '%d' "0x${_hex_gw##??????}")
                _o2=$(printf '%d' "0x$(echo "$_hex_gw" | cut -c5-6)")
                _o3=$(printf '%d' "0x$(echo "$_hex_gw" | cut -c3-4)")
                _o4=$(printf '%d' "0x$(echo "$_hex_gw" | cut -c1-2)")
                _node_ip="$_o1.$_o2.$_o3.$_o4"
            fi
        fi
        if [ -n "$_node_ip" ] && tcp_probe "$_node_ip" 10250; then
            CAN_REACH_KUBELET_API="true"
        else
            CAN_REACH_KUBELET_API="false"
        fi

        # Generic component reachability map — keyed by short component
        # name, value true/false. Probes the standard in-cluster Service
        # endpoints for components whose CVEs Cepheus tracks. Failures
        # are recorded as false so the matcher can distinguish "probed
        # and absent" from "never probed".
        for _comp in \
            "ingress-nginx-controller.ingress-nginx.svc.cluster.local:443:ingress-nginx" \
            "argocd-server.argocd.svc.cluster.local:443:argocd" \
            "harbor.harbor.svc.cluster.local:443:harbor" \
            "buildkitd.buildkit.svc.cluster.local:1234:buildkit"; do
            _h=$(echo "$_comp" | cut -d: -f1)
            _p=$(echo "$_comp" | cut -d: -f2)
            _name=$(echo "$_comp" | cut -d: -f3)
            if tcp_probe "$_h" "$_p"; then
                COMPONENT_REACHABILITY=$(list_append "$COMPONENT_REACHABILITY" "$(json_str "$_name"): true")
            else
                COMPONENT_REACHABILITY=$(list_append "$COMPONENT_REACHABILITY" "$(json_str "$_name"): false")
            fi
        done
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
            # Benign PUBLIC key material — package-signing keys, key IDs,
            # keyrings, public keys, known_hosts. These match *KEY* but are not
            # secrets; flagging them (GPG_KEYS, *_PGP_KEY_ID, etc.) was a false
            # positive. Skipped before the secret match below. Note real private
            # material (PRIVATE_KEY, SECRET_KEY, API_KEY, ACCESS_KEY) does NOT
            # match these globs and still gets flagged.
            *GPG*|*PGP*|*PUBLIC*|*KEYRING*|*KEYSERVER*|*KEY_ID|*KEY_FINGERPRINT|*KNOWN_HOSTS*)
                : ;;
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

    # Runtime detection — try several signals, ordered most-specific first.
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
    # Fallback — inspect mountinfo for runtime-specific overlay paths. Useful
    # on kind/EKS/GKE/k3s where /run/containerd isn't mounted into the pod and
    # /.dockerenv isn't present, but the overlay snapshot path identifies the
    # runtime unambiguously.
    if [ "$RUNTIME" = "unknown" ] && [ -r /proc/self/mountinfo ]; then
        _mi=$(cat /proc/self/mountinfo 2>/dev/null)
        case "$_mi" in
            *io.containerd.snapshotter*) RUNTIME="containerd" ;;
            *docker/overlay2*)            RUNTIME="docker" ;;
            *cri-o*)                      RUNTIME="cri-o" ;;
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

    # runc version detection — several fallbacks because most workload
    # containers don't have runc on PATH. The v0.3.1 matcher uses this
    # to gate CVE-2019-5736 (runc proc/self/exe overwrite) on a real
    # version comparison instead of firing speculatively.
    RUNC_VERSION=""
    # Method 1: runc directly on PATH (debug containers, build images).
    if command -v runc >/dev/null 2>&1; then
        RUNC_VERSION=$(runc --version 2>/dev/null | head -1 | awk '{print $NF}' || true)
    fi
    # Method 2: /proc/1/exe sometimes resolves to the runc binary itself
    # in pods spawned by older runtimes. Cheap to check.
    if [ -z "$RUNC_VERSION" ] && [ -r /proc/1/exe ]; then
        _exe=$(readlink /proc/1/exe 2>/dev/null || true)
        case "$_exe" in
            *runc*)
                RUNC_VERSION=$("$_exe" --version 2>/dev/null | head -1 | awk '{print $NF}' || true)
                ;;
        esac
    fi
    # Method 3: scan common host-bind-mounted paths (privileged + hostPath
    # pods often have the host's /usr/bin or /usr/sbin available).
    # IMPORTANT: gate on `timeout` because host binaries executed from
    # inside a container may need shared libraries the container's
    # mount namespace doesn't provide. Without the timeout guard,
    # `--version` can hang for the OS process default (60+ s per attempt).
    if [ -z "$RUNC_VERSION" ] && command -v timeout >/dev/null 2>&1; then
        for _p in /usr/bin/runc /usr/sbin/runc /usr/local/bin/runc \
                  /host/usr/bin/runc /host-system/usr/bin/runc \
                  /host-root/usr/bin/runc; do
            if [ -x "$_p" ]; then
                RUNC_VERSION=$(timeout 1 "$_p" --version 2>/dev/null | head -1 | awk '{print $NF}' || true)
                [ -n "$RUNC_VERSION" ] && break
            fi
        done
    fi
    # Strip the leading "v" if present (some runc builds report "v1.1.10").
    case "$RUNC_VERSION" in
        v[0-9]*) RUNC_VERSION=${RUNC_VERSION#v} ;;
    esac

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

    # Sandbox runtime detection
    SANDBOX_RUNTIME=""
    if grep -qi "gvisor" /proc/version 2>/dev/null; then
        SANDBOX_RUNTIME="gvisor"
    elif [ -f /sys/class/dmi/id/product_name ] && grep -qi "firecracker" /sys/class/dmi/id/product_name 2>/dev/null; then
        SANDBOX_RUNTIME="firecracker"
    elif [ -d /run/kata-containers ] || [ -f /.kata-containers ]; then
        SANDBOX_RUNTIME="kata"
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
    # v0.3.3 additions — populated by SA-token-driven probes below.
    K8S_CLUSTER_COMPONENTS=""
    K8S_CLUSTER_COMPONENTS_PROBED="false"

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

    # ── Cluster-component scan (v0.3.3) ───────────────────────────────
    # Use the SA token to list pods cluster-wide and detect known
    # components by image-prefix or label. Populates
    # `kubernetes.cluster_components` so the matcher can gate CVE
    # techniques (IngressNightmare etc.) on "is this component actually
    # deployed?" instead of "is this a Kubernetes cluster?".
    #
    # Graceful degradation:
    #   - cluster_components_probed=true   → list is authoritative
    #   - cluster_components_probed=false  → couldn't probe; matcher
    #     should treat as "unknown" via confidence_if_absent.
    _comp_resp=$(k8s_api_get "/api/v1/pods?limit=200" 2>/dev/null || true)
    if [ -n "$_comp_resp" ]; then
        K8S_CLUSTER_COMPONENTS_PROBED="true"
        # POSIX shell can't JSON-parse, so we substring-match on known
        # image prefixes. False positives here would over-trigger CVE
        # matches — keep the patterns specific. False negatives keep
        # the current "drop on absence" behaviour.
        for _pair in \
            "registry.k8s.io/ingress-nginx:ingress-nginx" \
            "k8s.gcr.io/ingress-nginx:ingress-nginx" \
            "docker.io/argoproj/argocd:argocd" \
            "quay.io/argoproj/argocd:argocd" \
            "goharbor/harbor:harbor" \
            "moby/buildkit:buildkit" \
            "docker/buildkit:buildkit" \
            "falcosecurity/falco:falco" \
            "registry.k8s.io/etcd:etcd" \
            "tigera/operator:calico" \
            "cilium/cilium:cilium"; do
            _pattern=${_pair%:*}
            _name=${_pair##*:}
            case "$_comp_resp" in
                *"\"image\":\"$_pattern"*|*"$_pattern/"*)
                    K8S_CLUSTER_COMPONENTS=$(list_append "$K8S_CLUSTER_COMPONENTS" "$(json_str "$_name")")
                    ;;
            esac
        done
    fi

    # ── K8s API self-introspection (v0.3.3) ───────────────────────────
    # When the SA token grants `get pods` on its own namespace, query
    # the API server for the authoritative pod spec and OVERRIDE the
    # heuristic-derived namespaces.{pid,ipc,net} and runtime.privileged
    # values. The inode-comparison heuristics are unreliable on
    # kind/WSL/some CNI plugins; the API answer is ground truth.
    if [ -n "$K8S_NAMESPACE" ] && [ -n "$K8S_POD_NAME" ]; then
        _pod_resp=$(k8s_api_get "/api/v1/namespaces/$K8S_NAMESPACE/pods/$K8S_POD_NAME" 2>/dev/null || true)
        if [ -n "$_pod_resp" ]; then
            # Extract spec.hostPID / hostIPC / hostNetwork / privileged
            # via simple substring matching. Each appears at most once
            # in the response. Missing field means false (K8s default).
            case "$_pod_resp" in
                *'"hostPID":true'*) NS_PID="false" ;;  # NS_PID=false means PID ns shared with host
                *'"hostPID":false'*) NS_PID="true" ;;
            esac
            case "$_pod_resp" in
                *'"hostIPC":true'*) NS_IPC="false" ;;
                *'"hostIPC":false'*) NS_IPC="true" ;;
            esac
            case "$_pod_resp" in
                *'"hostNetwork":true'*) NS_NET="false" ;;
                *'"hostNetwork":false'*) NS_NET="true" ;;
            esac
            # privileged: search for the first occurrence of "privileged":true
            # within a securityContext block. Conservative — keep the cap-set
            # heuristic's True (set above by collect_runtime) and only escalate
            # from False to True when the API confirms.
            case "$_pod_resp" in
                *'"privileged":true'*)
                    if [ "$PRIVILEGED" = "false" ]; then
                        PRIVILEGED="true"
                    fi
                    ;;
            esac
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
    # Scan /proc for envoy or linkerd-proxy processes if not already found.
    #
    # Perf note (CEPH-2): a previous version of this loop iterated every
    # PID visible in /proc. On pods with hostPID:true (e.g. monitoring
    # sidecars, kind-on-WSL nodes) /proc exposes hundreds-to-thousands of
    # host PIDs, turning the per-PID `cat` into a 60-300s hot loop and
    # blowing past `kubectl exec`'s default timeout.
    #
    # Mitigations:
    #   1. Skip the loop entirely when this pod has its own PID namespace
    #      (NS_PID=true). Sidecars live in the pod's PID namespace, so the
    #      env-var check above already covers the common case, and there
    #      is no reason to walk host PIDs.
    #   2. When the loop does run (hostPID:true), cap iteration at the
    #      first $_pid_scan_max PIDs and break early on first match.
    if [ "$K8S_HAS_SIDECAR" = "false" ] && [ "$NS_PID" = "true" ] && [ -d /proc ]; then
        _pid_scan_max=200
        _pid_scanned=0
        for _pid_dir in /proc/[0-9]*; do
            _pid_scanned=$((_pid_scanned + 1))
            if [ "$_pid_scanned" -gt "$_pid_scan_max" ]; then
                break
            fi
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
# GPU detection
# ---------------------------------------------------------------------------

collect_gpu() {
    # NVIDIA devices
    NVIDIA_DEVICES=""
    for dev in /dev/nvidia*; do
        [ -e "$dev" ] || continue
        if [ -z "$NVIDIA_DEVICES" ]; then
            NVIDIA_DEVICES="\"$dev\""
        else
            NVIDIA_DEVICES="$NVIDIA_DEVICES, \"$dev\""
        fi
    done

    # NVIDIA toolkit version
    NVIDIA_TOOLKIT_VERSION=""
    if command -v nvidia-container-toolkit >/dev/null 2>&1; then
        NVIDIA_TOOLKIT_VERSION=$(nvidia-container-toolkit --version 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    fi

    # NVIDIA driver version
    NVIDIA_DRIVER_VERSION=""
    if [ -f /proc/driver/nvidia/version ]; then
        NVIDIA_DRIVER_VERSION=$(head -1 /proc/driver/nvidia/version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1)
    elif command -v nvidia-smi >/dev/null 2>&1; then
        NVIDIA_DRIVER_VERSION=$(nvidia-smi --query-gpu=driver_version --format=csv,noheader 2>/dev/null | head -1)
    fi
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
    collect_gpu
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
    printf '    "listening_ports": [%s],\n' "$LISTENING_PORTS"
    # New in v0.3.3 — populated when KUBERNETES_SERVICE_HOST is set.
    # Schema treats null as "not probed" (analyzer reads as None) so
    # techniques degrade gracefully on non-K8s containers.
    printf '    "can_reach_etcd": %s,\n' "$CAN_REACH_ETCD"
    printf '    "can_reach_kubelet_api": %s,\n' "$CAN_REACH_KUBELET_API"
    printf '    "component_reachability": {%s}\n' "$COMPONENT_REACHABILITY"
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
    printf '    "runc_version": %s,\n' "$(json_str_or_null "$RUNC_VERSION")"
    printf '    "sandbox_runtime": %s\n' "$(json_str_or_null "$SANDBOX_RUNTIME")"
    printf '  },\n'

    # gpu
    printf '  "gpu": {\n'
    printf '    "nvidia_devices": [%s],\n' "$NVIDIA_DEVICES"
    printf '    "nvidia_toolkit_version": %s,\n' "$(json_str_or_null "$NVIDIA_TOOLKIT_VERSION")"
    printf '    "nvidia_driver_version": %s\n' "$(json_str_or_null "$NVIDIA_DRIVER_VERSION")"
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
    printf '    "node_name": %s,\n' "$(json_str_or_null "$K8S_NODE_NAME")"
    # v0.3.3 additions
    printf '    "cluster_components": [%s],\n' "$K8S_CLUSTER_COMPONENTS"
    printf '    "cluster_components_probed": %s\n' "$(json_bool "$K8S_CLUSTER_COMPONENTS_PROBED")"
    printf '  },\n'

    printf '  "cgroup_version": %s,\n' "$(json_int "$CGROUP_VERSION")"
    printf '  "writable_paths": [%s],\n' "$WRITABLE_PATHS"
    printf '  "available_tools": [%s]\n' "$TOOLS_JSON"
    printf '}\n'
}

main
