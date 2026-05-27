# Cepheus

Container escape path enumerator and analyzer.

## How it works

Cepheus has two components. A POSIX shell enumerator runs inside a container and dumps its security posture to JSON. A Python analysis engine ingests that JSON, matches findings against 65 known escape techniques, builds single- and multi-step attack chains with scored PoC commands, and outputs prioritized results. Chains are ranked by a composite of reliability, stealth, and confidence.

## Install

Pick the form that fits where you're running Cepheus. Full details in
[docs/INSTALL.md](docs/INSTALL.md).

```bash
# Container (CI-friendly, no Python required)
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  ghcr.io/su1ph3r/cepheus:latest ci nginx:latest --max-severity critical

# Single binary (Linux/macOS/Windows, no Python required)
curl -L -o cepheus \
  https://github.com/Su1ph3r/Cepheus/releases/latest/download/cepheus-linux-amd64
chmod +x cepheus && ./cepheus --version

# Homebrew (macOS + Linux)
brew tap su1ph3r/cepheus https://github.com/Su1ph3r/Cepheus
brew install cepheus

# Scoop (Windows)
scoop install https://raw.githubusercontent.com/Su1ph3r/Cepheus/main/scoop/cepheus.json

# pip (existing Python env)
pip install git+https://github.com/Su1ph3r/Cepheus@v0.4.2

# Source (contributors)
git clone https://github.com/su1ph3r/Cepheus.git && cd Cepheus
pip install -e '.[dev,html,llm]'
```

## Usage

```bash
# enumerate a running container
docker cp enumerator/cepheus-enum.sh mycontainer:/tmp/
docker exec mycontainer sh /tmp/cepheus-enum.sh > posture.json

# or use the built-in enumerate command
cepheus enumerate --container-id mycontainer --runtime docker -o posture.json
```

```bash
# analyze escape paths
cepheus analyze posture.json
cepheus analyze posture.json --min-severity high
cepheus analyze posture.json --format json -o report.json
cepheus analyze posture.json --format mitre -o layer.json
cepheus analyze posture.json --format html -o report.html
```

```bash
# compare before/after hardening
cepheus diff before.json after.json
cepheus diff before.json after.json --format json -o delta.json
```

```bash
# CI gate — fail the build on critical chains; SARIF for GitHub Code Scanning
cepheus ci my-app:${GITHUB_SHA} --max-severity critical -f sarif -o cepheus.sarif

# Regression-only gate — fail only when NEW chains appear vs. baseline
cepheus ci my-app:${GITHUB_SHA} --baseline baseline.sarif --fail-on-new -f sarif -o out.sarif
```

```bash
# browse techniques
cepheus techniques
cepheus techniques --category capability
cepheus techniques --search "sys_admin"
cepheus techniques --severity critical
```

See [docs/CI.md](docs/CI.md) for the full CI integration guide, including
the GitHub Actions workflow that uploads SARIF to Code Scanning.

## Technique coverage

65 techniques across 6 categories:

- Capability-based: 9 techniques (SYS_ADMIN, SYS_PTRACE, DAC_READ_SEARCH, DAC_OVERRIDE, NET_ADMIN, SYS_RAWIO, BPF probe_write_user, and more)
- Mount-based: 15 techniques (docker.sock, containerd/CRI-O sockets, core_pattern, sysrq, sysfs, host path mounts, cgroup fs, /dev, shared /dev/shm, /proc/self/fd, device-mapper, /proc/sys/vm)
- Kernel CVE-based: 17 techniques (CVE-2022-0185, CVE-2022-0847 DirtyPipe, CVE-2024-1086, CVE-2024-21626, CVE-2025-21756, CVE-2024-23651/23652/23653 BuildKit, and 10 more)
- Runtime/orchestrator: 14 techniques (K8s service account, kubelet API, etcd, Docker API, containerd shim, runc CVE-2019-5736, cloud metadata SSRF, NVIDIA CVEs, IngressNightmare CVE-2025-1974)
- Combinatorial: 6 multi-prerequisite chains plus dynamic two-step chain building
- Information disclosure: 4 techniques (env var secrets, cloud metadata credentials, K8s secret mounts, Docker env inspection)

## Scoring

```
composite = (reliability × 0.40 + stealth × 0.25 + confidence × 0.35) × length_penalty
```

Chains are ranked highest-score-first. Multi-step chains receive a 15%-per-step length penalty. Missing posture data defaults to 0.3 confidence rather than discarding the technique.

## Configuration

```bash
CEPHEUS_MIN_CONFIDENCE=0.3              # minimum confidence threshold
CEPHEUS_MAX_CHAIN_LENGTH=3              # maximum chain step count
CEPHEUS_WEIGHT_RELIABILITY=0.40         # scoring weight: reliability
CEPHEUS_WEIGHT_STEALTH=0.25             # scoring weight: stealth
CEPHEUS_WEIGHT_CONFIDENCE=0.35          # scoring weight: confidence
CEPHEUS_CHAIN_LENGTH_PENALTY=0.15       # per-step penalty
CEPHEUS_SANDBOX_MITIGATION_FACTOR=0.6   # score reduction for sandbox runtimes
CEPHEUS_KERNEL_ONLY_MAX_CONFIDENCE=0.5  # cap on techniques with only kernel-version prereqs
CEPHEUS_DISTRO_KERNEL_MAX_CONFIDENCE=0.2  # further cap when kernel is a backport-maintained distro build (WSL2/EKS/AKS/GKE/RHEL/...)
CEPHEUS_LLM_MODEL=anthropic/claude-sonnet-4-20250514  # litellm model string
CEPHEUS_LLM_API_KEY=sk-...              # API key for LLM enrichment
CEPHEUS_LLM_TEMPERATURE=0.3             # LLM sampling temperature
CEPHEUS_LLM_MAX_TOKENS=4096             # LLM max response tokens
```

## Enumerator details

The enumerator is an 849-line POSIX shell script with zero external dependencies — it runs under busybox sh, dash, bash, and inside distroless or scratch containers. It collects capabilities (full hex decode of CapEff/CapBnd/CapPrm), mounts and filesystem types (with backslash-safe JSON escaping), kernel version, cgroup v1/v2 detection, seccomp mode, AppArmor/SELinux profiles, namespace isolation via inode comparison, network interfaces, cloud metadata reachability, socket access, K8s service account tokens, secret-pattern env vars, runtime detection (with `/proc/self/mountinfo` fallback for kind/k3s/EKS), RBAC permissions, 30+ tool availability checks, and writable sensitive paths.

## LLM support

LLM enrichment is optional and adds novel combination analysis, contextual remediation, and executive summaries via LiteLLM. Install with `pip install -e ".[llm]"` and pass `--llm` to the analyze command.

## Testing

```bash
pip install -e ".[dev]"
pytest
pytest --cov=cepheus --cov-report=term
```

## License

[MIT](LICENSE)
