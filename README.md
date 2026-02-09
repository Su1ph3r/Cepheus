# Cepheus

**Container Escape Scenario Modeler** — enumerate container security posture and model realistic escape paths with ranked attack chains, tailored PoC commands, and actionable remediation.

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-105%20passing-brightgreen.svg)](#testing)

---

## What is Cepheus?

Cepheus is a two-component container security tool that answers one question: **"Can an attacker escape this container, and how?"**

1. **Enumerator** — a zero-dependency POSIX shell script that runs inside any container and dumps its full security posture to JSON (capabilities, mounts, kernel version, seccomp, AppArmor, namespaces, cgroups, credentials, network config, writable paths, and available tools).

2. **Analysis Engine** — a Python CLI that ingests the enumerator's JSON output, maps findings against **44 known escape techniques** across 6 categories, builds single-step and multi-step attack chains, generates tailored PoC commands, scores each chain by reliability and stealth, and produces prioritized remediation guidance.

Named after the constellation Cepheus — the king who watches over the heavens — it watches over container boundaries.

## Why Cepheus?

| Feature | deepce | CDK | amicontained | BOtB | Cepheus |
|---|:---:|:---:|:---:|:---:|:---:|
| Capability enumeration | Partial | Yes | Yes | Partial | **Full** |
| Kernel CVE correlation | - | - | - | - | **10 CVEs** |
| Runtime version detection | - | Partial | - | - | **Yes** |
| Combinatorial chain analysis | - | - | - | - | **6 combos** |
| Escape path scoring | - | - | - | - | **Weighted** |
| PoC generation | - | Some | - | Some | **All 44** |
| Defense enumeration | - | - | Partial | - | **Full** |
| 2024-2025 CVEs | - | - | - | - | **Yes** |
| Stealth scoring | - | - | - | - | **Yes** |
| Multi-step chain building | - | - | - | - | **Yes** |
| LLM enrichment | - | - | - | - | **Optional** |
| Zero-dependency enumerator | - | Go binary | Go binary | Go binary | **POSIX shell** |

## Quick Start

### Install

```bash
# From source
git clone https://github.com/su1ph3r/Cepheus.git
cd Cepheus
pip install -e .

# With LLM support
pip install -e ".[llm]"
```

### Enumerate a Container

```bash
# Copy the enumerator into a running container and execute it
docker cp enumerator/cepheus-enum.sh mycontainer:/tmp/
docker exec mycontainer sh /tmp/cepheus-enum.sh > posture.json

# Or use the built-in enumerate command
cepheus enumerate --container-id mycontainer --runtime docker -o posture.json
```

### Analyze Escape Paths

```bash
# Full analysis with terminal output
cepheus analyze posture.json

# Filter by severity
cepheus analyze posture.json --min-severity high

# JSON output for automation
cepheus analyze posture.json --format json -o report.json

# With LLM-powered novel pattern analysis
cepheus analyze posture.json --llm
```

### Browse Techniques

```bash
# List all 44 techniques
cepheus techniques

# Filter by category
cepheus techniques --category capability
cepheus techniques --category kernel

# Search
cepheus techniques --search "sys_admin"
cepheus techniques --severity critical
```

## Technique Coverage

Cepheus covers **44 escape techniques** across 6 categories:

### Capability-Based (8)
Escapes leveraging Linux capabilities: `CAP_SYS_ADMIN` mount/cgroup/BPF attacks, `CAP_SYS_PTRACE` process injection, `CAP_DAC_READ_SEARCH` and `CAP_DAC_OVERRIDE` for bypassing file permissions, `CAP_NET_ADMIN` network namespace manipulation, and `CAP_SYS_RAWIO` raw device I/O.

### Mount-Based (8)
Docker socket mounts, `/proc/sys/kernel/core_pattern` writes, `/proc/sysrq-trigger` abuse, sysfs exploitation, writable host path mounts (`/etc`, `/`), cgroup filesystem escapes, and `/dev` device access.

### Kernel CVE-Based (10)
- **CVE-2022-0185** — FSConfig heap overflow (5.1–5.16.2)
- **CVE-2022-0847** — DirtyPipe (5.8–5.16.11)
- **CVE-2021-22555** — Netfilter heap OOB write (2.6.19–5.12)
- **CVE-2022-2588** — route4 use-after-free (< 5.19.2)
- **CVE-2023-0386** — OverlayFS privilege escalation (5.11–6.2)
- **CVE-2023-32233** — nf_tables use-after-free (< 6.4)
- **CVE-2024-1086** — nf_tables double-free (3.15–6.8)
- **CVE-2021-31440** — eBPF verifier bypass
- **CVE-2022-23222** — eBPF type confusion
- **CVE-2024-21626** — runc process.cwd container breakout

### Runtime / Orchestrator (8)
Kubernetes service account abuse, kubelet API access, etcd direct access, unauthenticated Docker API, containerd shim escape, runc `/proc/self/exe` overwrite (CVE-2019-5736), cloud metadata SSRF, and kubelet node proxy.

### Combinatorial (6)
Multi-prerequisite chains: `SYS_ADMIN + no seccomp`, `privileged + docker.sock`, `NET_RAW + metadata`, `writable procfs + privileged`, `user namespace + kernel CVE`, `SYS_ADMIN + no AppArmor`.

### Information Disclosure (4)
Environment variable secret leaks, cloud instance credential theft via metadata service, Kubernetes configmap/secret volume mounts, and Docker environment inspection via API.

## Scoring Model

Each escape chain receives a **composite score** based on three weighted factors:

```
composite = (reliability × 0.40 + stealth × 0.25 + confidence × 0.35) × length_penalty
```

| Factor | Weight | Description |
|---|---|---|
| **Reliability** | 0.40 | How consistently the technique succeeds |
| **Stealth** | 0.25 | Likelihood of evading monitoring/detection |
| **Confidence** | 0.35 | How certain we are prerequisites are met |
| **Length penalty** | -15%/step | Multi-step chains are penalized for complexity |

Chains are ranked highest-score-first. Missing posture data uses a configurable default confidence (0.3) rather than discarding the technique — incomplete enumeration degrades gracefully.

## Enumerator

The enumerator is a **582-line POSIX shell script** with zero external dependencies. It runs anywhere:

| Environment | Shell | Status |
|---|---|---|
| Alpine | busybox sh | Supported |
| Ubuntu / Debian | dash / bash | Supported |
| Distroless | (copy script in) | Supported |
| Scratch containers | (copy script in) | Supported |

What it enumerates:
- **Capabilities** — full hex decode of CapEff, CapBnd, CapPrm from `/proc/self/status`
- **Mounts** — all mount points, filesystem types, and options
- **Kernel** — version parsed into major.minor.patch for CVE correlation
- **Cgroups** — v1 vs v2 detection
- **Security** — seccomp mode, AppArmor profile, SELinux context
- **Namespaces** — PID/net/mnt/user/UTS/IPC/cgroup isolation via inode comparison
- **Network** — interfaces, cloud metadata reachability, Docker socket access, listening ports
- **Credentials** — K8s service account tokens, environment variable names matching secret patterns, cloud metadata availability
- **Runtime** — Docker/containerd/cri-o/Kubernetes detection, PID 1 process
- **Tools** — 30+ binary availability checks (curl, wget, gcc, mount, nsenter, etc.)
- **Writable paths** — sensitive path write access testing

Output is a single JSON object conforming to the `ContainerPosture` schema.

## Configuration

All settings are configurable via environment variables with the `CEPHEUS_` prefix:

```bash
# Analysis
export CEPHEUS_MIN_CONFIDENCE=0.3          # Minimum confidence threshold
export CEPHEUS_MAX_CHAIN_LENGTH=3          # Maximum chain step count

# Scoring weights (must sum to 1.0)
export CEPHEUS_WEIGHT_RELIABILITY=0.40
export CEPHEUS_WEIGHT_STEALTH=0.25
export CEPHEUS_WEIGHT_CONFIDENCE=0.35
export CEPHEUS_CHAIN_LENGTH_PENALTY=0.15   # Per-step penalty

# LLM enrichment (optional)
export CEPHEUS_LLM_MODEL=anthropic/claude-sonnet-4-20250514
export CEPHEUS_LLM_API_KEY=sk-...
export CEPHEUS_LLM_TEMPERATURE=0.3
export CEPHEUS_LLM_MAX_TOKENS=4096
```

## Architecture

```
Enumerator (POSIX sh)          Analysis Engine (Python)
┌──────────────┐               ┌──────────────────────┐
│ cepheus-enum │──── JSON ────→│ Matcher              │
│   .sh        │               │   ↓                  │
└──────────────┘               │ Chainer              │
                               │   ↓                  │
                               │ Scorer               │
                               │   ↓                  │
                               │ Output (terminal/JSON)│
                               │   ↓ (optional)       │
                               │ LLM Enrichment       │
                               └──────────────────────┘
```

For full architecture details, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## LLM Integration

LLM enrichment is **optional** — the core analysis is fully deterministic. When enabled with `--llm`, it adds:

- **Novel combination analysis** — identifies escape patterns not in the technique database
- **Contextual remediation** — tailored advice for your specific environment
- **Executive summary** — natural language overview of findings

Powered by [LiteLLM](https://github.com/BerriAI/litellm), supporting OpenAI, Anthropic, local models, and 100+ providers.

```bash
pip install cepheus[llm]
export CEPHEUS_LLM_API_KEY=your-key
cepheus analyze posture.json --llm
```

## Testing

```bash
pip install -e ".[dev]"
pytest                                     # 105 tests
pytest --cov=cepheus --cov-report=term     # with coverage
```

## Use Cases

- **Penetration testing** — identify container escape paths during authorized engagements
- **Red team exercises** — model attack chains with realistic PoC commands
- **Blue team hardening** — scan containers for misconfigurations with prioritized remediations
- **CI/CD security gates** — integrate JSON output into pipeline checks
- **Security audits** — document container security posture with evidence
- **Training and CTFs** — learn container escape techniques with hands-on PoCs

## Responsible Use

Cepheus is a **defensive security tool** for authorized assessments. Do not use it against systems you do not own or have explicit written permission to test. See [SECURITY.md](SECURITY.md) for the full security policy.

## Contributing

Contributions welcome — especially new escape techniques and CVEs. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE) — Copyright (c) 2026 su1ph3r
