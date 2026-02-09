# Cepheus Architecture

## Overview

Cepheus is a two-component container escape modeling tool:

1. **Enumerator** (`cepheus-enum.sh`) — POSIX shell script that runs inside a container and dumps its security posture to JSON
2. **Analysis Engine** (`cepheus` CLI) — Python tool that ingests the posture JSON, matches it against 56 known escape techniques, builds attack chains, scores them, and generates remediation guidance

## Data Flow

```
┌─────────────────────────────────┐     ┌──────────────────────────────────────┐
│  Target Container               │     │  Attack Box / Host                   │
│                                 │     │                                      │
│  ┌───────────────────────────┐  │     │  ┌────────────────────────────────┐  │
│  │ cepheus-enum.sh           │  │     │  │ cepheus analyze posture.json   │  │
│  │                           │  │     │  │                                │  │
│  │ • Capabilities (capsh)    │  │     │  │ ┌──────────┐  ┌────────────┐  │  │
│  │ • Mounts (/proc/mounts)   │──┼─JSON─┼──│ Matcher   │→ │ Chainer    │  │  │
│  │ • Kernel (uname -r)       │  │     │  │ └──────────┘  └────────────┘  │  │
│  │ • Cgroups (v1/v2)         │  │     │  │       ↓              ↓        │  │
│  │ • Seccomp status          │  │     │  │ ┌──────────┐  ┌────────────┐  │  │
│  │ • AppArmor/SELinux        │  │     │  │ │ Scorer   │← │ Analyzer   │  │  │
│  │ • Namespaces              │  │     │  │ └──────────┘  └────────────┘  │  │
│  │ • Network config          │  │     │  │       ↓                       │  │
│  │ • Writable paths          │  │     │  │ ┌──────────┐  ┌────────────┐  │  │
│  │ • Available tools         │  │     │  │ │ Terminal │  │ JSON Report│  │  │
│  │ • Runtime detection       │  │     │  │ │ Output   │  │ Output     │  │  │
│  │ • Credentials             │  │     │  │ ├──────────┤  ├────────────┤  │  │
│  │ • Kubernetes metadata     │  │     │  │ │ HTML     │  │ MITRE ATT&K│  │  │
│  │ • Runtime versions        │  │     │  │ │ Report   │  │ Navigator  │  │  │
│  │                           │  │     │  │ └──────────┘  └────────────┘  │  │
│  └───────────────────────────┘  │     │  │       ↓ (optional)           │  │
│                                 │     │  │ ┌──────────────────────────┐  │  │
│                                 │     │  │ │ LLM Enrichment          │  │  │
│                                 │     │  │ │ (novel patterns, advice) │  │  │
│                                 │     │  │ └──────────────────────────┘  │  │
│                                 │     │  └────────────────────────────────┘  │
└─────────────────────────────────┘     └──────────────────────────────────────┘
```

## Project Structure

```
Cepheus/
├── pyproject.toml                    # Build config, dependencies
├── enumerator/
│   └── cepheus-enum.sh               # POSIX shell enumerator (zero deps)
├── src/cepheus/
│   ├── cli.py                        # Typer CLI (analyze, enumerate, techniques, diff)
│   ├── config.py                     # CepheusConfig (env vars via pydantic-settings)
│   ├── models/
│   │   ├── posture.py                # ContainerPosture + KubernetesInfo + sub-models
│   │   ├── technique.py              # EscapeTechnique + Prerequisite DSL
│   │   ├── chain.py                  # EscapeChain + ChainStep
│   │   └── result.py                 # AnalysisResult + RemediationItem
│   ├── engine/
│   │   ├── technique_db.py           # 56 techniques, declarative prerequisites
│   │   ├── poc_templates.py          # PoC command templates + SafeFormatDict
│   │   ├── matcher.py                # Prerequisite evaluation engine
│   │   ├── chainer.py                # Single + combinatorial chain builder
│   │   ├── scorer.py                 # Weighted composite scoring
│   │   ├── differ.py                 # Posture diff/delta comparison
│   │   └── analyzer.py               # Orchestrator pipeline
│   ├── llm/
│   │   ├── client.py                 # LLMClient (LiteLLM wrapper)
│   │   └── prompts.py                # System + analysis + summary prompts
│   └── output/
│       ├── terminal.py               # Rich terminal output (tables, panels)
│       ├── json_report.py            # JSON serialization
│       ├── html_report.py            # Self-contained HTML report (Jinja2)
│       ├── mitre_layer.py            # MITRE ATT&CK Navigator layer export
│       └── diff_terminal.py          # Diff/delta terminal output
└── tests/                            # 144 tests across all modules
```

## Engine Pipeline

The analysis engine runs a deterministic pipeline:

### 1. Technique Loading
`technique_db.py` provides 56 `EscapeTechnique` objects, each with declarative `Prerequisite` checks.

### 2. Prerequisite Matching
`matcher.py` evaluates each technique's prerequisites against the container posture:
- Resolves dot-paths into the Pydantic model (e.g., `capabilities.effective`)
- Applies typed checks: `contains`, `equals`, `not_equals`, `gte`, `lte`, `kernel_gte`, `kernel_lte`, `kernel_between`, `exists`, `not_empty`, `regex`, `version_lte`
- Missing fields use `confidence_if_absent` (default 0.3) rather than failing — handles incomplete enumeration gracefully

### 3. Chain Building
`chainer.py` constructs escape chains:
- **Single chains**: One technique per chain (direct escape path)
- **Combinatorial chains**: Multi-prerequisite techniques that combine capabilities
- **Natural pairings**: Info-disclosure → escalation chains (e.g., credential leak → K8s API abuse)

### 4. Scoring
`scorer.py` computes a weighted composite score:
```
composite = (reliability × 0.40 + stealth × 0.25 + confidence × 0.35) × length_penalty
length_penalty = 1.0 / (1.0 + 0.15 × (chain_length - 1))
```

### 5. Remediation Generation
The analyzer extracts remediation guidance and runtime flags from matched techniques, sorted by severity.

### 6. Output
Results render in multiple formats:
- **Terminal** — Rich tables and panels with color-coded severity
- **JSON** — Machine-readable report for automation
- **HTML** — Self-contained HTML report with inline CSS (requires `jinja2`)
- **MITRE ATT&CK** — Navigator v4.5 layer JSON for ATT&CK heatmaps

### 7. Diff/Delta
`differ.py` compares two posture analyses to show remediated and newly introduced risks, with color-coded terminal output (green=remediated, red=new, yellow=changed).

## Enumerator Design

The enumerator is a POSIX-compliant shell script with zero external dependencies. It works in:
- Alpine (busybox sh)
- Ubuntu/Debian (dash/bash)
- Distroless containers (copy in as standalone)
- Scratch containers (static binary-compatible)

Key enumeration sources:
- `/proc/self/status` — capabilities (hex decode), seccomp mode
- `/proc/mounts`, `/proc/self/mountinfo` — mount points
- `uname -r` — kernel version
- `/sys/fs/cgroup/` — cgroup version detection
- `/proc/self/attr/current` — AppArmor/SELinux
- `/proc/1/ns/*` vs `/proc/self/ns/*` — namespace isolation
- Network probes — cloud metadata (169.254.169.254), Docker/containerd/CRI-O sockets
- Kubernetes — RBAC permissions, pod security standard, sidecar detection, node access indicators
- Runtime versions — Docker, containerd, CRI-O, runc version detection
- Environment variables — secret detection (names only, not values)

## Configuration

All settings are configurable via environment variables with the `CEPHEUS_` prefix:

| Variable | Default | Description |
|---|---|---|
| `CEPHEUS_MIN_CONFIDENCE` | `0.3` | Minimum confidence threshold for technique matching |
| `CEPHEUS_WEIGHT_RELIABILITY` | `0.40` | Scoring weight for reliability |
| `CEPHEUS_WEIGHT_STEALTH` | `0.25` | Scoring weight for stealth |
| `CEPHEUS_WEIGHT_CONFIDENCE` | `0.35` | Scoring weight for prerequisite confidence |
| `CEPHEUS_CHAIN_LENGTH_PENALTY` | `0.15` | Per-step penalty for multi-step chains |
| `CEPHEUS_LLM_MODEL` | `anthropic/claude-sonnet-4-20250514` | LLM model for enrichment |
| `CEPHEUS_LLM_API_KEY` | `None` | API key for LLM provider |
