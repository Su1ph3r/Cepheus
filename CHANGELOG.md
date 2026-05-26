# Changelog

All notable changes to Cepheus will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.1] - 2026-05-26

This release supersedes the unreleased v0.4.0 development line. It rolls up
every change since v0.3.0 — 9 new escape techniques, GPU/sandbox detection,
the prerequisite DSL `any_of` operator, a major precision overhaul, and a
small set of enumerator/CLI fixes — and drops the Nubicustos integration.

### Removed

- **Nubicustos integration** (was `--from-nubicustos` flag on the `analyze`
  command, the `cepheus.importers.nubicustos` module, and the
  `AnalysisResult.cloud_context` field). Nubicustos is not a required
  dependency for any supported use case; the import path is gone and the
  `cepheus.importers` package no longer exists. Users who need cross-tool
  enrichment should pipe the analyzer's JSON output to their own tool of
  choice.

### Changed — precision overhaul (26% → 100% on 10-pod K8s Goat benchmark)

Tightens prerequisite logic on 11 techniques so they only fire when the
specific posture markers that make them exploitable are present, instead
of matching every Kubernetes pod or every default-Docker-cap container.

- **New matcher controls:** `CepheusConfig.kernel_only_max_confidence`
  (default 0.5) caps confidence on techniques whose prereqs are exclusively
  kernel-version checks. `CepheusConfig.distro_kernel_max_confidence`
  (default 0.2) drops kernel-only matches further when the kernel is a
  distro/vendor build with security backports.
- **Distro-kernel detection:** new `KernelInfo.is_distro_kernel` and
  `distro_kernel_tag` fields. Pattern detection in `engine/matcher.py`
  covers WSL2, EKS/AKS/GKE/GCP, RHEL/CentOS, Amazon Linux, LinuxKit,
  OrbStack, Bottlerocket, Flatcar. `engine/analyzer.py` backfills the flag
  at analyse time so existing posture JSONs benefit without re-enumeration.
- **Component-presence schema:** new `NetworkInfo.can_reach_etcd`,
  `can_reach_kubelet_api`, `component_reachability`; new
  `KubernetesInfo.cluster_components`, `cluster_components_probed`.
- **Technique-level gates:**
  - `cap_dac_override` now requires `runtime.privileged` (it's in the
    default Docker cap set; not a standalone escape).
  - `procfs_sysrq`, `procfs_core_pattern`, `sysfs_hugepages`,
    `vm_param_manipulation` now require `CAP_SYS_ADMIN` in addition to
    writable_paths — DAC writability alone returns `EROFS` in unprivileged
    containers.
  - `proc_fd_symlink_traversal` requires `CAP_DAC_READ_SEARCH` or
    `CAP_SYS_ADMIN` (not CAP_DAC_OVERRIDE, which is default).
  - `tmpfs_shm_cross_container` requires `runtime.privileged` (proxy for
    shared IPC, since direct hostIPC detection in the enumerator is
    unreliable).
  - `lsm_selinux_unconfined` severity dropped to LOW + gated on
    `runtime.privileged` (host context, not a per-pod escape).
  - `cve_2025_1974` IngressNightmare requires
    `kubernetes.cluster_components` to contain `"ingress-nginx"`.
  - `k8s_etcd_access` requires `network.can_reach_etcd`.
  - `cve_2024_23651`/`cve_2024_23652` BuildKit CVEs require
    `network.can_reach_docker_sock`.
  - `containerd_shim_escape` requires `network.can_reach_containerd_sock`.
  - `runc_cve_2019_5736` requires detected `runtime.runc_version` ≤ `1.0.0-rc6`.

### Added

#### 9 New Escape Techniques (56 → 65 total)
- **runc Breakout Trio:** CVE-2025-31133 (masked path race), CVE-2025-52565 (/dev/console race), CVE-2025-52881 (procfs write redirect) — all fixed in runc ≥ 1.2.8
- **NVIDIA Container Toolkit:** CVE-2025-23266 (NVIDIAScape OCI hook escape, CVSS 9.0), CVE-2024-0132 (host filesystem access)
- **Kubernetes:** CVE-2025-1974 (IngressNightmare admission webhook RCE, CVSS 9.8)
- **BuildKit Leaky Vessels:** CVE-2024-23651 (cache mount TOCTOU race, CVSS 8.7), CVE-2024-23652 (path traversal, CVSS 10.0)
- **Docker Desktop:** CVE-2025-9074 (container escape, CVSS 9.3)

#### GPU and Sandbox Runtime Detection
- New `GpuInfo` posture model with NVIDIA device, toolkit version, and driver version detection
- Sandbox runtime detection for gVisor, Firecracker, and Kata Containers
- Sandbox-aware scoring: 0.3× composite score reduction when sandbox runtime is detected

#### Prerequisite DSL Enhancement
- New `any_of` check type for OR-logic prerequisites (e.g., requires CAP_SYS_ADMIN *or* CAP_BPF)

#### LLM Executive Summary
- New `--executive-summary` CLI flag generates a concise executive summary via LLM (requires `--llm`)

#### Chain Improvements
- `max_chain_length` configuration is now enforced in the chain builder
- 12 new chain pairings for IngressNightmare, NVIDIA, runc, and BuildKit techniques

#### Tooling
- `cepheus --version` / `-V` flag
- `.gitattributes` enforces LF line endings on `*.sh` and `*.py` — required for the enumerator (POSIX shell) to be parseable by `dash`/`busybox sh` after a Windows checkout

### Fixed
- `any_of` prerequisite logic: `ebpf_probe_write_user` and `cve_2021_31440` now correctly match with either CAP_SYS_ADMIN or CAP_BPF (was requiring both)
- HTML report XSS: PoC commands with user-interpolated posture data are now escaped before rendering
- Differ no longer reports identical postures as "REGRESSED" — unchanged is treated as not-regressed
- Differ now considers critical and high chain counts in the improved/regressed determination
- `diff_terminal.py` no longer permanently mutates module-level console global
- Kernel version parser now handles 2-part versions like "6.1" (was returning (0,0,0))
- LLM error messages now include diagnostic details instead of generic "failed" messages
- Enumerator `json_str()` uses `printf` instead of `echo` and escapes control characters for valid JSON
- Enumerator mount-option emission now goes through `json_str()` — fixes invalid JSON output when WSL DrvFS mounts expose options containing literal backslashes (`path=C:\;...`)
- Enumerator runtime detection adds a third fallback that parses `/proc/self/mountinfo` for runtime-specific overlay paths — fixes `Runtime: unknown` on kind / k3s / EKS where `/.dockerenv` and `/run/containerd` are absent
- All `read_text()`/`write_text()` calls now specify `encoding="utf-8"` explicitly
- Subprocess stderr bytes are properly decoded before display
- `_render_poc` now catches only `ImportError`, not `KeyError` (which was masking template bugs)
- `asyncio.run()` in LLM sync wrappers now falls back to ThreadPoolExecutor when an event loop is already running

## [0.3.0] - 2026-02-09

### Added

#### Cross-Tool Integration (removed in 0.3.1)
- `--from-nubicustos` option on the `analyze` command for cloud context enrichment
- Nubicustos container inventory import with cloud metadata preservation
- Cloud context fields added to escape chain analysis results

## [0.2.0] - 2026-01-28

### Added
- Initial release
- POSIX shell enumerator for container security posture collection
- Python analysis engine with 56 escape techniques across 6 categories
- 12 kernel CVE correlations (CVE-2022-0185 through CVE-2025-21756)
- Combinatorial chain analysis with weighted scoring
- PoC command generation for all techniques
- Multiple output formats: terminal, JSON, HTML, MITRE ATT&CK Navigator
- Optional LLM enrichment via LiteLLM
- Posture diff command for before/after comparison

[Unreleased]: https://github.com/Su1ph3r/Cepheus/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/Su1ph3r/Cepheus/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/Su1ph3r/Cepheus/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Su1ph3r/Cepheus/releases/tag/v0.2.0
