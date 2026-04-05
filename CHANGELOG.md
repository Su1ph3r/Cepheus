# Changelog

All notable changes to Cepheus will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2026-04-04

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

### Fixed
- `any_of` prerequisite logic: `ebpf_probe_write_user` and `cve_2021_31440` now correctly match with either CAP_SYS_ADMIN or CAP_BPF (was requiring both)
- HTML report XSS: PoC commands with user-interpolated posture data are now escaped before rendering
- Differ no longer reports identical postures as "REGRESSED" — unchanged is treated as not-regressed
- Differ now considers critical and high chain counts in the improved/regressed determination
- `diff_terminal.py` no longer permanently mutates module-level console global
- Kernel version parser now handles 2-part versions like "6.1" (was returning (0,0,0))
- LLM error messages now include diagnostic details instead of generic "failed" messages
- Enumerator `json_str()` uses `printf` instead of `echo` and escapes control characters for valid JSON
- All `read_text()`/`write_text()` calls now specify `encoding="utf-8"` explicitly
- Subprocess stderr bytes are properly decoded before display
- `_render_poc` now catches only `ImportError`, not `KeyError` (which was masking template bugs)
- `asyncio.run()` in LLM sync wrappers now falls back to ThreadPoolExecutor when an event loop is already running

## [0.3.0] - 2026-02-09

### Added

#### Cross-Tool Integration
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

[Unreleased]: https://github.com/Su1ph3r/Cepheus/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/Su1ph3r/Cepheus/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/Su1ph3r/Cepheus/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Su1ph3r/Cepheus/releases/tag/v0.2.0
