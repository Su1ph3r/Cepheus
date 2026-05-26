# Changelog

All notable changes to Cepheus will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.3] - 2026-05-26

Finishes the precision-overhaul work started in v0.3.1: wires up the
enumerator probes that the matcher already consumes. v0.3.1 added
schema fields (`network.can_reach_etcd`, `kubernetes.cluster_components`,
`runtime.runc_version`, etc.) and matcher gates that read them, but the
enumerator wasn't yet populating them — every CVE technique gated on
those fields would drop with `confidence_if_absent`. This release fills
the gap so techniques can MATCH on confirmed evidence, not just DROP on
missing data.

Behavioural change on the K8s Goat benchmark: **none** (the benchmark's
SA tokens lack list-pods RBAC, so the new probes still return defaults;
matched-technique sets are identical and the precision benchmark stays
at 100% precision / 100% recall). On clusters where the pod's SA has
list-pods OR the components are TCP-reachable, recall improves —
techniques like `cve_2025_1974` (IngressNightmare) now match when
ingress-nginx is actually deployed instead of being permanently
suppressed.

### Added

- **TCP-reachability probes in the enumerator** — new `tcp_probe`
  shell helper with four backend methods (nc → curl → python3 → bash
  /dev/tcp, each gated on availability AND an explicit timeout so a
  single hung probe can't blow the enumerator deadline). Used to
  populate:
  - `network.can_reach_etcd` (probes `$KUBERNETES_SERVICE_HOST:2379`
    and `etcd.kube-system.svc.cluster.local:2379`)
  - `network.can_reach_kubelet_api` (probes node default-gateway IP
    on port 10250)
  - `network.component_reachability` map — TCP probes well-known
    service VIPs for ingress-nginx, argocd, harbor, buildkit
- **Reusable K8s API helper** — `k8s_api_get` / `k8s_api_post`
  functions wrap the SA-token + ca.crt + curl boilerplate; the
  existing SelfSubjectRulesReview block was already doing this
  inline. Token is passed via `-H @file` not inline so it doesn't
  leak via `ps aux`.
- **`kubernetes.cluster_components` population** — when the SA can
  `list pods`, the enumerator queries `/api/v1/pods?limit=200` and
  detects known component image-prefixes (ingress-nginx, argocd,
  harbor, buildkit, falco, calico, cilium). When the API call is
  forbidden, the enumerator falls back to deriving `cluster_components`
  from successful entries in `component_reachability` — so recall
  improves even without list-pods RBAC, as long as the component is
  TCP-reachable.
- **`kubernetes.cluster_components_probed: bool`** — true iff the
  K8s API list-pods call succeeded.
- **K8s API self-introspection** — when the SA can `get pods` on its
  own namespace, the enumerator queries
  `/api/v1/namespaces/$NS/pods/$POD_NAME` and reads `spec.hostPID`,
  `spec.hostIPC`, `spec.hostNetwork`, and
  `containers[].securityContext.privileged`. These are OVERRIDES on
  the inode-comparison heuristics (which are unreliable on kind / k3s /
  some CNI plugins). When the API call fails, the heuristics
  remain in effect.

### Changed

- **`runtime.runc_version` detection improved** — was only `command
  -v runc` lookup; now also resolves `/proc/1/exe` and scans common
  host-bind-mounted paths (`/host/usr/bin/runc`, `/host-system/usr/bin/runc`,
  etc.) when the container has hostPath mounts. Each
  fallback execution is wrapped in `timeout 1` because the host binary
  may need shared libraries the container's mount namespace doesn't
  provide. The leading `v` (e.g. `v1.1.10`) is stripped for
  consistency.
- **`tcp_probe` falls through methods in timeout-reliability order**
  — nc → curl → python3 → bash (last because /dev/tcp has no native
  timeout; gated on `timeout` being available).
- **Bashism test now uses word-boundary matching** —
  `tests/test_enumerator.py::test_script_no_bashisms` previously
  flagged any substring match for `let `, which triggered on the
  word `kubelet ` in comments and identifiers. Now uses regex
  `(^|\s)<keyword>\s` so identifiers don't false-positive.
  Authoritative bashism detection is `dash -n` in CI.

### Notes for benchmark fixtures

The 10 K8s Goat fixtures at `tests/fixtures/k8s-goat/` were regenerated
against the v0.3.3 enumerator. Matched-technique sets are identical to
v0.3.2 (the precision benchmark's `EXPECTED_MATCHES` sets did not
need updating). One known regeneration limitation: T1
(system-monitor, hostPID:true + hostIPC:true + hostPath:/) enumeration
exceeds typical `kubectl exec` timeouts because hostPID exposes
hundreds of host PIDs; that fixture is retained from v0.3.1 and
verified to produce the same matched set via the benchmark. Slow-T1
will be addressed in a future enumerator-perf pass.

A regression-safety release. The v0.3.1 precision overhaul reached
100% precision and 100% recall on the 10-pod K8s Goat benchmark; this
release locks that result in via fixture-driven tests, bootstraps CI,
and lands a couple of small polish items.

### Added

- **Regression-precision suite** — 10 real-world container postures
  captured from a K8s Goat cluster on `kind` are now committed at
  `tests/fixtures/k8s-goat/` and asserted by
  `tests/test_precision_benchmark.py`. Per-pod `EXPECTED_MATCHES` sets
  fail loudly on any technique drift; a shared `FORBIDDEN_TECHNIQUES`
  list ensures the 26 confirmed false positives from the v0.3.1 audit
  never match these postures again. Marked `@pytest.mark.benchmark` so
  the unit suite stays fast.
- **GitHub Actions CI** — new `.github/workflows/ci.yml` runs three
  jobs on every PR and push to `main`:
  - `pytest` matrix on Python 3.11 / 3.12 / 3.13 (ubuntu-latest) with
    pip caching and coverage.
  - `ruff` (check + format check) pinned to a known-good version so
    upstream ruff releases can't silently red the build.
  - `dash -n` on the enumerator to catch bashisms that would break it
    under busybox/distroless sh. (Shellcheck deliberately deferred to
    v0.3.3 when the enumerator gets its planned expansion.)
- Pytest `benchmark` marker registered in `pyproject.toml`. Skip with
  `pytest -m "not benchmark"` during fast local iteration.

### Changed

- **MITRE ATT&CK coverage audit** — 10 techniques now reference more
  precise sub-techniques or additional MITRE IDs:
  - `cap_sys_ptrace`, `cap_dac_read_search`, `cap_dac_override`,
    `cap_sys_rawio` now also reference `T1611` (Escape to Host)
    alongside their respective primitive (T1055/T1005/T1565/T1006).
  - `cloud_metadata_creds`, `cloud_metadata_ssrf`, `cap_net_raw_metadata`
    now reference `T1552.005` (Cloud Instance Metadata API) instead of
    the bare parent `T1552`.
  - `k8s_configmap_secrets`, `docker_env_inspection` now reference
    `T1552.007` (Container API) instead of bare `T1552`.
  - `env_secret_leak` now also references `T1552.001` (Credentials in
    Files) — the closest sub-technique for env-var exposure via
    `/proc/<pid>/environ`.
- **Codebase ruff-normalised.** First CI run on a fresh checkout would
  have failed on 12 lint issues and 22 files needing reformat — fixed
  in-tree as part of this release so the lint gate isn't immediately
  red. One real test bug fixed in the process: a missing `assert
  len(two_step) > 0` in `tests/test_engine/test_chainer.py::test_max_chain_length_enforcement`.

### Fixed

- **Enumerator hostPID perf (CEPH-2)** — the sidecar-detection loop in
  `enumerator/cepheus-enum.sh` previously iterated every PID visible
  in `/proc`. On pods with `hostPID: true` (typical for monitoring
  sidecars) this turned into a hundreds-of-PIDs-per-iteration hot loop
  that blew past `kubectl exec`'s default 60s timeout. The loop now
  short-circuits when the pod has its own PID namespace (`NS_PID=true`)
  and caps iteration at 200 PIDs otherwise.



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

[Unreleased]: https://github.com/Su1ph3r/Cepheus/compare/v0.3.3...HEAD
[0.3.3]: https://github.com/Su1ph3r/Cepheus/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/Su1ph3r/Cepheus/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/Su1ph3r/Cepheus/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/Su1ph3r/Cepheus/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Su1ph3r/Cepheus/releases/tag/v0.2.0
