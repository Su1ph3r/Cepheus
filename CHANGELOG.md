# Changelog

All notable changes to Cepheus will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **`cepheus fleet scan`** — enumerate every running pod in a cluster via
  `kubectl get pods -o json` and analyze each one, emitting a fleet report
  (JSON). Supports `--namespace`, `--selector`, `--context`, `--kubeconfig`,
  and `--parallel`. Per-pod analyzer failures are captured in the report
  rather than aborting the scan.
- **`cepheus fleet diff <before> <after>`** — compute the posture delta
  between two fleet reports (pods added/removed/regressed/improved, with
  per-pod chain and score changes). `--fail-on-regression` exits non-zero
  when any pod gains chains or raises its score, for CI drift gating.
- **`cepheus update`** — check whether a newer published release is
  available and print the upgrade command for each install channel.
  `--fail-if-outdated` exits non-zero when an upgrade is available. The
  check is unauthenticated and read-only; no in-place self-upgrade.
- **Admission webhook outbound notifications.** `cepheus admission-server`
  gains `--slack-webhook-url` and `--pagerduty-routing-key` (also via the
  `CEPHEUS_SLACK_WEBHOOK_URL` / `CEPHEUS_PAGERDUTY_ROUTING_KEY` env vars).
  Every DENY (and WARN-mode near-deny) is POSTed to the configured
  channels. Delivery is best-effort, rate-limited, and dispatched on
  background threads so it never blocks the admission decision.
- **Compliance crosswalk.** Techniques can carry CIS Kubernetes Benchmark,
  NIST SP 800-190, and PCI-DSS control identifiers, surfaced in SARIF rule
  properties and the HTML report. A curated starter set maps the
  capability, socket, mount, and secret families.
- **Performance regression suite.** CI pins analyzer wall-clock and
  peak-allocation budgets over the K8s Goat fixtures so an algorithmic
  regression is caught at build time.
- **Admission webhook end-to-end test.** A kind-based workflow exercises
  the webhook against a live cluster.

### Changed

- Verifier coverage raised to 57/65; the coverage regression floor is now
  55/65 (was 47/65).

## [0.6.3] - 2026-05-27

Patch release fixing a packaging bug that prevented any PyPI install
from running ``cepheus ci`` / ``cepheus enumerate``: the POSIX-shell
enumerator script was missing from the published wheel. Also lands
the standalone ``Su1ph3r/cepheus-action`` repository setup.

### Fixed

- **Enumerator shell script now bundled inside the wheel.**
  ``enumerator/cepheus-enum.sh`` lived at the repo root, outside
  ``src/cepheus/``. Hatchling's wheel build only includes
  ``src/cepheus/``, so every pre-0.6.3 PyPI install shipped without
  the script and ``cepheus ci nginx:latest`` failed with
  ``Error: Cannot find cepheus-enum.sh``. The bug has existed since
  v0.5.0 but only surfaced with v0.6.1 (the first PyPI release).
  Moved the script to ``src/cepheus/enumerator/cepheus-enum.sh``
  (now a proper Python sub-package with ``__init__.py``);
  ``cepheus.cli._find_enumerator_script`` resolves it via
  ``Path(__file__).parent / "enumerator" / "cepheus-enum.sh"`` so
  every install layout (editable, wheel, future PyInstaller-frozen)
  works. Two fallback paths kept for backwards compatibility with
  pre-0.6.3 working copies. Local wheel-build verification confirms
  ``cepheus/enumerator/cepheus-enum.sh`` ships in the published
  artifact.
- **Action `cache: pip` removed from `setup-python` step.** The
  composite action's setup-python step had ``cache: pip``, which
  errors hard when the consumer's checkout contains no
  ``requirements.txt`` / ``pyproject.toml`` — the common case for
  consumer repos that ``docker build`` then scan with no in-tree
  Python project. The cache saved ~2-3s on a ~10s install while
  costing real consumer-side breakage; drop it. Mirrors the same
  fix in ``Su1ph3r/cepheus-action``.

### Added

- **Standalone `Su1ph3r/cepheus-action` GitHub repository** — the
  GitHub Action that wraps `cepheus ci` now lives in a dedicated
  public repo so consumers can pin via the canonical
  `uses: Su1ph3r/cepheus-action@vX.Y.Z` form (instead of the
  subdir-path form), and so it can be listed on the GitHub Actions
  Marketplace.
- **`.github/workflows/sync-action.yml`** — release-triggered mirror
  workflow. On every `v*.*.*` tag push to this repo, the workflow
  copies `cepheus-action/{action.yml, README.md, LICENSE, CHANGELOG.md}`
  to `Su1ph3r/cepheus-action`, commits, pushes to its `main`, and
  creates a same-named release + tag on the standalone repo. Cross-
  repo writes use a fine-grained PAT scoped to the standalone repo
  only (`Contents: read+write`) — the workflow's own `GITHUB_TOKEN`
  stays read-only. Preserves the standalone repo's `.github/`
  directory across syncs so its own self-test workflow survives.
  Idempotent — re-runs on the same tag skip already-committed
  contents and already-created releases.
- `README.md` — new "GitHub Actions integration" section pointing
  consumers at `Su1ph3r/cepheus-action`.

### Changed

- `.github/workflows/ci.yml` ``enumerator-shell-lint`` job now
  lints at the new path ``src/cepheus/enumerator/cepheus-enum.sh``.
- `tests/test_enumerator.py` updated to reference the new path.
- `docs/ARCHITECTURE.md` directory-layout diagram updated.
- `tests/fixtures/k8s-goat/README.md` example ``ENUM=...`` path
  updated.
- `README.md` ``docker cp`` example path updated.

## [0.6.2] - 2026-05-27

Patch release fixing a `__version__` reporting bug that shipped in
0.6.0 / 0.6.1 and made the CLI + SARIF reports misreport the
installed Cepheus version.

### Fixed

- **`cepheus --version` and SARIF tool-driver metadata reported the
  wrong version.** `src/cepheus/__init__.py` hardcoded
  `__version__ = "0.5.0"`, which was never bumped during the 0.6.0
  or 0.6.1 cuts. The literal flowed into the CLI's `--version`
  output (cli.py) and the SARIF tool-driver block
  (`runs[].tool.driver.version` + `semanticVersion`) in every
  report Cepheus emits, four call sites in `output/sarif.py`.
  Operators upgrading to 0.6.0 / 0.6.1 saw their tools still
  identifying as "0.5.0" — incident-response reproducibility was
  broken and GitHub Code Scanning attributed findings to the wrong
  version. Fix: source `__version__` dynamically via
  `importlib.metadata.version("cepheus-engine")` so the value can
  never drift from `pyproject.toml`. Falls back to
  `"0.0.0+unknown"` only in the rare source-checkout-without-
  installed-dist case.
- Added `tests/test_version.py` regression test asserting
  `cepheus.__version__` equals `pyproject.toml`'s declared version
  whenever the package is installed. CI installs the package via
  `pip install -e ".[dev,html]"`, so the assertion runs there;
  source-checkout developers without an editable install see a
  clean skip rather than a confusing failure.

## [0.6.1] - 2026-05-27

Patch release that unblocks PyPI distribution and ships two release-
pipeline fixes plus the standalone `cepheus-action` GitHub Actions
repository setup.

### Changed

- **PyPI distribution name renamed from `cepheus` to `cepheus-engine`.**
  The bare `cepheus` name on PyPI was already taken by an unrelated
  2018 Cepheid-variable-star analysis package — `twine upload` returns
  403 regardless of token validity. The Python module import
  (`import cepheus`), the CLI binary (`cepheus`), the GHCR image
  (`ghcr.io/su1ph3r/cepheus`), the Homebrew formula, the Scoop
  manifest, the GitHub Action, and every other identifier remain
  unchanged. Only the `pip install <NAME>` token changes:
  `pip install cepheus-engine` going forward.
- `pyproject.toml` `name` field → `cepheus-engine`.
- `Dockerfile` wheel glob widened to `cepheus*-py3-none-any.whl` —
  PEP 427 normalises the project name's hyphen to an underscore in
  the wheel filename (`cepheus_engine-0.6.1-py3-none-any.whl`), so
  the glob now matches both the legacy and renamed filenames.

### Fixed

- **`release.yml` workflow_dispatch tag resolution.** The
  `attach-to-release` and `update-package-manifests` jobs used the
  pattern
  ``tag="${GITHUB_REF#refs/tags/}"; [ -z "$tag" ] && tag="$INPUT_TAG"``
  which silently fails under `workflow_dispatch` because
  `GITHUB_REF` is `refs/heads/<branch>` (not `refs/tags/<tag>`) and
  the strip pattern doesn't match — `tag` ends up as the literal
  `refs/heads/main`, non-empty, so the `INPUT_TAG` fallback never
  fires. Both jobs now branch on `GITHUB_EVENT_NAME` like the
  `build` job already does. Push-tag-triggered runs were always
  fine; only the rarer workflow_dispatch path was broken.
- **`release.yml` publish-pypi metadata compatibility.** The job
  had no `actions/setup-python@v5` step, so it ran against the
  runner's apt-installed system Python with an old `pkginfo`. That
  `pkginfo` rejected the PEP 639 metadata fields
  (`License-Expression`, `License-File`) that modern hatchling
  emits when `pyproject.toml` uses the SPDX string form
  (`license = "MIT"`). Added a pinned `setup-python@v5` step and an
  explicit `pip install "twine>=6.0" "pkginfo>=1.12"` so `twine
  check` understands modern wheel metadata.

### Added

- **Standalone `Su1ph3r/cepheus-action` repository setup.** The
  GitHub Action that wraps `cepheus ci` now ships in a dedicated
  repo so consumers can reference it as
  `uses: Su1ph3r/cepheus-action@v0.6.1` (instead of the subdir-path
  form), and so it can be listed on the GitHub Actions Marketplace.
  The action source remains in `cepheus-action/` inside this repo
  — a release-triggered sync workflow mirrors the directory to the
  standalone repo on every tag. The action installs Cepheus from
  PyPI as `cepheus-engine`.
- `cepheus-action/action.yml`: `cepheus-version` default bumped to
  `0.6.1`; install line now uses `cepheus-engine`.
- `cepheus-action/README.md`: `uses:` references updated to
  `v0.6.1`.
- `cepheus-action/LICENSE` (MIT, matching Cepheus) and
  `cepheus-action/CHANGELOG.md` added for the standalone repo.
- `docs/INSTALL.md` + `README.md`: stale `v0.4.2` references
  refreshed to `v0.6.1`; `pip install` examples updated to the new
  distribution name.

## [0.6.0] - 2026-05-27

Adds the Kubernetes admission webhook's Node kernel-version lookup,
plus a thorough finalize hardening pass on the surrounding admission
flow (CA-pinned TLS, projected SA token re-read per request,
no-redirect handler, env-var URL validation, narrowed exception
handling, ``/readyz`` cache-health propagation, chain-id-based
de-duplication). Also adds a ``.pre-commit-config.yaml`` mirroring
the CI gates so local developers catch ruff issues before push
instead of after.

### Added

- **Admission webhook: Node kernel-version lookup.** The webhook can
  now source kernel versions from cluster Node objects via the K8s
  API and evaluate each pod against every distinct kernel currently
  in the cluster — so kernel-CVE chains become real gate inputs
  instead of being dropped. Enabled by combining
  `gate.includeKernelCves=true` with `nodeKernelLookup.enabled=true`
  in the Helm chart. The chart auto-provisions a `ClusterRole`
  granting `nodes: list` to the webhook ServiceAccount and flips
  `automountServiceAccountToken` on. Fail-fast at startup when the
  initial fetch can't reach the apiserver and kernel-CVE gating is
  requested, so the webhook never silently runs with the gate
  disabled. `/readyz` returns 503 when the cache is unhealthy so
  `failurePolicy: Fail` propagates the failure to the apiserver.
- **`cepheus.server.k8s_client`** — new module. Minimal stdlib K8s
  API client (`K8sClient`) with in-pod ServiceAccount auto-detection
  via `K8sClient.in_cluster()`, plus `NodeKernelCache`: a
  background-refreshing snapshot of cluster kernel versions with
  atomic snapshot reads, error-preserving refresh semantics, and
  configurable poll interval. Zero new runtime dependencies — same
  constraint as the rest of `cepheus.server`.
- **`cepheus admission-server` flags**: `--node-kernel-lookup` /
  `--no-node-kernel-lookup` and `--node-kernel-refresh-seconds`.
- **Helm chart**: `nodeKernelLookup.enabled` and
  `nodeKernelLookup.refreshSeconds` values; `ClusterRole` +
  `ClusterRoleBinding` for node read access; deployment passes the
  new admission-server flags.
- **`posture_from_podspec(spec, *, kernel_version=...)`** — importer
  accepts a kernel version kwarg that populates `posture.kernel`
  (parsed into major/minor/patch). Defaults to empty when omitted
  so existing CLI-driven flows are unchanged.
- Tests: `tests/test_server/test_k8s_client.py` (client parsing, auth
  header, cache refresh semantics, error preservation); additions to
  `tests/test_server/test_admission.py` and
  `tests/test_importers/test_podspec.py`.

### Changed

- `docs/ADMISSION.md` — new "Kernel CVE evaluation via Node lookup"
  section documenting RBAC, failure modes, and heterogeneous-kernel
  semantics. Per-category coverage table updated to reflect
  `kernel: ✅ when nodeKernelLookup enabled`.

## [0.5.1] - 2026-05-27

Drops the prebuilt `cepheus-darwin-amd64` binary from the release matrix.
The GitHub-hosted `macos-13` runner that produces the Intel Mac native
binary has been queueing for hours without progress on the last several
release pipelines, blocking the rest of the asset set from landing.
Intel Mac users can run the `darwin-arm64` binary under Rosetta 2:

```sh
arch -x86_64 ./cepheus-darwin-arm64 --version
```

Homebrew on Intel Macs is no longer supported by the formula. Other
install paths (`pip`, container, native binaries on linux-amd64,
linux-arm64, darwin-arm64, windows-amd64, Scoop) are unaffected.

### Changed

- `.github/workflows/release.yml` — `darwin-amd64` removed from the
  binary matrix; manifest-rewrite step no longer requires a
  `cepheus-darwin-amd64` checksum.
- `Formula/cepheus.rb` — `on_macos`/`on_intel` block removed; formula
  declares `depends_on arch: :arm64` on macOS.
- `docs/INSTALL.md` — Native-binary section drops the macOS Intel curl
  example.

## [0.5.0] - 2026-05-27

Adds Kubernetes admission webhook mode. `cepheus admission-server`
runs as a `ValidatingAdmissionWebhook`; on `kubectl apply -f pod.yaml`,
kube-apiserver hands the PodSpec to Cepheus, which converts it to a
synthetic `ContainerPosture`, runs the full analyzer pipeline, and
returns allow/deny based on configured gates. Pods are blocked before
the kubelet ever schedules them.

### Added

- **`cepheus.importers.podspec`** — new module. `posture_from_podspec(spec)`
  converts a Kubernetes PodSpec dict (from an AdmissionReview request
  or `kubectl get pod -o json`) into a `ContainerPosture`. Extracts:
  - Capability set (Docker defaults + securityContext.capabilities.add
    − drop; `privileged: true` grants ALL caps).
  - Host-namespace flags (`hostPID` / `hostIPC` / `hostNetwork` → the
    corresponding `NamespaceInfo` field inverted).
  - hostPath mounts → `mounts[]` + `writable_paths[]`.
  - Docker / containerd / CRI-O socket reachability via hostPath
    detection.
  - Service-account token availability (default-true unless
    `automountServiceAccountToken: false`).
  - RuntimeClass → sandbox runtime (gvisor, kata, firecracker).
  - Multi-container pods produce the UNION of all containers'
    surfaces (any privileged container → privileged pod, etc.).
- **`cepheus.server.admission`** — new module. HTTPS server (stdlib
  `ThreadingHTTPServer` + `ssl.wrap_socket`, zero new runtime deps)
  exposing:
  - `POST /validate` — AdmissionReview v1 handler.
  - `GET /healthz`, `GET /readyz` — kubelet probes (plaintext HTTP
    on a separate port; default 8080).
  - `_handle_admission(body, cfg)` — pure function used directly by
    unit tests so test runs don't need TLS plumbing.
  - Request bodies capped at 1 MB (DoS shield).
  - Fail-open (default) admits-with-warning via the AdmissionResponse
    `warnings[]` array on internal error; fail-closed denies.
  - Kernel-CVE techniques EXCLUDED from gate decisions by default
    (`--include-kernel-cves` to opt in) — they need a runtime kernel
    version which PodSpec doesn't carry; including them
    false-positives every pod.
- **`cepheus admission-server` CLI subcommand.** Flags: `--port`,
  `--cert-file`, `--key-file`, `--bind`, `--health-port`,
  `--max-severity`, `--baseline`, `--fail-on-new`,
  `--include-kernel-cves`, `--fail-open` / `--fail-closed`.
  Configuration errors (missing baseline with `--fail-on-new`,
  invalid severity, unreadable cert / baseline) exit 2 at startup so
  misconfigured deployments don't run silently broken.
- **`charts/cepheus-admission/`** — Helm chart. Components:
  - `Deployment` with 2 replicas, locked-down `podSecurityContext`
    (non-root, read-only root FS, dropped caps, RuntimeDefault
    seccomp).
  - `Service` (ClusterIP, 443 → 8443).
  - `ValidatingWebhookConfiguration` scoped to Pod CREATE, excludes
    `kube-system` by default; configurable per-namespace via
    `namespaceSelector`.
  - cert-manager `Issuer` + `Certificate` for TLS (auto-injects the
    CA bundle into the VWC via `cert-manager.io/inject-ca-from`);
    bring-your-own-secret + self-signed alternatives also supported.
  - `ServiceAccount` (with `automountServiceAccountToken: false` —
    the admission server doesn't need K8s API access).
  - `PodDisruptionBudget` (minAvailable: 1) so cluster maintenance
    doesn't all-replicas-down the webhook.
  - Optional `ConfigMap` for the baseline, mounted at
    `/etc/cepheus/baseline/baseline.json`.
- **`docs/ADMISSION.md`** — deployment guide. Quickstart, what the
  gate evaluates per category, per-namespace scoping, TLS modes,
  per-distribution notes (kind / EKS / GKE / OpenShift), baseline
  update flow, troubleshooting.
- 36 new tests across `tests/test_importers/test_podspec.py` and
  `tests/test_server/test_admission.py`. Covers cap normalization,
  privileged-container detection, multi-container union, namespace
  inversion, hostPath / emptyDir distinction, socket detection,
  sandbox runtime detection, end-to-end privileged-pod → critical
  chains, end-to-end hardened-pod → zero evaluable criticals, kernel-CVE
  filter behaviour, fail-open vs fail-closed paths, load-time config
  validation.

### Changed

- `cepheus-action`'s default `cepheus-version` bumped from `0.4.2` →
  `0.5.0`.

### Notes

- The admission webhook requires cert-manager for the default install
  path. Bring-your-own-secret and self-signed alternatives are
  available via `values.yaml`.
- Kernel CVE chains are excluded from admission decisions by default
  because PodSpec doesn't carry a kernel version. After admission,
  run `cepheus verify` against the running pod for the runtime-side
  check (kernel CVEs still won't have verifiers in most cases, but
  the verifier catches the capability / mount / socket / cap-derived
  primitives that DO have probes).
- Multi-container pods: the importer takes the UNION of all
  containers' surfaces, including init containers. This is the right
  model — any container being compromised gives an attacker
  pod-namespace-level access to the rest.

## [0.4.2] - 2026-05-26

Adds prebuilt native binaries, a GHCR container image, Homebrew tap,
and a Scoop manifest. Cepheus is now installable in five forms (pip,
container, native binary, Homebrew, Scoop). v0.4.1 was cut, hit a
Windows-specific crash in the release pipeline's binary-smoke-test
step, and was withdrawn (the v0.4.1 GitHub Release and git tag were
deleted before any artifacts were published). All features described
against v0.4.1 land in v0.4.2 unchanged, plus the Windows fix below.

### Fixed

- **Windows: non-TTY stdout no longer crashes with `OSError [Errno 22]`.**
  Python on Windows defaults stdout/stderr to the active code page
  (typically `cp1252`) when not connected to a TTY. Any Cepheus command
  whose output runs through a pipe — `cepheus techniques | grep`,
  `cepheus analyze posture.json --format text > out.txt`, the release
  pipeline's smoke-test piping through `head`, etc. — would crash the
  moment Rich tried to emit a non-ASCII character (`…` for column
  truncation, box-drawing chars for tables). `cli.py` now calls
  `sys.stdout.reconfigure(encoding="utf-8", errors="replace")` and the
  same on stderr at import time on Windows. Idempotent and no-op on
  non-Windows platforms. The `errors="replace"` fallback keeps output
  flowing if a truly un-encodable char ever slips through.
- **Release pipeline binary smoke test simplified.** The previous
  `./binary techniques --severity critical | head -20` step was what
  surfaced the cp1252 bug; reducing the smoke test to `--version` +
  `--help > /dev/null` keeps the entry-point coverage without
  re-introducing the same encoding edge case (which is now properly
  fixed at the source).

### Changed

- `cepheus-action` default `cepheus-version` bumped from `0.4.1` →
  `0.4.2`.

### Notes

- v0.4.1 git tag and GitHub Release were deleted before any installable
  artifacts were published. The v0.4.1 CHANGELOG entry has been merged
  into v0.4.2 below; no one should reference v0.4.1 as a release.

## [0.4.1] - 2026-05-26

(withdrawn — see v0.4.2 note above)

Adds prebuilt native binaries, a GHCR container image, Homebrew tap,
and a Scoop manifest. Cepheus is now installable in
five forms (pip / native binary / GHCR container / Homebrew / Scoop)
covering every reasonable deployment target including air-gapped hosts
and distroless CI runners. Zero behaviour change — `cepheus --version`
prints `0.4.1` from every install path and runs identical code.

### Added

- **`src/cepheus/__main__.py`** — `python -m cepheus` now works as a
  module entry point. Also serves as the Nuitka compilation target so
  the native-binary builds compile a single concrete file rather than
  a synthetic shim.
- **`Dockerfile`** — `python:3.12-slim` base + docker-ce-cli + tini.
  Image is ~210 MB after slim base + cepheus + docker CLI; runs as
  non-root `cepheus` user (uid 1000) by default. OCI labels for GHCR
  package-page rendering.
- **`.dockerignore`** — keeps the build context to `dist/*.whl` only
  so the image build doesn't ship the source tree, tests, fixtures,
  or git history.
- **`.github/workflows/release.yml` extended** with:
  - **`binaries` matrix job** — 5 platforms: `ubuntu-latest` (linux
    amd64), `ubuntu-24.04-arm` (linux arm64), `macos-13` (darwin
    amd64), `macos-latest` (darwin arm64), `windows-latest` (windows
    amd64). Uses Nuitka 2.4+ with `--standalone --onefile --lto=yes
    --enable-plugin=anti-bloat`. Each binary is smoke-tested
    (`--version` + `techniques --severity critical`) before upload.
  - **`container` job** — `docker/build-push-action` with QEMU +
    buildx, multi-arch (linux/amd64 + linux/arm64), pushes to
    `ghcr.io/su1ph3r/cepheus` with three tags: `:X.Y.Z`, `:X.Y`,
    `:latest`. Provenance + SBOM attached.
  - **`attach-to-release` rewritten** to gather sdist + wheel +
    5 native binaries into one staging directory, sha256sum
    everything into a `SHA256SUMS` file, then upload all of it to
    the GitHub Release in one `gh release upload --clobber` call.
  - **`update-package-manifests` job** — downloads the
    `SHA256SUMS` from the release, extracts per-platform hashes,
    rewrites `Formula/cepheus.rb` + `scoop/cepheus.json` with the
    real values, commits + pushes to main as github-actions[bot].
    Workflow-token commits don't re-trigger workflows so there's no
    loop risk.
- **`Formula/cepheus.rb`** — Homebrew formula. Downloads the
  per-platform native binary from the GitHub Release rather than a
  source tarball so `brew install cepheus` is fast. Install:
  `brew tap su1ph3r/cepheus https://github.com/Su1ph3r/Cepheus && brew install cepheus`.
- **`scoop/cepheus.json`** — Scoop manifest with `autoupdate` against
  the GitHub Release SHA256SUMS file. Install:
  `scoop install https://raw.githubusercontent.com/Su1ph3r/Cepheus/main/scoop/cepheus.json`.
- **`docs/INSTALL.md`** — consolidates all install paths with copy-
  pasteable commands, sha256-verification flow, and air-gapped
  install guide.

### Changed

- README install section rewritten to show all five paths at a glance;
  full details live in `docs/INSTALL.md`.
- `cepheus-action`'s default `cepheus-version` bumped from `0.4.0` to
  `0.4.1` so the action stays version-locked to the cepheus release it
  ships alongside.
- Release workflow comment header updated to document the new
  binaries + container + manifest-update pipeline.

### Notes

- **First-run window for Homebrew + Scoop:** the v0.4.1 release commit
  ships placeholder sha256 values in `Formula/cepheus.rb` and
  `scoop/cepheus.json`. The release workflow's `update-package-manifests`
  job rewrites them with the real hashes ~30 seconds after the binaries
  finish building and pushes a follow-up commit to main. Users who run
  `brew install` in that 30-second window will get a sha256 mismatch
  error — wait for the green check on the follow-up commit before
  installing the freshly-released version.
- **GHCR token:** no extra secret needed. The workflow uses
  `${{ github.token }}` with `packages: write` scope (granted by the
  workflow's `permissions:` block). The package is created on first
  push.
- **PyPI:** still gated behind `SKIP_PYPI` repo variable + missing
  `PYPI_API_TOKEN`. Unchanged from v0.4.0.

## [0.4.0] - 2026-05-26

Verifier-depth + parallelism release. Coverage of `verify_command`
probes more than doubles (23 → 47, 35% → 72% of the 65-technique
catalog) and probes now run concurrently inside the target container
by default. `cepheus verify --format sarif` produces a SARIF log that
uploads to GitHub Code Scanning alongside (or instead of) the
static-analysis SARIF — operators get CONFIRMED/NOT_CONFIRMED/NO_VERIFIER/ERROR
findings as first-class Code Scanning results.

### Added

- **24 new `verify_command` probes** across capability, mount,
  combinatorial, info-disclosure, and runtime categories:
  - **capability (3):** `cap_sys_admin_cgroup_escape` (cgroup.procs
    writability), `cap_sys_admin_bpf` / `ebpf_probe_write_user`
    (bpftool prog list + BTF readability).
  - **mount (3):** `cgroupfs_escape`, `systemd_cgroup_injection`,
    `device_mapper_access`.
  - **runtime (7):** `k8s_kubelet_api` (probes default-gateway:10250),
    `k8s_etcd_access` (probes etcd VIP), `docker_api_unauth` (unix +
    2375), `containerd_shim_escape`, `k8s_node_proxy`, NVIDIA CVEs
    `cve_2025_23266` and `cve_2024_0132` (device-presence), Docker
    Desktop `cve_2025_9074`.
  - **kernel (2):** BuildKit `cve_2024_23651` and `cve_2024_23652`
    (daemon-socket reachability).
  - **combinatorial (6):** every combinatorial technique now has a
    composite probe that checks all sub-primitives via /proc/self/status
    grep + path tests + secondary file checks.
  - **info-disclosure (2):** `env_secret_leak` (greps
    /proc/self/environ for secret-pattern var names), `docker_env_inspection`
    (Docker socket reachability).
  - Categories now at 100% coverage: mount (15/15), combinatorial
    (6/6), info_disclosure (4/4). Capability at 8/9 (`cap_sys_ptrace`
    intentionally has no probe — the v0.3.5 Q2 fix). Runtime at 12/14.
  - All probes are POSIX-sh compatible and non-destructive (read-only
    or open-then-close idiom).
- **`cepheus verify --parallel N` / `-j N`** — concurrent probe
  execution via a `ThreadPoolExecutor`. Default `min(8, len(matched))`;
  `--parallel 1` skips the pool entirely (debuggability); `--parallel 0`
  resolves to auto. Results are sorted by severity-desc + technique_id
  so the report is byte-deterministic regardless of execution order.
  ~5-10× speedup on multi-finding postures.
- **`cepheus verify --format sarif`** — new `VerifyFormat` enum
  (`terminal` / `json` / `sarif`). Verify SARIF emits one result per
  verified technique (not per chain) with `level` reflecting the
  outcome: CONFIRMED → `error`, NOT_CONFIRMED → `note`, NO_VERIFIER →
  `warning`, ERROR → `warning`. Run-level `properties` carry counts so
  consumers can dashboard without iterating results. Stable
  `partialFingerprints.verifyFingerprint/v1` includes the outcome, so
  a CONFIRMED → NOT_CONFIRMED transition (e.g. after a cap drop) opens
  a new Code Scanning finding rather than reusing the old one.
- **`generate_verify_sarif()` + `write_verify_sarif()`** in
  `cepheus.output.sarif` — public API for downstream consumers building
  custom verify-side reports.
- **Verifier coverage regression guard test** — `tests/test_engine/test_verifier.py::test_verifier_coverage_meets_minimum`
  fails the build if `verify_command` coverage drops below 40/65,
  preventing accidental deletion of probes during refactors.
- **Per-category coverage guard** — asserts mount/combinatorial/info_disclosure
  stay at 100% and capability at all-but-one.

### Changed

- `cepheus verify` help text updated to reflect 47/65 coverage.
- Verifier classifier extracted to `_classify(rc)` and per-technique
  execution extracted to `_verify_one()` — pure functions over their
  inputs, safely dispatchable from a thread pool.
- `verify_analysis()` now accepts a `parallel: int | None` kwarg.

### Notes

- Probes are dispatched via `docker exec` (or `podman exec`) which
  serializes on the container's lock for some operations — N=8 is a
  good default for most images; bump higher if your runtime tolerates
  it (containerd shim typically does), lower if you see probe-flake
  from contention.
- `cap_sys_ptrace` and the 15 unverifiable kernel CVEs remain
  intentionally NO_VERIFIER — the test for those is the exploit
  itself, which is not what `verify` is for.

## [0.3.5] - 2026-05-26

Shift-left + verification release. Turns Cepheus from a one-shot CLI
into a CI/CD gate (SARIF + `cepheus ci`) and adds live verification
(`cepheus verify`) that confirms whether the kernel/runtime actually
permits each matched primitive — catching false positives that even
posture-driven precision can't eliminate.

Note: 0.3.4 was never published; 0.3.5 supersedes the prior 0.3.4 entry
in this changelog. PyPI / git tags jump 0.3.3 → 0.3.5 directly.

### Added

#### CI gate (`cepheus ci`)

- **SARIF 2.1.0 output format** — new `src/cepheus/output/sarif.py`.
  Each ranked chain becomes a SARIF `result`; each unique technique
  becomes a deduplicated `rule` in `tool.driver.rules`. Severity maps
  to SARIF `level` (critical/high → error, medium → warning, low →
  note), and `properties.security-severity` carries a CVSS-like 0-10
  score so GitHub Code Scanning's severity filters work as expected.
  Stable `partialFingerprints.chainFingerprint/v1` prevents re-runs
  from opening duplicate findings. Free-form posture data (hostname,
  poc commands) is URL-encoded/markdown-escaped so a malicious posture
  can't inject markup into the Code Scanning UI.
- **`cepheus ci` subcommand** — `cepheus ci TARGET [OPTIONS]`. TARGET
  is either an image reference (enumerated in an ephemeral container)
  or a previously-captured posture JSON file. Gates:
  - `--max-severity LEVEL` exits 1 if any chain meets or exceeds the
    threshold (`low` / `medium` / `high` / `critical`).
  - `--baseline FILE --fail-on-new` exits 1 if any chain appears in
    the current scan that wasn't in the baseline report (regression
    detection). Baseline accepts JSON or SARIF.
  - Default `--format sarif` is the format GitHub Code Scanning
    ingests.
  - Exit codes: `0` pass, `1` gate failed, `2` invocation error.
- **`cepheus enumerate --image IMAGE`** — extends `enumerate` with an
  image-reference mode that spins up `docker run --rm --entrypoint sh
  IMAGE /tmp/cepheus-enum.sh` to capture posture at build time. Pair
  with `--runtime podman` for podman environments. The image path
  detects "enumerator produced no output" (distroless / scratch
  images that lack `/bin/sh`) and fails loudly with a clear pointer
  to the running-container flow, rather than silently passing a
  zero-finding scan.
- **Posture structural validation** — both file-loaded and
  enumerator-captured postures are now structurally validated before
  the analyzer sees them. An empty `{}` or a JSON object missing
  required top-level keys (`enumeration_version`, `kernel`, `runtime`)
  is rejected with exit 1 instead of silently accepting a
  fully-default `ContainerPosture` and producing a zero-finding scan.
- **Baseline-diff engine** — `cepheus.engine.baseline` with
  `load_baseline(path)` (auto-detects JSON vs. SARIF) and
  `diff(current_chains, baseline_identities) -> BaselineDiff`.
  Identities match on EITHER the chain hash OR the sorted technique-id
  tuple, so a re-tune of the chain builder doesn't trigger
  false-positive regressions on identical primitives. The `removed`
  list is now deterministically ordered across runs.
- **`docs/CI.md`** — operator guide covering the GitHub Actions
  workflow, the three gating patterns (severity-only, regression-only,
  both), and runtime troubleshooting.
- **`cepheus-action/`** — composite GitHub Action that wraps
  `cepheus ci` and uploads SARIF to Code Scanning. Every input is
  funnelled through the step `env:` block (not interpolated into the
  shell script) so untrusted caller inputs cannot inject shell
  commands. All inputs are shape-validated up-front; the action
  fails loudly if SARIF generation produces no file when upload is
  requested, rather than silently skipping the upload step.
- **`.github/workflows/release.yml`** — publishes wheel + sdist on
  `v*.*.*` tag push, uploads release assets, publishes to PyPI when
  `PYPI_API_TOKEN` is set. Missing token is now a hard failure
  (was a silent `exit 0` no-op). Workflow runs with `contents: read`
  by default; jobs widen scope only as needed. The `workflow_dispatch`
  `tag` input is passed via env var and shape-validated before use.
- README has a `cepheus ci` snippet linking to the full CI guide.

#### Verification (`cepheus verify`)

- **`cepheus verify` subcommand** — live-tests each matched technique
  against a running container by `<runtime> exec`-ing a
  non-destructive probe inside it. Three outcomes per technique:
  - `CONFIRMED` — verifier exited 0; primitive works in this container.
  - `NOT_CONFIRMED` — verifier exited non-zero; static match was a
    false positive (typical: EROFS, EPERM, missing tool).
  - `NO_VERIFIER` — technique has no automated probe (kernel CVEs
    where the only confirmation is real exploitation).
  Exit code 0 if any technique is `CONFIRMED`, 1 otherwise. Supports
  `--all-critical` filter, repeatable `--technique ID` for targeted
  runs, and `--format json` for downstream consumption.
- **`EscapeTechnique.cli_flag: str | None`** — explicit typed field
  for the container-runtime flag that closes the primitive
  (e.g. `--cap-drop=SYS_ADMIN`). Replaces the prose-mining regex
  extraction from `remediation` text used pre-0.3.5. A safer
  first-word-only fallback remains for downstream consumers that
  ship their own technique definitions.
- **`EscapeTechnique.verify_command: str | None`** — non-destructive
  shell one-liner that proves the primitive when run inside a matched
  container. 23 of 65 techniques populated; the rest have
  `verify_command=None` (kernel CVEs, RBAC checks that need API
  access, etc.).
- `cepheus.engine.verifier` module with `verify_analysis()`,
  `VerifyOutcome` enum, `TechniqueVerification` + `VerificationReport`
  dataclasses. Distinct sentinel exit codes for "timeout" vs.
  "runtime binary missing" so operators can tell whether to bump
  `--timeout` or fix their docker install.

### Changed

- **`analyze` command body extracted into shared helpers** —
  `_run_analysis`, `_filter_by_severity`, `_render_output` are now
  module-level so `cepheus ci` reuses them without copy-pasting the
  pipeline. Behaviour is unchanged for `analyze`.
- **`enumerate` accepts `--image` as an alternative to `--container-id`**
  — exactly one of the two must be passed (the command exits 2 — the
  same exit code `ci` uses for invocation errors — if both or neither
  are given).
- **`OutputFormat` enum extends** with `sarif`. The `analyze` command
  now accepts `--format sarif` directly (the `ci` command uses it by
  default).
- **14 capability/mount/namespace techniques** now declare an explicit
  `cli_flag`. The analyzer's `RemediationItem.runtime_flag` now reads
  this field directly when populated. The 3 `--security-opt`
  techniques (apparmor/selinux + apparmor-cap) previously had
  INCOMPLETE flag extraction (the regex stopped at the first word and
  dropped the value); the explicit `cli_flag` field fixes them to
  `--security-opt apparmor=docker-default` etc.
- **Verifier outcomes are best-effort non-destructive.** The verifier
  family covers two shapes: pure file/readlink/test probes that
  perform no state change at all, and open-then-close (`exec 3>>…;
  exec 3>&-`) probes that trigger the kernel's permission check
  without ever issuing a write. Two members (`cap_sys_admin_mount`,
  `cap_net_admin`) do perform transient state changes that self-clean
  on the same shell line; treat these as "minimally-destructive
  transient state that self-cleans" rather than "strictly read-only."
- **`cap_dac_override` verifier** rewritten from a create-and-delete
  probe (`:> /var/log/_cepheus_v && rm -f`) to a strictly-readonly
  open-for-append-and-close on `/etc/shadow`, eliminating the
  "interrupt leaks state" failure mode the old probe had.
- **`cap_sys_ptrace` verify_command set to None.** The previous probe
  (`ps -p 1 -o stat=`) only checked /proc/1 readability — true in
  every container — and reported CONFIRMED 100% of the time
  regardless of whether the cap was actually held. NO_VERIFIER is
  honest; always-CONFIRMED is a silent lie.

### Fixed

- **Release-pipeline split-brain prevention.** `release.yml` `publish-pypi`
  job now `needs: [build, attach-to-release]` — was `needs: build` only,
  letting PyPI (which forbids re-uploads) publish before GitHub Release
  assets were durable. If the asset upload then failed, the only
  recovery was bumping the version. The serialized variant trades
  ~30s of pipeline time for an unbreakable invariant.
- **`workflow_dispatch` tag input now actually used in `release.yml`.**
  `Capture metadata` previously read `GITHUB_REF` unconditionally, which
  on `workflow_dispatch` is `refs/heads/<branch>` — so the documented
  manual-dispatch path always failed with a misleading "tag doesn't
  match pyproject.toml version" error. The step now sources from
  `inputs.tag` (env-hoisted) when the trigger is `workflow_dispatch`.
- **`get_all_techniques()` now returns isolated objects.** Pre-0.3.5
  returned `list(_TECHNIQUES)` — a shallow copy where the inner Pydantic
  models were shared. A caller mutating one technique (test fixtures,
  SDK monkey-patching) silently corrupted the global database for every
  subsequent caller. Now returns a `copy.deepcopy` so each caller gets
  its own isolated graph. Negligible cost (~65 model clones, <1ms).
- **`_enumerate_container` empty-stdout guard mirrors `_enumerate_image`.**
  A `docker exec` that exited 0 with empty stdout previously fell
  through to `_validate_posture_json` and surfaced as a confusing
  "did not produce valid JSON" error. Now detected at the source with
  a clear pointer to the actual cause (container's `/bin/sh` exited
  early, enumerator killed mid-run).
- **`_enumerate_container` now streams the script via stdin instead of
  `docker cp` + `docker exec`.** Closes a TOCTOU window where a
  co-tenant process inside the target container could have replaced
  `/tmp/cepheus-enum.sh` between the copy and the exec, getting
  Cepheus's privileged scan to run attacker-controlled code. Also
  eliminates the leftover-script artifact (forensics no longer sees
  an unexplained shell script in `/tmp/` after a scan).
- **Wall-clock timeout (`120s`) on `_enumerate_image` and
  `_enumerate_container`.** A hung enumerator no longer runs forever;
  the host-side subprocess kill fires deterministically.
- **In-container `timeout(1)` wrap on every verifier probe.**
  `docker exec`'s host-side SIGKILL on `subprocess.TimeoutExpired`
  does NOT propagate through the daemon to the in-container shell —
  pre-0.3.5 a timed-out probe left an orphan shell running inside the
  target. The verifier now invokes `timeout -k 1 <budget> sh -c <cmd>`
  inside the container so the wall-clock kill fires in the right
  namespace. Falls back gracefully when `timeout(1)` is missing.
- **`_RC_INFRA = -3` sentinel catches the long tail of OS-side
  subprocess errors.** Pre-0.3.5 `_execute_in_container` only caught
  `TimeoutExpired` and `FileNotFoundError`; `PermissionError`, `OSError`,
  `UnicodeDecodeError` propagated and crashed the entire
  `verify_analysis` walk. Now per-technique `ERROR` rows.
- **Executive summary now describes only the chains the user sees.**
  Pre-0.3.5 the LLM summary was generated BEFORE `_filter_by_severity`,
  so a `--min-severity critical` run produced a report whose summary
  discussed chains the user had explicitly filtered out. The summary
  step now runs after the filter; the per-chain LLM enrichment still
  runs before so the LLM has full cross-chain context.
- **`AnalysisResult.techniques_in_visible_chains`** — additive field
  populated by `_filter_by_severity` with the unique-technique count
  across the post-filter chain set. The legacy `techniques_matched`
  (pre-filter count) is preserved unchanged so dashboards charting it
  over time don't see a step-change. Renderers should prefer the new
  field when present to keep summary counts consistent with rendered
  chain counts.
- **`_render_output` `auto_write_json` gate.** Pre-0.3.5 the auto-write
  fallback fired for any format that wasn't mitre/html/sarif — meaning
  `cepheus ci --format text -o gate.log` silently wrote a JSON report
  into `gate.log`. The `analyze` command (which historically used
  `-o X.json` as shorthand for "give me a JSON file") still gets the
  shortcut via `auto_write_json=True`; `ci` does not, so its text-format
  output is now empty-or-rendered-terminal as expected.
- **`_validate_output_path` helper rejects directory `--output` cleanly.**
  Every `--output` site (`analyze`, `ci`, `diff`, `verify`, `enumerate`)
  previously raised an uncaught `IsADirectoryError` (Linux) /
  `PermissionError` (Windows) when the user passed an existing
  directory. Now a clear "directory, not a file" error at exit code 2.
  Same for `--output` paths whose parent directory doesn't exist.
- **Baseline JSON/SARIF loaders harden against malformed input.**
  `_identities_from_json_report` and `_identities_from_sarif` now use
  `isinstance` defenses throughout — a corrupted or hand-edited
  baseline with `null` chains, non-dict steps, non-list `runs`, or
  non-dict `properties` no longer crashes with an uncaught
  `AttributeError`; entries are silently skipped and the rest of the
  baseline loads. Empty-string technique IDs are dropped at extract
  time so they can't form a `("",)` tuple that spuriously matches
  other corrupted baseline entries.
- **`baseline.diff` consume-on-match: one baseline entry preserves AT
  MOST one current chain.** Pre-0.3.5 if two current chains both matched
  the same baseline entry (same technique tuple, different chain_ids),
  both were appended to `preserved` and the second silently masked a
  regression for `--fail-on-new`. Now the first claims the baseline
  entry and the second correctly falls through to `new`.
- **SARIF format detection in baseline loader loosened.** Now accepts
  any dict with a `runs` array AND either `version` or `$schema` —
  pre-0.3.5 required strict `version == "2.1.0"` string equality,
  rejecting structurally-valid SARIF logs from generators that emit
  `version: 2.1` (numeric) or use only `$schema`.
- **`_generate_remediations` no longer crashes on whitespace-only
  remediation.** `.split()[0]` raises `IndexError` on whitespace-only
  strings; the analyzer now uses safe length-check indexing.
- **Markdown code-fence sanitizer hardened against long backtick runs
  and indented fences.** Pre-0.3.5 the regex `^```` only collapsed the
  FIRST 3 backticks at line start, leaving any leftover backticks
  (10-char run → 7 remaining) to close the outer fence and inject
  arbitrary markdown into Code Scanning UI. New regex
  `^\s{0,3}`{3,}` collapses any 3-or-more-backtick run, including
  CommonMark's up-to-3-space-indented variants.
- **SARIF rules and results builders share the same chain filter.**
  Pre-0.3.5 the rules loop didn't pre-filter empty-step chains while
  the results loop did, producing reports where rule counts could
  drift from result counts.
- **`_render_poc` ImportError catch narrowed to the import statement.**
  Was wrapping both import and call — so a transitive-dep `ImportError`
  raised from inside `render_poc` was silently swallowed and the user
  got a "No PoC template" placeholder. Now only the import is wrapped;
  call-time exceptions surface as real tracebacks.
- **GitHub Action `chain-count=unknown` documented.** Action README now
  shows the right consumer pattern (check for `unknown` before
  numeric comparison) so downstream gates don't silently classify a
  corrupt scan as "all clear."
- **GitHub Action `sarif-sha256` output added.** Captures the
  immediately-post-scan hash of the SARIF file so consumers using the
  action in parallel matrix jobs or with shared output paths can
  detect a later overwrite before the upload step runs.
- **Silent zero-finding scan when enumerator emits empty output.**
  `_enumerate_image` now detects empty stdout (distroless / scratch
  images) and fails loudly instead of returning `""` and letting
  every downstream gate report "no issues." Stderr is also surfaced
  even when the runtime exits 0.
- **`_validate_posture_json` actually validates structure** — was
  named "validate" but only checked `json.loads`-ability; `{}` and
  any other valid-JSON-but-not-a-posture string passed the gate.
  Now also rejects objects missing required top-level keys.
- **Severity-gate filter no longer silently bypasses unknown
  severities.** Pre-0.3.5 used `dict.get(c.severity.value, 0)`,
  routing any new severity tier below every gate. Switched to direct
  indexing so a new enum value raises loudly instead.
- **Posture-validation exception handling narrowed to
  `pydantic.ValidationError`** at three sites in `cli.py`. Previously
  every other exception (model refactor bugs, AttributeError,
  TypeError) collapsed into the same "Invalid posture data" message,
  making real model bugs indistinguishable from bad user input.
- **LLM-client exception handling narrowed** in `_run_analysis` —
  `AttributeError` and `TypeError` are re-raised so programming bugs
  (renamed methods, wrong signatures) surface as tracebacks instead
  of being buried as "LLM failed" warnings. Other exceptions still
  warn-and-continue, now with the exception type name surfaced.
- **`ContainerPosture.hostname` URL-encoded into SARIF URIs.** A
  hostname containing newlines, slashes, or control characters can no
  longer produce a malformed SARIF or break the location rendering
  in Code Scanning.
- **PoC commands sanitized before embedding in SARIF markdown.**
  Triple-backtick fence-breaking sequences in posture-derived
  PoC strings are rewritten to tilde sequences so a malicious
  posture can't escape the code fence and inject arbitrary markdown.
- **Untrusted CLI strings escaped through Rich.** Image references,
  container IDs, and runtime names rendered into CI log output via
  `console.print(f"[cyan]…[/cyan]")` are now passed through
  `rich.markup.escape` so a value like `[link=evil]click[/link]`
  can't inject a clickable link into CI logs.
- **`enumerate` exit code on mutex-violation argv** changed from 1 to
  2 to match the documented exit-code convention in `docs/CI.md`
  (2 = invocation/configuration error).
- **Verifier sentinel exit codes split.** `_RC_TIMEOUT` (-1) and
  `_RC_NO_RUNTIME` (-2) are now distinct so operators can tell
  whether the verifier hit a timeout vs. failed to find `docker` /
  `podman`.
- **`baseline.ChainIdentity.matches` no longer returns true for two
  empty identities.** Corrupted baseline entries with no chain_id and
  no techniques can no longer silently match every degenerate chain.
- **`baseline.load_baseline` surfaces read errors as `ValueError`.**
  Permission errors and encoding errors are now wrapped in
  `ValueError` so the CLI's existing handler produces a polished
  message instead of leaking a raw Python traceback.
- **`baseline.diff` produces deterministic `removed` ordering.**
  Output is now stable across runs against the same inputs; consumers
  diff'ing CI output against itself no longer see spurious churn.
- **Analyzer remediation regex fallback hardened.** Pre-0.3.5
  scanned the full remediation text for any `--` token, which could
  produce inverted advice ("If --privileged is set, drop X" extracted
  `--privileged` as the *fix*). Now matches only the leading token.
- **GitHub Action input handling moved fully to `env:` indirection.**
  Every `${{ inputs.* }}` reference in a `run:` block was a
  script-injection sink; values are now hoisted into the step
  `env:` block and referenced as shell variables, where quoting is
  meaningful.
- **Action validation error strings use single-quoted echo.** Pre-0.3.5
  used double-quoted echo with embedded backticks, which bash
  interpreted as command substitution and would silently invoke
  `image`, `posture-file`, `fail-on-new`, or `baseline` binaries if
  present on PATH.
- **Action SARIF-upload behaviour fails loudly when SARIF is missing.**
  Replaces the prior `hashFiles(inputs.output) != ''` conditional
  that silently skipped the upload step when SARIF write failed —
  which left Code Scanning empty while CI reported success.
- **Action `chain-count` output distinguishes parse-error from zero.**
  Pre-0.3.5 collapsed corrupt-SARIF parse failures into `chain-count=0`;
  now emits `chain-count=unknown` so downstream gates that branch on
  zero results don't mis-classify a broken scan as "all clear."
- **Release workflow fails loudly when `PYPI_API_TOKEN` is unset.**
  Was `exit 0` (silent no-op publish); operator opt-out is now via
  the `SKIP_PYPI` repository variable at the job-conditional level.
- **Release workflow `workflow_dispatch` tag input validated and
  passed via env var.** Pre-0.3.5 interpolated the input directly
  into a bash script (script-injection sink); now hoisted into
  `INPUT_TAG` and shape-validated against `v<n>.<n>.<n>`.
- **ruff version drift between local dev and CI** — `pyproject.toml`'s
  `[project.optional-dependencies].dev` now pins `ruff==0.15.14`
  exactly, matching the pin in `.github/workflows/ci.yml`. Both v0.3.2
  and v0.3.3 had their first CI run go red because a `pip install -e
  ".[dev]"` had silently downgraded local ruff to a version that
  formats `assert + f-string` messages differently from CI's. The
  exact pin closes that drift channel; update CI + dev together when
  bumping ruff.

### Notes

- **Verify outcomes are best-effort non-destructive.** Most probes
  are read-only or use the open-then-close idiom; two
  (`cap_sys_admin_mount`, `cap_net_admin`) perform transient state
  changes that self-clean on the same shell line. The verifier never
  exploits.
- **NOT_CONFIRMED is a precision win, not a recall loss.** If
  `cap_net_admin` matches statically but the container has no `ip`
  binary, the verifier reports NOT_CONFIRMED because it couldn't
  prove the primitive works — not because the cap is absent. Operators
  reading the report should treat NOT_CONFIRMED as "primitive may
  still be exploitable via a different mechanism" rather than
  "completely safe."

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

[Unreleased]: https://github.com/Su1ph3r/Cepheus/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/Su1ph3r/Cepheus/compare/v0.4.2...v0.5.0
[0.4.2]: https://github.com/Su1ph3r/Cepheus/compare/v0.4.0...v0.4.2
[0.4.0]: https://github.com/Su1ph3r/Cepheus/compare/v0.3.5...v0.4.0
[0.3.5]: https://github.com/Su1ph3r/Cepheus/compare/v0.3.3...v0.3.5
[0.3.3]: https://github.com/Su1ph3r/Cepheus/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/Su1ph3r/Cepheus/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/Su1ph3r/Cepheus/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/Su1ph3r/Cepheus/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Su1ph3r/Cepheus/releases/tag/v0.2.0
