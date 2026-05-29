# Cepheus threat model & audit scope

Cepheus is a defensive security tool: it enumerates container posture and
models escape paths. This document records its trust boundaries, the
mitigations already in place, and the proposed scope for an external
security audit ahead of broad 1.0 adoption.

## Trust boundaries & assets

Cepheus processes attacker-influenceable input in several places. Each is
a boundary where untrusted data crosses into Cepheus.

### 1. Untrusted posture JSON (`cepheus analyze` / `ci` / `diff`)
A posture file (or a scanned image's enumeration) can be attacker-shaped
— hostnames, kernel strings, env values, mount paths.
- **Mitigations:** Pydantic validation at the boundary; SARIF code-fence
  sanitizer (`output/sarif.py:_sanitize_for_code_fence`) collapses any
  3+-backtick run so posture-derived PoC text can't break out of the
  embedding fence and inject markdown into GitHub Code Scanning; the
  hostname is `quote(...)`-encoded into the SARIF `container://` URI;
  the HTML report renders through Jinja `autoescape=True`.

### 2. Untrusted SARIF in the web viewer (`web/index.html`)
The viewer is designed to open arbitrary, possibly third-party SARIF
files dropped by a user.
- **Mitigations:** all SARIF-derived content is inserted via
  `textContent` / `createTextNode` (never `innerHTML`); the one
  attribute sink (`helpUri` → `href`) is scheme-validated to http(s),
  rendering any `javascript:`/`data:` URI inert; numeric properties are
  coerced via `numOrNull` so malformed values can't crash rendering.
  Pure helpers are unit-tested (`web/viewer.test.js`).

### 3. kubectl / cluster (`cepheus fleet scan`)
User-supplied namespace/selector/context/kubeconfig flow into a kubectl
invocation.
- **Mitigations:** the command is built as an argv list passed to
  `subprocess.run` with no shell; each value follows its own flag, so a
  value beginning with `-` is consumed as a flag value, not parsed as a
  new flag. `shutil.which` guards the binary.

### 4. Admission webhook `/validate`
The webhook receives AdmissionReview requests on a TLS port.
- **Mitigations:** server-side TLS (1.2 floor); **optional mTLS**
  (`--client-ca`) requires + verifies the kube-apiserver client cert;
  body size capped (1 MiB); fail-open vs fail-closed is explicit; a
  notifier failure can never convert a deny into an admit (dispatch is
  off the decision path, on daemon threads, fully exception-wrapped);
  the `cepheus.io/policy` per-pod label can only weaken enforcement and
  grants no privilege beyond what `securityContext` already exposes
  (unknown values fall back to `enforce`).
- **Residual / defense-in-depth:** without mTLS, the endpoint trusts
  network reachability — a caller able to reach the TLS port could
  trigger notifications (bounded by the DENY/WARN rate buckets) but
  cannot affect a real pod's admission. NetworkPolicy scoping to the
  apiserver is the recommended complement; mTLS closes it directly.

### 5. Notifier outbound URLs (Slack / PagerDuty / generic webhook)
Operator-supplied endpoints, POSTed to on deny/warn.
- **Mitigations:** outbound-only (no inbound surface); best-effort,
  rate-limited per decision (DENY has an independent higher ceiling so a
  WARN flood can't starve deny alerts); webhook URLs are redacted to
  scheme+host in logs (`_redact`).

### 6. Node-kernel Kubernetes API client (`--node-kernel-lookup`)
The webhook optionally reads Node objects via the in-cluster API.
- **Mitigations:** CA-pinned TLS with no system-trust fallback;
  hostname verification; a no-redirect handler prevents replaying the
  ServiceAccount bearer token to another host; the SA token is re-read
  per request (rotation-safe); the API host/port env vars are
  regex-validated; least-privilege RBAC (`nodes: list` only).

### 7. Update channel (`cepheus update [--apply]`)
- **Mitigations:** the version check is an unauthenticated GET to a
  hardcoded GitHub API host with a 2 MiB read cap and a strict tag
  regex; `is_newer` returns False on any unparseable input (never a
  spurious "out of date"). `--apply` shells to the *detected* package
  manager (pipx/pip/brew/scoop) only after an interactive confirmation;
  binary/unknown installs are never auto-replaced.

### 8. Release / supply chain
Artifacts are built in CI and published to GitHub Releases, GHCR, PyPI,
Homebrew, and Scoop.
- **Current state:** SHA256SUMS are published with releases; the
  release pipeline gates PyPI publish behind durable GitHub Release
  assets. Artifact signing (cosign / SLSA provenance) is **not yet**
  implemented — see audit scope below.

## Accepted risks (1.0)
- The technique DB ships in the wheel/binary; there is no independent
  signed technique-DB channel in 1.0 (deferred — updating Cepheus
  updates the DB).
- The notifier rate buckets are intentionally lossy under sustained
  bursts (best-effort delivery); operators relying on notifications for
  detection should also consume the admission server logs.

## Proposed external-audit scope
Priorities for a third-party review (e.g. Trail of Bits / NCC), in
order:
1. **Injection surfaces:** the SARIF/HTML/markdown sanitizers and the
   kubectl argv construction (boundaries 1 & 3).
2. **Admission webhook trust model:** mTLS, fail-open/closed semantics,
   the per-pod policy label, and the node-kernel client's token handling
   (boundaries 4 & 6).
3. **Web viewer DOM safety** for arbitrary third-party SARIF (boundary 2).
4. **Supply chain:** add cosign signing + SLSA provenance to the release
   pipeline and audit the build/publish flow (boundary 8).

## Reporting
Security issues: see the repository's security policy / `SECURITY.md`.
Do not file public issues for undisclosed vulnerabilities.
