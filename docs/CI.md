# Cepheus in CI

`cepheus ci` is the shift-left entry point. It enumerates a container or
image, analyses the posture, applies severity / regression gates, and
exits non-zero when the gates fail — making it a drop-in step for any
Docker build pipeline or pull-request workflow.

## Quick start (GitHub Actions)

```yaml
# .github/workflows/cepheus.yml
name: container security
on: [pull_request]

jobs:
  cepheus:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # required for SARIF upload to Code Scanning
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }

      - name: Install Cepheus
        run: pip install cepheus-engine     # or pip install git+https://github.com/Su1ph3r/Cepheus@v0.4.0

      # Build the image you want to scan.
      - name: Build image
        run: docker build -t my-app:${{ github.sha }} .

      # Cepheus enumerates the image in an ephemeral container, analyses
      # the posture, and writes SARIF. Fails the build if any chain is
      # critical or higher.
      - name: Cepheus CI gate
        run: |
          cepheus ci my-app:${{ github.sha }} \
            --max-severity critical \
            --format sarif \
            --output cepheus.sarif

      # Always upload SARIF — runs even when the previous step failed —
      # so the findings show up in the Security tab.
      - name: Upload SARIF to Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: cepheus.sarif
```

After the first run, GitHub renders Cepheus findings in the repo's
**Security → Code Scanning** tab with rule descriptions, severity
filtering, and dismiss-with-reason tracking.

## Command reference

```text
cepheus ci TARGET [OPTIONS]

  TARGET   Image reference (e.g. nginx:latest) OR path to a posture JSON
           captured previously with `cepheus enumerate`.

Options:
  -b, --baseline      PATH    Previous report (JSON or SARIF). Pairs with
                              --fail-on-new for regression-only gating.
  -m, --max-severity  LEVEL   Fail if any chain is at this severity or higher.
                              One of: low / medium / high / critical.
  --fail-on-new               Fail if any chain is present in TARGET that
                              isn't in --baseline. Requires --baseline.
  -f, --format        FORMAT  sarif (default) / json / text.
  -o, --output        PATH    Write report to file (recommended for CI).
  -r, --runtime       NAME    docker (default) or podman, for image scanning.
```

### Exit codes

| Code | Meaning |
|---|---|
| 0 | All gates passed (or no gate configured). |
| 1 | A gate failed (severity threshold or baseline regression). |
| 2 | Invocation / configuration error (missing baseline, bad target, etc.). |

## Patterns

### Severity-only gate (block any critical chains)

```sh
cepheus ci my-app:latest --max-severity critical --format sarif -o out.sarif
```

Use this when you want a flat "never ship a critical-chain container"
policy. Easy to start with; gets noisy if your baseline image already
has critical chains you can't fix immediately.

### Regression-only gate (only block NEW chains since baseline)

```sh
# In a nightly job against your main branch, capture the baseline:
cepheus ci my-app:main --format sarif -o baseline.sarif

# In PR builds, compare against it:
cepheus ci my-app:${{ github.sha }} \
  --baseline baseline.sarif --fail-on-new \
  --format sarif -o cepheus.sarif
```

Better for repos that haven't fully hardened their containers yet —
existing chains are accepted, new ones block the merge. Pair this with
a periodic "the baseline is too generous" review.

### Both gates (recommended for new projects)

```sh
cepheus ci my-app:${{ github.sha }} \
  --max-severity critical \
  --baseline baseline.sarif --fail-on-new \
  --format sarif -o cepheus.sarif
```

Critical chains block immediately; non-critical regressions block
relative to baseline.

### Scanning a posture captured elsewhere

When the image you want to analyse is in a remote cluster (production
EKS, GKE, etc.), capture the posture from inside a running pod and pipe
it to Cepheus in CI:

```sh
# On the cluster, on demand:
kubectl exec my-pod -- sh /tmp/cepheus-enum.sh > prod-posture.json

# Later, in CI / locally:
cepheus ci prod-posture.json --max-severity high --format sarif -o out.sarif
```

This is the right shape for compliance audits, where you want to verify
the deployed posture rather than the build-time image.

## What image-based enumeration captures

Running the enumerator in an ephemeral `docker run --rm --entrypoint sh
IMAGE /tmp/cepheus-enum.sh` container catches **image-level**
misconfigurations:

- Effective capability set on default-run
- AppArmor / SELinux profile expectations
- Default user / `runAsRoot` posture
- File-system mounts the image itself declares (`/dev`, `/sys`, etc.)
- Kernel CVEs against the host kernel running CI (use a recent runner)
- Available tools / binaries baked into the image

It does **NOT** capture **runtime-injected** posture — Kubernetes
ServiceAccount tokens, hostPath mounts declared in pod specs, cluster
component reachability, etc. For those, enumerate from inside a running
pod (the `kubectl exec` flow above) — the same enumerator works.

## Baseline tips

- Keep baselines in source control (small SARIF files compress well).
- Re-baseline on every release — don't carry forward indefinitely or
  the regression gate loses meaning.
- A reasonable workflow: nightly job updates `baseline.sarif` on the
  `main` branch; PR jobs compare against the tip of `main`'s baseline.

## Troubleshooting

**"Image reference looks suspicious"** — the target argument matched a
heuristic for a URL, flag, or absolute path. Rename or escape if your
image ref legitimately contains `://` (it shouldn't).

**"docker not found in PATH"** — install Docker / Podman on the runner,
or use `--runtime podman` if podman is what's available. GitHub-hosted
Ubuntu runners ship Docker pre-installed.

**"Enumerator did not produce valid JSON"** — the image likely lacks a
POSIX-compatible `sh`. Distroless and scratch images need to be
inspected from a running pod (where Kubernetes ensures a usable
entrypoint), not via image-based enumeration. Use the
`cepheus enumerate --container-id` flow instead.

**SARIF upload fails with "Insufficient permissions"** — the workflow
needs `permissions: { security-events: write }` at the job or workflow
level.
