# cepheus-action

GitHub Action wrapping [Cepheus](https://github.com/Su1ph3r/Cepheus) — a
container escape scanner. Fails the build on severity or baseline-regression
gates and uploads SARIF to GitHub Code Scanning.

> **Note**: This directory is the source of truth for the action. At each
> release of Cepheus we extract these files to the standalone
> `Su1ph3r/cepheus-action` repo so users can reference it as
> `Su1ph3r/cepheus-action@v0.4.0`. The action itself is thin — it just
> installs Cepheus and calls `cepheus ci` — so it rarely needs to change
> independently.
>
> The action ships with `cepheus-version: '0.4.0'` as the default install
> target so consumers get a reproducible cepheus version on every action
> invocation. Override with `cepheus-version: <pep440>` if you need a
> different release.

## Quick start

```yaml
# .github/workflows/cepheus.yml
name: container security
on: [pull_request]

jobs:
  cepheus:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write   # required for SARIF upload
    steps:
      - uses: actions/checkout@v4

      - name: Build image
        run: docker build -t my-app:${{ github.sha }} .

      - name: Cepheus scan
        uses: Su1ph3r/cepheus-action@v0.4.0
        with:
          image: my-app:${{ github.sha }}
          max-severity: critical
```

The action installs Cepheus from PyPI, runs `cepheus ci` against your
image, writes a SARIF report, and uploads it to GitHub Code Scanning.
The build fails if any chain is at the `max-severity` threshold or
higher.

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `image` | one of | — | Image reference to scan (e.g. `nginx:latest`). |
| `posture-file` | one of | — | Path to a previously-captured posture JSON. Use for cluster-side scans. |
| `max-severity` | no | (none) | Fail if any chain ≥ this severity (`low`/`medium`/`high`/`critical`). |
| `baseline` | no | — | Previous Cepheus report (JSON or SARIF) for regression detection. |
| `fail-on-new` | no | `false` | Fail if any chain in current isn't in `baseline`. Requires `baseline`. |
| `output` | no | `cepheus.sarif` | SARIF output file. |
| `upload-sarif` | no | `true` | Auto-upload to Code Scanning. Requires `security-events: write`. |
| `cepheus-version` | no | `0.4.0` | Pin Cepheus to a specific version on PyPI. Defaults to the version this action ships alongside so installs are reproducible. |
| `runtime` | no | `docker` | `docker` or `podman`. |
| `python-version` | no | `3.12` | Python version for Cepheus install. |

Exactly one of `image` / `posture-file` must be passed.

## Outputs

| Output | Description |
|---|---|
| `sarif-path` | Path to the SARIF file written by the scan. |
| `passed` | `true` if all gates passed, else `false`. |
| `chain-count` | Decimal-integer string of detected escape chains, or the literal string `unknown` if the SARIF could not be parsed (see note below). |
| `sarif-sha256` | Hex SHA-256 of the SARIF file as written by the scan. Use when multiple action invocations in one job could overwrite the SARIF path. |

### Handling `chain-count`

Downstream workflow steps that gate on the chain count MUST handle the
`unknown` value explicitly. A naïve numeric comparison would silently
treat a corrupt scan as "all clear":

```yaml
# WRONG — treats `unknown` the same as a passing scan:
- if: ${{ steps.cepheus.outputs.chain-count == '0' }}
  run: echo "all clear"

# RIGHT — explicitly fails when the SARIF couldn't be parsed:
- name: Verify scan integrity
  if: ${{ steps.cepheus.outputs.chain-count == 'unknown' }}
  run: |
    echo "::error::Cepheus did not produce a parseable SARIF file."
    exit 1
- if: ${{ steps.cepheus.outputs.chain-count == '0' }}
  run: echo "all clear"
```

## Gating patterns

### Severity-only gate

```yaml
- uses: Su1ph3r/cepheus-action@v0.4.0
  with:
    image: my-app:${{ github.sha }}
    max-severity: critical
```

Simple. Block any container that ships a critical chain.

### Regression-only gate

```yaml
- uses: Su1ph3r/cepheus-action@v0.4.0
  with:
    image: my-app:${{ github.sha }}
    baseline: .github/cepheus-baseline.sarif
    fail-on-new: true
```

Better for existing projects with imperfect baselines — only blocks NEW
chains, lets existing ones through.

### Both

```yaml
- uses: Su1ph3r/cepheus-action@v0.4.0
  with:
    image: my-app:${{ github.sha }}
    max-severity: critical
    baseline: .github/cepheus-baseline.sarif
    fail-on-new: true
```

Critical chains always block. Anything else blocks only if it's new
relative to `main`.

### Scanning a deployed pod (out-of-band capture)

When the workload you want to gate on is in a cluster, capture the
posture outside CI and reference it in the workflow:

```yaml
# Step 1 (run on a host with cluster access, e.g. nightly cron):
#   kubectl exec my-pod -- sh /tmp/cepheus-enum.sh > prod-posture.json
#   gh api repos/ORG/REPO/contents/.github/prod-posture.json ...

# Step 2 (in CI):
- uses: Su1ph3r/cepheus-action@v0.4.0
  with:
    posture-file: .github/prod-posture.json
    max-severity: high
```

## Required permissions

The job needs at least:

```yaml
permissions:
  contents: read
  security-events: write   # only required if upload-sarif: true
```

## Troubleshooting

- **"Resource not accessible by integration"** on the SARIF upload step
  → the job is missing `security-events: write`.
- **Build fails immediately with "image not found"** → the action runs
  *after* checkout but doesn't build the image for you. Add a `docker
  build` step before the action call.
- **"Pass exactly one of image or posture-file"** → don't pass both, and
  don't omit both.

## Versioning

The action is version-locked to the Cepheus release it ships alongside.
`@v0.4.0` installs Cepheus 0.4.0. `@main` tracks the latest dev version
(not recommended for CI). Pin to a specific tag in production workflows.

## License

MIT — same as the underlying Cepheus tool.
