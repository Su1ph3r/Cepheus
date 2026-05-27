# Changelog

All notable changes to the `cepheus-action` GitHub Action will be
documented in this file.

The action is version-locked to a Cepheus release — `vX.Y.Z` of the
action installs and runs Cepheus `X.Y.Z`. Action-only changes (input
schema, output schema, install plumbing) ship as patch bumps inside
the same engine major/minor when needed.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.6.1] - 2026-05-27

Initial release of the standalone action repo. The action itself has
been part of [`Su1ph3r/Cepheus`](https://github.com/Su1ph3r/Cepheus)
under `cepheus-action/` since v0.4.0; this is the first release in
the dedicated `Su1ph3r/cepheus-action` repo so consumers can
reference it as `uses: Su1ph3r/cepheus-action@v0.6.1` and so the
GitHub Actions Marketplace can list it.

The first standalone-action release is tagged `v0.6.1` (not
`v0.6.0`) because the Cepheus PyPI distribution had to be renamed
from `cepheus` to `cepheus-engine` at v0.6.1 (the bare name was
already taken on PyPI by an unrelated project), and the action
depends on a PyPI install. Earlier Cepheus releases never published
to PyPI.

### Behaviour

- Installs Cepheus `0.6.1` from PyPI as the
  [`cepheus-engine`](https://pypi.org/project/cepheus-engine/)
  distribution (`pip install cepheus-engine==0.6.1`). The installed
  CLI binary is still named `cepheus` and `import cepheus` still
  works — only the PyPI distribution name differs.
- Composite action — runs on any Linux runner with `docker` (or
  `podman`, configurable) available.
- Inputs: `image`, `posture-file`, `max-severity`, `baseline`,
  `fail-on-new`, `output`, `upload-sarif`, `cepheus-version`,
  `runtime`, `python-version`. Exactly one of `image` /
  `posture-file` is required.
- Outputs: `sarif-path`, `passed`, `chain-count`, `sarif-sha256`.
- Hardened against script injection — every `inputs.*` value is
  routed through an `env:` block as `INPUT_*` so GitHub never
  string-substitutes user-controlled input into a shell command.
- Auto-uploads the SARIF report to GitHub Code Scanning when the
  job has `permissions: { security-events: write }`.

### Source of truth

The action is developed in
[`Su1ph3r/Cepheus`](https://github.com/Su1ph3r/Cepheus) under
`cepheus-action/`. A release-triggered sync workflow mirrors that
directory to this repo and tags the same version on every Cepheus
release. PRs against `Su1ph3r/cepheus-action` directly should be
opened against [`Su1ph3r/Cepheus`](https://github.com/Su1ph3r/Cepheus/pulls)
instead — changes to this repo are overwritten on the next release.
