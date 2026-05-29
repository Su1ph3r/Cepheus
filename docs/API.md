# Cepheus public API (1.x)

Cepheus follows [semantic versioning](https://semver.org). This document
defines what is covered by that promise for the 1.x series. Anything not
listed here is an internal implementation detail and may change in any
release without notice.

## Stable Python API

Import the engine entry points from `cepheus.engine` and the data models
from `cepheus.models`. These names, their call signatures, and their
documented return types are stable across 1.x minor/patch releases:

```python
from cepheus.engine import (
    analyze,                     # (ContainerPosture, CepheusConfig|None) -> AnalysisResult
    verify_analysis,             # run non-destructive verifier probes
    load_baseline,               # (path) -> set[ChainIdentity]
    baseline_diff,               # (chains, baseline) -> BaselineDiff
    diff_postures,               # (before, after, config|None) -> DiffResult
    get_all_techniques,          # () -> list[EscapeTechnique]
    get_technique_by_id,         # (str) -> EscapeTechnique | None
    get_techniques_by_category,  # (TechniqueCategory) -> list[EscapeTechnique]
)
from cepheus.models import (
    ContainerPosture, KubernetesInfo,
    EscapeChain, ChainStep,
    AnalysisResult, RemediationItem,
    EscapeTechnique, Prerequisite, Severity, TechniqueCategory,
)
```

Each module's `__all__` is the source of truth for the exported surface.

## Output contracts

The serialized outputs are stable interfaces too:

- **SARIF 2.1.0** (`cepheus ... -f sarif`): rule and result `properties`
  keys are additive. Existing keys are not renamed or removed within
  1.x. Compliance keys (`cis-kubernetes-benchmark`, `nist-800-190`,
  `pci-dss`) are present only when a technique is mapped — absence means
  "not mapped", never "no control applies". Each result also carries
  `impact` (the consequence/end-state) and `affected-components` (the
  container plus the subsystems the chain abuses); each rule carries
  `remediation` (the operator recommendation, including the runtime flag
  that closes the primitive when one exists) and, when curated, `impact`.
- **JSON report** (`-f json`): `AnalysisResult.model_dump(mode="json")`.
  Fields are additive.
- **Exit codes**: `cepheus ci` / gating commands return `0` (pass), `1`
  (gate tripped), `2` (usage/IO error). Stable within 1.x.

## Model mutability

Cepheus enriches results in place during analysis, so not every model is
immutable. This is intentional and part of the contract:

| Model | Frozen? | Why |
|-------|---------|-----|
| `ChainStep` | **yes** | Built once by the chainer; never mutated. |
| `RemediationItem` | **yes** | Built once; never mutated. |
| `EscapeChain` | no | The scorer sets `composite_score` after construction. |
| `AnalysisResult` | no | The CLI attaches LLM analysis / executive summary and applies severity filtering. |
| `ContainerPosture` / `KernelInfo` | no | The analyzer backfills distro-kernel metadata. |
| `EscapeTechnique` | no | The technique DB applies the compliance crosswalk; SDK consumers may patch `verify_command` for sandboxed runs. |

Treat the non-frozen models as read-only unless you are deliberately
driving the analysis pipeline.

## Not part of the API

- Anything under `cepheus.engine.*` not re-exported from
  `cepheus.engine` (e.g. `chainer`, `matcher`, `scorer`, internal
  helpers prefixed with `_`).
- The `web/` SARIF viewer internals and the Helm chart template
  structure (the chart's `values.yaml` keys are a separate, documented
  surface).
- CLI output *formatting* (table layout, colors). Parse the JSON/SARIF
  outputs for machine consumption, not the human-rendered tables.
