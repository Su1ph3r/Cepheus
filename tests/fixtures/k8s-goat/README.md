# K8s Goat posture fixtures

10 real-world container posture JSONs captured from a deliberately-vulnerable
Kubernetes Goat (https://github.com/madhuakula/kubernetes-goat) cluster
running on `kind` v0.24 with Kubernetes 1.31.0.

These fixtures power `tests/test_precision_benchmark.py`, the
regression-precision suite that locks in the 100% precision / 100% recall
result established when the precision-overhaul shipped in v0.3.1.

## Pod inventory

| Fixture file | Pod (deployment) | Posture summary |
|---|---|---|
| `T1-system-monitor-posture.json` | `default/system-monitor` | privileged + hostPID + hostIPC + hostPath:/ — textbook host escape |
| `T2-health-check-posture.json` | `default/health-check` | privileged + full caps + writable proc/sys + writable /dev |
| `T3-hunger-check-posture.json` | `big-monolith/hunger-check` | unprivileged, SA token only, overprivileged role |
| `T4-build-code-posture.json` | `default/build-code` | unprivileged, default Docker caps |
| `T5a-internal-api-posture.json` | `default/internal-proxy` (internal-api container) | unprivileged, SSRF proxy |
| `T5b-info-app-posture.json` | `default/internal-proxy` (info-app container) | unprivileged, Flask hint pod |
| `T6-poor-registry-posture.json` | `default/poor-registry` | unprivileged Docker Registry v2 |
| `T9-metadata-db-posture.json` | `default/metadata-db` | unprivileged AWS-IMDS-like emulator |
| `T-cache-store-posture.json` | `secure-middleware/cache-store` | unprivileged Redis seed |
| `T-goat-home-posture.json` | `default/kubernetes-goat-home` | unprivileged landing page |

## Regenerating

If the enumerator schema changes (planned in v0.3.3 — see roadmap), these
fixtures must be regenerated against the new enumerator. Procedure:

```sh
# Spin up a fresh kind cluster + K8s Goat install
kind create cluster --name k8sgoat --image kindest/node:v1.31.0
cd kubernetes-goat && bash setup-kubernetes-goat.sh

# For each pod, copy the enumerator in and dump posture
ENUM=/path/to/Cepheus/enumerator/cepheus-enum.sh
for pod in $(kubectl get pods -A -o jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name} {end}'); do
  ns=${pod%%/*}; name=${pod##*/}
  kubectl -n "$ns" cp "$ENUM" "$name:/tmp/e.sh"
  kubectl -n "$ns" exec "$name" -- sh /tmp/e.sh > posture.json
done

# Copy back into this directory with the T-prefix naming
```

The expected-TP sets in `tests/test_precision_benchmark.py` will need to be
re-baselined any time the technique database or the enumerator schema
changes.
