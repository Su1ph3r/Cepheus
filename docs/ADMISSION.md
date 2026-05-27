# Cepheus as a Kubernetes admission webhook

`cepheus admission-server` runs as a `ValidatingAdmissionWebhook` —
when a user runs `kubectl apply -f pod.yaml`, kube-apiserver hands the
pod spec to Cepheus, which converts it to a synthetic
`ContainerPosture`, runs the analyzer + chain construction, and
returns allow/deny based on configured gates. Deny verdicts include a
message that kubectl surfaces verbatim to the user.

This is shift-LEFT-of-shift-left: pod creation gets blocked before
the kubelet ever schedules it, rather than catching the vulnerable
image at PR time (`cepheus ci`) or post-deploy (`cepheus verify`).

## Prerequisites

- Kubernetes 1.19 or newer (AdmissionReview `admission.k8s.io/v1`).
- [cert-manager](https://cert-manager.io/) installed in the cluster
  (default install path; alternatives in the [TLS section](#tls)).
- Helm 3.

## Quickstart

```sh
helm install cepheus-admission \
  https://github.com/Su1ph3r/Cepheus/raw/main/charts/cepheus-admission \
  --namespace cepheus-system --create-namespace \
  --set gate.maxSeverity=critical
```

Verify the webhook is up:

```sh
kubectl get pods -n cepheus-system
kubectl get validatingwebhookconfiguration cepheus-admission
```

Test the gate:

```sh
# Should be DENIED:
kubectl run cepheus-test --image=nginx --privileged \
  --overrides='{"spec":{"hostPID":true,"volumes":[{"name":"host","hostPath":{"path":"/"}}],"containers":[{"name":"cepheus-test","image":"nginx","volumeMounts":[{"name":"host","mountPath":"/host"}],"securityContext":{"privileged":true}}]}}'

# Should be ADMITTED:
kubectl run cepheus-test --image=nginx \
  --overrides='{"spec":{"containers":[{"name":"cepheus-test","image":"nginx","securityContext":{"runAsNonRoot":true,"capabilities":{"drop":["ALL"]}}}]}}'
```

## What the gate actually evaluates

The admission server runs the FULL Cepheus analyzer pipeline, but
restricts the gate decision to techniques that are **evaluable from a
PodSpec alone** — capability, mount, runtime, combinatorial, and
information-disclosure categories. Kernel CVEs are excluded by
default because they need a kernel version which AdmissionReview
doesn't carry; including them would false-positive every pod on every
cluster.

Per-category coverage at admission time:

| Category | Evaluable | Why |
|---|---|---|
| `capability` | ✅ | PodSpec carries `securityContext.capabilities.{add,drop}` + `privileged` |
| `mount` | ✅ | PodSpec carries `volumes[].hostPath` + `volumeMounts[]` |
| `runtime` | ✅ | PodSpec carries `serviceAccountName`, `automountServiceAccountToken`, `runtimeClassName`, host-namespace flags |
| `combinatorial` | ✅ | Built from primitives the categories above already cover |
| `info_disclosure` | ✅ | Same |
| `kernel` | ✅ when `nodeKernelLookup` enabled | AdmissionReview doesn't carry a kernel version, but the webhook can resolve it per-Node via the K8s API (see [Kernel CVE evaluation](#kernel-cve-evaluation-via-node-lookup) below). Without that, kernel CVEs are dropped from gating because matching against an empty version produces no useful signal. |

For the runtime-only check, run `cepheus verify` against the running
pod AFTER admission — `kubectl exec`-able primitives like the
verifier's open-then-close probes confirm what the static admission
check could only suspect.

## Kernel CVE evaluation via Node lookup

By default the admission webhook can't gate on kernel CVEs because a
PodSpec doesn't carry a kernel version — the kernel is a property of
the Node the pod is scheduled onto, not the pod itself. Enabling
`nodeKernelLookup` flips this on by having the webhook poll the K8s
API for the kernel version of every Node in the cluster, then
evaluating each admission against **every distinct kernel currently
present**. A pod is denied if it produces a gate-violating chain
under any kernel it could plausibly land on.

```yaml
gate:
  includeKernelCves: true     # tells the gate to evaluate kernel CVEs
nodeKernelLookup:
  enabled: true               # tells the webhook to source kernel data
  refreshSeconds: 60          # how often to re-poll the apiserver
```

When `enabled: true`, the chart automatically:

- Mounts a ServiceAccount token into the webhook pod
  (`automountServiceAccountToken: true`).
- Creates a `ClusterRole` granting `nodes: list` and binds it to
  the webhook ServiceAccount.
- Passes `--node-kernel-lookup --node-kernel-refresh-seconds=N` to
  the admission-server process.

### Failure modes

| Condition | Behaviour |
|---|---|
| ServiceAccount lacks `nodes: list` RBAC | Initial fetch fails. If `gate.includeKernelCves=true`, the webhook **fails to start** (exit 2) with a clear error pointing at the RBAC. If `gate.includeKernelCves=false`, the cache is opportunistic — webhook starts, kernel CVE chains stay dropped, error appears in `/readyz`. |
| Apiserver unreachable during a refresh | Last-known kernel snapshot keeps serving. `last_error` updates in the cache; gate decisions continue against the previously-known kernel set. |
| Cluster has heterogeneous kernels (e.g. mid-rolling-upgrade) | Each distinct kernel produces a separate analyzer run; the gate sees the UNION of all chains. A pod is denied if it would violate the gate under any kernel. |
| `nodeKernelLookup.enabled=true` but `gate.includeKernelCves=false` | Cache refreshes in the background but the gate ignores its data. A startup warning is logged. Configure both or neither. |

### RBAC details

The chart's `ClusterRole` has the minimum verbs needed:

```yaml
rules:
  - apiGroups: [""]
    resources: ["nodes"]
    verbs: ["list"]
```

No `watch` (we poll at a fixed interval, simpler failure model), no
`get` (the client only reads the collection endpoint), no write
verbs, no other resources. If your cluster's policy controller
restricts ClusterRole creation, an admin can create the role
out-of-band and point the chart at it via a future
`nodeKernelLookup.existingClusterRoleName` value (not yet
implemented).

## Configuration

The full `values.yaml` is documented inline; the most common flags:

```yaml
# Severity gate — deny pods with any chain at this severity or higher.
gate:
  maxSeverity: "critical"   # "" / low / medium / high / critical

# Baseline regression gate — deny pods that introduce NEW chains vs.
# a previous report.
gate:
  failOnNew: true
baseline:
  contents: |
    {"chains": [{"id": "...", "steps": [...]}]}
  # OR mount a baseline ConfigMap yourself and point at it:
  # gate:
  #   baselinePath: /path/inside/pod/baseline.json

# Failure mode when the webhook is unreachable.
webhookConfig:
  failurePolicy: "Fail"     # "Fail" denies on webhook down; "Ignore" admits
```

### Per-namespace scoping

By default the webhook gates pods in all namespaces except
`kube-system`. Add additional exclusions:

```yaml
webhookConfig:
  namespaceSelector:
    matchExpressions:
      - key: kubernetes.io/metadata.name
        operator: NotIn
        values:
          - kube-system
          - cepheus-system
          - infra-system
```

Or opt IN specific namespaces only:

```yaml
webhookConfig:
  namespaceSelector:
    matchLabels:
      cepheus.io/admission: enabled
```

Then label namespaces you want gated:

```sh
kubectl label namespace prod cepheus.io/admission=enabled
```

### Behaviour on internal error

Two modes:

- `failOpen: true` (default) — admits the pod with a `warnings[]` entry
  in the response. kubectl surfaces these as `Warning: ...` lines.
- `failOpen: false` — denies the pod with the error as the message.

The right choice depends on your `webhookConfig.failurePolicy`:

| `failurePolicy` | `failOpen` | Behaviour |
|---|---|---|
| `Fail` | `true` (default) | Strict gate when healthy; admit-with-warning if Cepheus internal error |
| `Fail` | `false` | Strictest: deny on any internal error |
| `Ignore` | `true` | Loose: admit if webhook unreachable OR errors |
| `Ignore` | `false` | Admit if webhook unreachable; deny on logic errors only |

## TLS

Three modes, controlled by `tls.*` values:

### cert-manager (default, recommended)

```yaml
tls:
  certManager:
    enabled: true
    issuerName: ""           # empty = chart creates a self-signed Issuer
    issuerKind: "Issuer"
    duration: "8760h"        # 1 year
    renewBefore: "720h"      # 30 days
```

cert-manager generates a Certificate, populates a Secret with `tls.crt`
+ `tls.key`, AND auto-populates the
`ValidatingWebhookConfiguration.clientConfig.caBundle` via the
`cert-manager.io/inject-ca-from` annotation. The webhook just works.

Use an EXISTING cert-manager Issuer / ClusterIssuer:

```yaml
tls:
  certManager:
    enabled: true
    issuerName: "my-cluster-issuer"
    issuerKind: "ClusterIssuer"
```

### Bring-your-own secret

```yaml
tls:
  certManager:
    enabled: false
  existingSecret: "my-webhook-tls"
```

The Secret must contain `tls.crt` + `tls.key`. You're responsible for
rotation. You'll also need to populate
`ValidatingWebhookConfiguration.webhooks[].clientConfig.caBundle`
out-of-band, since the chart can't infer the CA from a pre-existing
secret. The cleanest path: include the CA cert as a third key
`ca.crt` in the secret, mount it, and use `cert-manager.io/inject-ca-from-secret`
on the VWC — or just use the cert-manager path.

### Self-signed (dev / kind)

```yaml
tls:
  certManager:
    enabled: false
  selfSigned: true
```

Generates a self-signed cert via a one-shot Job at install time.
**Not suitable for production** — no rotation, no chain.

## Cluster-specific notes

### kind

Works out of the box once cert-manager is installed:

```sh
kind create cluster
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/latest/download/cert-manager.yaml
helm install cepheus-admission charts/cepheus-admission \
  --namespace cepheus-system --create-namespace \
  --set gate.maxSeverity=critical
```

### EKS

cert-manager works the same on EKS. The webhook bind address
(`0.0.0.0`) and the Service type `ClusterIP` are fine for EKS's
VPC-CNI default. No special IRSA configuration needed — the
admission server doesn't need AWS API access.

### GKE

Same as EKS. If your cluster uses Workload Identity, no special
configuration needed for the admission webhook (it doesn't call any
GCP APIs).

GKE Autopilot users: the admission server pod's security context
(non-root, read-only root FS, capabilities dropped) is already
Autopilot-compatible.

### OpenShift

OpenShift requires SCC clearance for the admission server pod. The
default chart settings should fit `restricted-v2` SCC, but if you see
the pod failing to start, check:

```sh
kubectl describe pod -n cepheus-system -l app.kubernetes.io/name=cepheus-admission
```

and add the `serviceaccount` to a compatible SCC if needed:

```sh
oc adm policy add-scc-to-user restricted-v2 \
  -z cepheus-admission -n cepheus-system
```

## Updating the baseline

Capture a baseline from `cepheus ci` or `cepheus analyze`:

```sh
cepheus analyze posture.json --format sarif -o baseline.sarif
```

Then `helm upgrade` with the new baseline:

```sh
helm upgrade cepheus-admission charts/cepheus-admission \
  --namespace cepheus-system \
  --set-file baseline.contents=baseline.sarif \
  --set gate.failOnNew=true
```

The chart computes a checksum of the baseline content and forces a pod
restart on change, so the new baseline takes effect immediately.

## Uninstall

```sh
helm uninstall cepheus-admission --namespace cepheus-system
kubectl delete namespace cepheus-system
```

The `ValidatingWebhookConfiguration` is namespaced under the release
and will be removed by `helm uninstall`. If for any reason it lingers,
delete it manually:

```sh
kubectl delete validatingwebhookconfiguration cepheus-admission
```

## Troubleshooting

### "x509: certificate signed by unknown authority"

The webhook's TLS cert isn't trusted by kube-apiserver. This happens
when:

- `cert-manager` is not installed → install it.
- `cert-manager.io/inject-ca-from` annotation isn't being honored →
  check `kubectl get clusterissuer` / `kubectl get issuer -n cepheus-system`
  and that the Certificate is `Ready`.
- Using `tls.existingSecret` without populating `clientConfig.caBundle`
  on the VWC → patch it manually with your CA's base64.

### Pods are admitted that should be denied

- Verify the gate is configured: `helm get values cepheus-admission -n cepheus-system | grep -A 5 gate`
- Verify the namespace is in scope:
  ```sh
  kubectl get namespace --show-labels
  ```
- Check the webhook logs:
  ```sh
  kubectl logs -n cepheus-system -l app.kubernetes.io/name=cepheus-admission --tail=50
  ```
  Every admission decision is logged (`admission ALLOW ...` /
  `admission DENY ...`).

### Webhook pod CrashLoopBackOff

- TLS cert missing / unreadable → check that the Secret exists:
  ```sh
  kubectl get secret -n cepheus-system | grep tls
  ```
- Invalid `--baseline` file (missing / unparseable) → the server
  exits 2 at startup; logs include the parse error.
- Insufficient resources → bump `resources.limits.memory` if you see
  OOMKilled in `kubectl describe pod`.

### "context deadline exceeded" during pod creation

The webhook is taking >`timeoutSeconds` to respond. Defaults are
generous (10s for a sub-100ms analyzer). Check pod resources and
runtime — `cepheus analyze` against a typical PodSpec finishes in
<50ms.

## Testing the webhook locally

The same admission handler runs in unit tests without TLS:

```sh
pytest tests/test_server/test_admission.py -v
```

For an end-to-end test against a real cluster, spin up kind:

```sh
kind create cluster --name cepheus-e2e
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/latest/download/cert-manager.yaml
kubectl wait --for=condition=available --timeout=120s -n cert-manager deployment --all
helm install cepheus-admission charts/cepheus-admission \
  --namespace cepheus-system --create-namespace \
  --set gate.maxSeverity=critical \
  --set image.tag=0.5.0
kubectl run priv-pod --image=nginx --privileged   # should be DENIED
kubectl run safe-pod --image=nginx                # should be ADMITTED
```
