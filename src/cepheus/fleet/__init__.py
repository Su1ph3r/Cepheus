"""Fleet operations — scan many pods at once, diff cluster postures.

``cepheus fleet scan`` walks every running pod in a kubeconfig context
(optionally filtered by ``--namespace`` or ``--selector``), runs the
analyzer against each pod's PodSpec via the same importer the
admission webhook uses, and emits a single combined report.

``cepheus fleet diff`` consumes two scan reports and emits a posture
delta — which pods gained or lost chains, which pods changed score —
so an operator can answer "did anything regress overnight?" in one
diff rather than N invocations.

Both commands shell out to ``kubectl`` rather than embedding a Python
Kubernetes client. Operators already have kubectl configured for their
target cluster; relying on it keeps the install surface tiny and the
RBAC story identical to every other kubectl invocation the operator
runs.
"""

from cepheus.fleet.diff import FleetDiff, diff_reports
from cepheus.fleet.scan import FleetReport, FleetScanError, PodReport, scan_cluster

__all__ = ["FleetDiff", "FleetReport", "FleetScanError", "PodReport", "diff_reports", "scan_cluster"]
