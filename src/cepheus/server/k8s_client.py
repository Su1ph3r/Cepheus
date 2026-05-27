"""Minimal Kubernetes API client for the admission webhook.

Implemented on stdlib (``urllib.request`` + ``ssl``) so the admission
server stays at zero new runtime dependencies — same constraint as the
rest of ``cepheus.server.admission``. The official ``kubernetes`` PyPI
client is ~30 MB of transitive deps for a one-endpoint call.

Scope is deliberately narrow: list Node objects, read
``status.nodeInfo.kernelVersion`` off each. Authentication uses the
in-cluster ServiceAccount projected token + the apiserver CA, so the
client works automatically when the admission server runs as a Pod
with a SA bound to a ClusterRole granting ``nodes: list``.

``NodeKernelCache`` wraps the client in a background thread that
re-polls the node list every ``refresh_interval`` seconds. Per-request
work is then a single in-memory snapshot read instead of a synchronous
API round-trip per admission, so an apiserver outage doesn't stall
admission decisions — the cache serves the last-known kernel set with
``last_error`` exposed via ``/readyz`` on the admission server.

Threat-model hardening (vs naive stdlib HTTPS client):

  * ServiceAccount tokens are projected with a kubelet-enforced TTL
    (default ~1 hour) and rotated in place. The client re-reads the
    token file on every request so refreshes keep working across
    rotations.
  * The CA trust store is pinned EXPLICITLY to the in-pod CA file.
    If the file is missing or unreadable, we refuse to build the
    client — falling back to the system trust store would be a
    silent downgrade that lets an attacker with an apiserver-host
    redirect (env-var injection, malicious sidecar) feed forged
    Node data signed by a public CA.
  * ``KUBERNETES_SERVICE_HOST``/``PORT`` env values are validated
    against a strict shape before being interpolated into the URL,
    closing the userinfo-injection vector
    (``host=evil.example.com/foo``, ``port=443@attacker.com``).
  * HTTP redirects are refused outright — the default urllib opener
    follows 30x AND replays the bearer token to the new host. A
    custom opener rejects every redirect so a compromised or
    misconfigured upstream can't exfiltrate the SA token.
"""

from __future__ import annotations

import http.client
import json
import logging
import os
import re
import socket
import ssl
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger("cepheus.k8s_client")

# Standard in-pod ServiceAccount projection paths. Both files are
# present in any Pod whose ServiceAccount has
# ``automountServiceAccountToken`` not set to False. The CA is the
# apiserver's serving CA, not a generic bundle — verifying against the
# system trust store would be wrong.
_TOKEN_PATH = Path("/var/run/secrets/kubernetes.io/serviceaccount/token")
_CA_PATH = Path("/var/run/secrets/kubernetes.io/serviceaccount/ca.crt")

# Hard cap on the apiserver response body. Node lists in a large
# cluster are a few hundred KB; 16 MB is a generous DoS shield.
_MAX_RESPONSE_BYTES = 16 * 1024 * 1024

# Per-request timeout to the apiserver. The cache refreshes in the
# background, so a slow apiserver only delays the next refresh — it
# does not block admission. Default chosen to match the webhook's
# own ``timeoutSeconds`` so we fail before the apiserver gives up on us.
_DEFAULT_REQUEST_TIMEOUT_SEC = 10.0

# Floor on the cache refresh interval. Kernel versions only change on
# node reboot — values below 5s have no operational benefit and turn a
# misconfigured Helm value into a self-inflicted DoS on the apiserver.
_MIN_REFRESH_INTERVAL_SEC = 5.0

# Strict shape for KUBERNETES_SERVICE_HOST: DNS label / dotted hostname
# / bare IPv4 / bracketed IPv6. Rejects path separators, userinfo
# markers, scheme prefixes, and anything else that could re-target the
# URL after interpolation.
_HOST_RE = re.compile(r"^(?:[A-Za-z0-9](?:[A-Za-z0-9.\-]*[A-Za-z0-9])?|\[[0-9a-fA-F:]+\])$")
_PORT_RE = re.compile(r"^\d{1,5}$")


class K8sAPIError(RuntimeError):
    """Raised on apiserver communication failure, non-2xx response, or
    unexpected protocol behaviour (redirects, oversized bodies).

    The cache layer catches this and records it in ``last_error`` rather
    than tearing down the refresh thread — a transient apiserver hiccup
    shouldn't stop the admission server from running on its last-known
    snapshot.
    """


@dataclass
class NodeInfo:
    """One Node's identity + kernel version. Other status fields are
    available but we only need the kernel version for now; the rest can
    be added without breaking callers since this is a dataclass."""

    name: str
    kernel_version: str
    os_image: str = ""
    container_runtime_version: str = ""


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject every redirect. The default ``HTTPRedirectHandler`` re-
    sends the ``Authorization`` header to the redirect target — which
    would leak the ServiceAccount bearer token to any host that returns
    a 30x. Kube-apiserver never returns 30x on ``/api/v1/nodes`` under
    normal operation, so blocking redirects is a free hardening that
    closes the token-exfil vector if a malicious sidecar / proxy is
    inserted into the request path."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ARG002
        raise K8sAPIError(
            f"apiserver returned unexpected redirect {code} -> {newurl!r}; "
            "refusing to follow (would re-send bearer token to a different host)"
        )


def _build_opener(ssl_ctx: ssl.SSLContext) -> urllib.request.OpenerDirector:
    """Per-client opener with the supplied SSL context bound to the
    HTTPS handler and the no-redirect handler installed.

    ``OpenerDirector.open()`` does not accept a ``context`` keyword
    (that's a ``urlopen`` arg) — the context must be wired in via
    ``HTTPSHandler(context=...)``. Building one opener per K8sClient
    instead of a module-level singleton is cheap and lets tests inject
    their own SSL contexts cleanly.
    """
    https_handler = urllib.request.HTTPSHandler(context=ssl_ctx)
    return urllib.request.build_opener(_NoRedirectHandler(), https_handler)


def _build_pinned_ssl_context(ca_path: Path) -> ssl.SSLContext:
    """Build an SSL context that ONLY trusts the supplied CA — not the
    system trust store. ``ssl.create_default_context()`` mixes in the
    OS CAs, which is the wrong choice here: an attacker who can
    redirect the URL (see env-var validation in ``in_cluster``) could
    otherwise feed us forged Node data signed by any public CA."""
    if not ca_path.is_file():
        raise K8sAPIError(
            f"apiserver CA not found at {ca_path} — refusing to fall back to "
            "the system trust store for cluster-internal authentication"
        )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_verify_locations(cafile=str(ca_path))
    return ctx


class K8sClient:
    """Minimal apiserver client. Constructor takes explicit args so
    tests can inject a fake server URL + token; the ``in_cluster``
    factory wires up the in-pod ServiceAccount projection."""

    def __init__(
        self,
        api_server: str,
        token: str | None = None,
        ca_cert_path: str | Path | None = None,
        *,
        token_path: str | Path | None = None,
        request_timeout_sec: float = _DEFAULT_REQUEST_TIMEOUT_SEC,
    ) -> None:
        """Build a client.

        Either ``token`` (a literal bearer string, used by tests) or
        ``token_path`` (a filesystem path to re-read on every request,
        used in-cluster) must be supplied. ``token_path`` is the
        production path: projected SA tokens rotate in place every
        ~hour and a captured-at-startup token starts failing with 401s
        until the pod restarts — which the cache's preserve-on-error
        path would mask. Re-reading the file per request stays cheap
        (<1 KB, OS page cache) and keeps refreshes working across
        rotations.
        """
        if not api_server:
            raise ValueError("api_server is required (e.g. https://kubernetes.default.svc:443)")
        if token is None and token_path is None:
            raise ValueError("either token or token_path is required for apiserver authentication")
        if token is not None and not token:
            raise ValueError("token cannot be an empty string")

        self._api_server = api_server.rstrip("/")
        self._static_token = token
        self._token_path = Path(token_path) if token_path is not None else None
        self._request_timeout_sec = request_timeout_sec
        ssl_ctx = (
            _build_pinned_ssl_context(Path(ca_cert_path))
            if ca_cert_path is not None
            else ssl.create_default_context()
        )
        self._opener = _build_opener(ssl_ctx)

    @classmethod
    def in_cluster(
        cls,
        *,
        request_timeout_sec: float = _DEFAULT_REQUEST_TIMEOUT_SEC,
    ) -> "K8sClient":
        """Build a client from the in-pod ServiceAccount projection.

        Validates the env-var URL components against a strict shape so a
        downward-API-injection vector (an attacker writing
        ``KUBERNETES_SERVICE_HOST=evil.example.com/path``) can't
        re-target the bearer token at an arbitrary host. Raises
        ``K8sAPIError`` with a clear message if the projection is
        incomplete or malformed.
        """
        host = os.environ.get("KUBERNETES_SERVICE_HOST", "")
        port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
        if not host:
            raise K8sAPIError(
                "KUBERNETES_SERVICE_HOST not set — not running inside a Kubernetes pod, "
                "or the env var was scrubbed. Cannot auto-detect apiserver."
            )
        if not _HOST_RE.match(host):
            # Reject anything that isn't a bare hostname / IPv4 / bracketed IPv6.
            # Prevents userinfo-style URL injection (``user@host``), path
            # injection (``host/foo``), and scheme-smuggling (``http://x``).
            raise K8sAPIError(
                f"KUBERNETES_SERVICE_HOST has unexpected format: {host!r} — "
                "expected a DNS name, IPv4 address, or bracketed IPv6 literal"
            )
        if not _PORT_RE.match(port):
            raise K8sAPIError(
                f"KUBERNETES_SERVICE_PORT has unexpected format: {port!r} — expected a port number"
            )
        port_int = int(port)
        if not (1 <= port_int <= 65535):
            raise K8sAPIError(f"KUBERNETES_SERVICE_PORT out of range: {port_int}")

        if not _TOKEN_PATH.is_file():
            raise K8sAPIError(
                f"ServiceAccount token not found at {_TOKEN_PATH} — "
                "the Pod's ServiceAccount must have automountServiceAccountToken enabled "
                "for the kernel-lookup feature to work."
            )
        # CA path is validated inside _build_pinned_ssl_context via the
        # constructor — we don't pre-check it here so the failure mode
        # (TOCTOU race) is impossible.
        api_server = f"https://{host}:{port}"
        return cls(
            api_server=api_server,
            token_path=_TOKEN_PATH,
            ca_cert_path=_CA_PATH,
            request_timeout_sec=request_timeout_sec,
        )

    def list_nodes(self) -> list[NodeInfo]:
        """Return one NodeInfo per Node in the cluster.

        Uses the core/v1 endpoint (no field selector — node lists are
        small enough that filtering server-side isn't worth the
        complexity). Nodes without a kernel version in status are
        included with an empty string; the cache layer drops empties so
        a partially-reported cluster doesn't poison the snapshot.
        """
        body = self._get(f"{self._api_server}/api/v1/nodes")
        try:
            payload = json.loads(body)
        except json.JSONDecodeError as exc:
            raise K8sAPIError(f"apiserver returned invalid JSON: {exc}") from exc

        items = payload.get("items") or []
        nodes: list[NodeInfo] = []
        for item in items:
            meta = item.get("metadata") or {}
            name = meta.get("name", "")
            status = item.get("status") or {}
            node_info = status.get("nodeInfo") or {}
            nodes.append(
                NodeInfo(
                    name=name,
                    kernel_version=node_info.get("kernelVersion", ""),
                    os_image=node_info.get("osImage", ""),
                    container_runtime_version=node_info.get("containerRuntimeVersion", ""),
                )
            )
        return nodes

    def _current_token(self) -> str:
        """Return the current bearer token.

        Production path: re-reads ``_token_path`` from disk every call
        so projected-SA-token rotation works (kubelet swaps the file in
        place every ~hour). Test path: returns the static token passed
        at construction. The disk read is sub-millisecond (small file,
        page-cached) and gated on the request rate.
        """
        if self._token_path is not None:
            try:
                token = self._token_path.read_text(encoding="utf-8").strip()
            except OSError as exc:
                raise K8sAPIError(
                    f"could not read ServiceAccount token at {self._token_path}: {exc}"
                ) from exc
            if not token:
                raise K8sAPIError(
                    f"ServiceAccount token at {self._token_path} is empty — "
                    "kubelet may be mid-rotation; refresh will retry"
                )
            return token
        # Static-token mode (tests).
        assert self._static_token is not None  # constructor enforces this
        return self._static_token

    def _get(self, url: str) -> bytes:
        """HTTPS GET with bearer auth. Raises K8sAPIError on any
        non-2xx, transport error, oversized response, or unexpected
        redirect."""
        request = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {self._current_token()}",
                "Accept": "application/json",
                # Identifying ourselves in apiserver audit logs makes it
                # easy to tell "Cepheus admission webhook polling
                # nodes" apart from random scrapers in operator
                # incident response.
                "User-Agent": "cepheus-admission/k8s-client",
            },
            method="GET",
        )
        try:
            with self._opener.open(  # noqa: S310 — URL is constructed from validated apiserver base
                request,
                timeout=self._request_timeout_sec,
            ) as response:
                # ``read(n+1)`` then check len lets us detect that the
                # response would exceed the cap WITHOUT having to read
                # the whole oversized body into memory.
                data = response.read(_MAX_RESPONSE_BYTES + 1)
                if len(data) > _MAX_RESPONSE_BYTES:
                    raise K8sAPIError(
                        f"apiserver response exceeds {_MAX_RESPONSE_BYTES} byte cap — "
                        "refusing to read further"
                    )
                return data
        except urllib.error.HTTPError as exc:
            # 401/403 are the most common failures here: ServiceAccount
            # lacks `nodes: list`. Surface the status code so the
            # operator sees it in logs / readyz.
            raise K8sAPIError(f"apiserver returned HTTP {exc.code}: {exc.reason}") from exc
        except (urllib.error.URLError, socket.timeout, OSError, ssl.SSLError,
                http.client.HTTPException) as exc:
            # ``http.client.HTTPException`` covers ``IncompleteRead``,
            # ``BadStatusLine``, ``LineTooLong`` — transport-layer
            # protocol errors that the default catch list misses, and
            # that would otherwise propagate up to the cache's
            # refresh thread and silently kill it.
            raise K8sAPIError(f"apiserver request failed: {type(exc).__name__}: {exc}") from exc


@dataclass(frozen=True)
class CacheSnapshot:
    """Immutable view of the cache state. ``frozen=True`` is
    structural: it stops a future refactor from doing
    ``self._snapshot.last_error = "..."`` in-place, which would tear
    reads against the refresh-thread writer."""

    kernel_versions: frozenset[str] = field(default_factory=frozenset)
    last_refresh_at: float = 0.0  # epoch seconds; 0 means "never succeeded"
    last_error: str = ""  # last refresh error; "" means "last attempt succeeded"


class NodeKernelCache:
    """Background-refreshing cache of distinct cluster kernel versions.

    Why a cache instead of querying per admission:
      * Per-admission apiserver calls add latency to every Pod create
        and couple admission availability to apiserver availability,
        for data that changes on the order of node reboots (hours/days).
      * A 60s-stale snapshot is fine for this use case: if a new node
        with a vulnerable kernel joins the cluster mid-poll, the worst
        case is one admission window before we start gating on it.

    Failure modes:
      * Refresh raises an exception → log WARNING, preserve last-known
        snapshot, record ``last_error`` for ``/readyz``.
      * Refresh succeeds but returns zero usable kernels → if we had
        data before, treat this like a refresh failure: preserve the
        last-known set and surface a WARNING. A transition from
        "kernel set known" to "kernel set empty" silently disables
        gating, so we refuse to make it silent. A truly-empty cluster
        (zero nodes) is logged at INFO so an operator running on a
        scaled-down cluster knows what they're seeing.
      * Unexpected exception in the refresh thread → caught by an
        outer guard in ``_run``; we'd rather loop forever on a known
        error than have the thread silently die and freeze the cache.
    """

    def __init__(
        self,
        client: K8sClient,
        *,
        refresh_interval_sec: float = 60.0,
    ) -> None:
        if refresh_interval_sec < _MIN_REFRESH_INTERVAL_SEC:
            raise ValueError(
                f"refresh_interval_sec={refresh_interval_sec!r} is below the "
                f"{_MIN_REFRESH_INTERVAL_SEC}s floor — kernel versions only change "
                "on node reboot, more aggressive polling DoSes the apiserver "
                "with no operational benefit"
            )
        self._client = client
        # Public so /readyz can compute staleness without reaching into a private attr.
        self.refresh_interval_sec = refresh_interval_sec
        self._lock = threading.Lock()
        self._snapshot = CacheSnapshot()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self, *, fetch_now: bool = True, require_initial_fetch: bool = False) -> None:
        """Start the background refresh thread. Idempotent.

        Args:
            fetch_now: When True (default), do a synchronous initial
                fetch so the first admission already has a populated
                snapshot.
            require_initial_fetch: When True, propagate the initial
                fetch's ``K8sAPIError`` instead of swallowing it. Used
                by the CLI to fail-fast when the operator explicitly
                opted into kernel-CVE gating: silently starting in an
                empty-snapshot state would mean kernel CVEs are not
                gated, defeating the operator's intent.
        """
        if self._thread is not None and self._thread.is_alive():
            return
        if fetch_now:
            if require_initial_fetch:
                self.refresh_now()
            else:
                self._refresh_once()
        self._thread = threading.Thread(
            target=self._run,
            daemon=True,
            name="cepheus-node-kernel-refresh",
        )
        self._thread.start()
        logger.info(
            "node-kernel cache started: interval=%.1fs initial_kernels=%s",
            self.refresh_interval_sec,
            sorted(self._snapshot.kernel_versions),
        )

    def stop(self) -> None:
        """Signal the refresh thread to exit. Idempotent."""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None

    def __enter__(self) -> "NodeKernelCache":
        return self

    def __exit__(self, *_exc_info) -> None:
        self.stop()

    def snapshot(self) -> CacheSnapshot:
        """Atomic snapshot read. Safe to call from any thread."""
        with self._lock:
            return self._snapshot

    def refresh_now(self) -> None:
        """Synchronous refresh that re-raises K8sAPIError on failure.

        For callers that need to know whether the apiserver is
        reachable + RBAC is correct (CLI startup with explicit opt-in).
        Background callers should use ``_refresh_once`` which absorbs
        the error into the snapshot.
        """
        nodes = self._client.list_nodes()
        self._apply_refresh(nodes)

    def _refresh_once(self) -> None:
        """Single polling attempt. Errors are recorded into the snapshot
        but never propagate — the calling thread loops on this and
        stalling out would defeat the purpose of the cache."""
        try:
            nodes = self._client.list_nodes()
        except K8sAPIError as exc:
            logger.warning("node-kernel refresh failed: %s", exc)
            with self._lock:
                # Preserve last-known kernel set; just update the error.
                self._snapshot = CacheSnapshot(
                    kernel_versions=self._snapshot.kernel_versions,
                    last_refresh_at=self._snapshot.last_refresh_at,
                    last_error=str(exc),
                )
            return
        self._apply_refresh(nodes)

    def _apply_refresh(self, nodes: list[NodeInfo]) -> None:
        """Commit a successful list_nodes() result to the snapshot,
        with empty-result protection.

        If the new kernel set is empty AND we had a non-empty set
        before, we preserve the prior set + record the transition
        as ``last_error``. Going from "kernel set known" to "kernel
        set empty" silently disables kernel-CVE gating, which is
        exactly the kind of failure mode we don't want to hide.
        A truly empty cluster (zero nodes) is logged at INFO.
        """
        # Empty kernel strings happen briefly during node bootstrap
        # before kubelet posts node status. Drop them so the kernel set
        # doesn't contain a no-op entry that techniques can't match
        # against anyway.
        new_kernels = frozenset(n.kernel_version for n in nodes if n.kernel_version)
        with self._lock:
            prev_kernels = self._snapshot.kernel_versions
            if not new_kernels and prev_kernels:
                # Suspicious posture cliff. Preserve.
                msg = (
                    f"refresh returned 0 usable kernels from {len(nodes)} nodes; "
                    f"preserved prior set {sorted(prev_kernels)} — "
                    "check RBAC drift / node drain / apiserver pagination"
                )
                logger.warning("node-kernel %s", msg)
                self._snapshot = CacheSnapshot(
                    kernel_versions=prev_kernels,
                    last_refresh_at=self._snapshot.last_refresh_at,
                    last_error=msg,
                )
                return
            self._snapshot = CacheSnapshot(
                kernel_versions=new_kernels,
                last_refresh_at=time.time(),
                last_error="",
            )
        if not new_kernels:
            logger.info(
                "node-kernel refresh ok but cluster has 0 nodes reporting kernel data"
            )
        else:
            logger.debug(
                "node-kernel refresh ok: nodes=%d distinct_kernels=%d",
                len(nodes),
                len(new_kernels),
            )

    def _one_tick(self) -> None:
        """One refresh attempt with thread-safety guard.

        Extracted from ``_run`` so the guard semantics can be unit-
        tested without a daemon thread / sleep. The outer broad-except
        is rare-case-justified: a daemon thread that silently dies on
        an unexpected exception is strictly worse than one that loops
        forever on a recurring error — the dying-thread case freezes
        ``last_error`` at its last successful value and ``/readyz``
        then lies. The looping case at least keeps the error visible.
        """
        try:
            self._refresh_once()
        except Exception as exc:  # noqa: BLE001 — see docstring
            logger.exception(
                "node-kernel refresh thread caught unexpected error; continuing"
            )
            with self._lock:
                self._snapshot = CacheSnapshot(
                    kernel_versions=self._snapshot.kernel_versions,
                    last_refresh_at=self._snapshot.last_refresh_at,
                    last_error=f"unexpected {type(exc).__name__}: {exc}",
                )

    def _run(self) -> None:
        """Refresh loop. Sleeps in small chunks so ``stop()`` is
        responsive without waiting out a full refresh interval."""
        while not self._stop.is_set():
            # Sleep first — initial fetch happened in ``start()``.
            # ``Event.wait`` returns True if stop was set, which lets us
            # exit promptly during tests.
            if self._stop.wait(self.refresh_interval_sec):
                return
            self._one_tick()
