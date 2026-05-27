"""Tests for cepheus.server.k8s_client.

Coverage focuses on:
  * K8sClient.list_nodes() parsing of a realistic apiserver response.
  * Auth header + URL construction (verified via a fake urlopen).
  * NodeKernelCache: initial fetch, atomic snapshot reads,
    refresh-error preservation of last-known kernel set.
  * In-cluster auto-detection failure modes (missing env / files).

No real apiserver involved — urlopen is monkeypatched so the tests
don't depend on a Kubernetes cluster or network.
"""

from __future__ import annotations

import io
import json
import threading
import time

import pytest

from cepheus.server.k8s_client import (
    K8sAPIError,
    K8sClient,
    NodeInfo,
    NodeKernelCache,
)

# --- K8sClient ------------------------------------------------------


class _FakeResponse:
    """Stand-in for urlopen()'s context-manager return value. Holds a
    fixed body; mimics the read(n) interface the client uses."""

    def __init__(self, body: bytes):
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False

    def read(self, n: int | None = None) -> bytes:
        if n is None:
            return self._body
        return self._body[:n]


def _node_item(name: str, kernel: str, *, os_image: str = "Ubuntu 22.04.3 LTS") -> dict:
    return {
        "metadata": {"name": name},
        "status": {
            "nodeInfo": {
                "kernelVersion": kernel,
                "osImage": os_image,
                "containerRuntimeVersion": "containerd://1.7.11",
            }
        },
    }


def _patch_opener(monkeypatch, client: "K8sClient", captured: list, response_body: bytes):
    """Replace the client's per-instance opener.open with a recorder
    that returns a fixed body. ``OpenerDirector.open(request,
    timeout=...)`` is the actual call shape — no ``context`` kwarg
    (the SSL context is bound to the HTTPSHandler at opener-build
    time)."""

    class _RecorderOpener:
        @staticmethod
        def open(request, *, timeout: float):
            captured.append(
                {
                    "url": request.full_url,
                    "headers": dict(request.headers),
                    "method": request.get_method(),
                    "timeout": timeout,
                }
            )
            return _FakeResponse(response_body)

    monkeypatch.setattr(client, "_opener", _RecorderOpener)


# Backwards-compatible alias for tests that want to install the
# recorder before constructing the client (e.g. parametrized fixture
# style); they should instead patch on the instance.
def _patch_urlopen(monkeypatch, captured: list, response_body: bytes):
    """Module-level patch shim that swaps every K8sClient's opener at
    construction time. Used by tests that build the client AFTER the
    patch is installed; tests that want to patch a specific instance
    should call ``_patch_opener`` directly."""
    original_init = K8sClient.__init__

    class _RecorderOpener:
        @staticmethod
        def open(request, *, timeout: float):
            captured.append(
                {
                    "url": request.full_url,
                    "headers": dict(request.headers),
                    "method": request.get_method(),
                    "timeout": timeout,
                }
            )
            return _FakeResponse(response_body)

    def patched_init(self, *args, **kwargs):
        original_init(self, *args, **kwargs)
        self._opener = _RecorderOpener  # type: ignore[assignment]

    monkeypatch.setattr(K8sClient, "__init__", patched_init)


def test_list_nodes_returns_kernel_versions(monkeypatch):
    body = json.dumps(
        {
            "items": [
                _node_item("node-a", "5.15.0-76-generic"),
                _node_item("node-b", "6.1.0-13-amd64"),
            ]
        }
    ).encode("utf-8")
    captured: list = []
    _patch_urlopen(monkeypatch, captured, body)

    client = K8sClient(api_server="https://k8s.example:443", token="t", ca_cert_path=None)
    nodes = client.list_nodes()

    assert nodes == [
        NodeInfo(
            name="node-a",
            kernel_version="5.15.0-76-generic",
            os_image="Ubuntu 22.04.3 LTS",
            container_runtime_version="containerd://1.7.11",
        ),
        NodeInfo(
            name="node-b",
            kernel_version="6.1.0-13-amd64",
            os_image="Ubuntu 22.04.3 LTS",
            container_runtime_version="containerd://1.7.11",
        ),
    ]
    assert captured[0]["url"] == "https://k8s.example:443/api/v1/nodes"
    # Header names normalize via urllib — match case-insensitively.
    headers_ci = {k.lower(): v for k, v in captured[0]["headers"].items()}
    assert headers_ci["authorization"] == "Bearer t"
    assert headers_ci["accept"] == "application/json"
    assert captured[0]["method"] == "GET"


def test_list_nodes_handles_missing_kernel_field(monkeypatch):
    """Bootstrapping Nodes briefly have empty status.nodeInfo. The
    client returns them with empty kernel_version strings; the cache
    layer is responsible for dropping empties from the snapshot."""
    body = json.dumps(
        {
            "items": [
                {"metadata": {"name": "node-a"}, "status": {"nodeInfo": {}}},
                _node_item("node-b", "5.15.0-76-generic"),
            ]
        }
    ).encode("utf-8")
    _patch_urlopen(monkeypatch, [], body)
    client = K8sClient(api_server="https://k8s.example:443", token="t", ca_cert_path=None)
    nodes = client.list_nodes()
    assert nodes[0].kernel_version == ""
    assert nodes[1].kernel_version == "5.15.0-76-generic"


def test_list_nodes_raises_on_http_error(monkeypatch):
    import urllib.error

    class _ErrorOpener:
        @staticmethod
        def open(request, *, timeout):  # noqa: ARG004
            raise urllib.error.HTTPError(
                url="https://k8s.example:443/api/v1/nodes",
                code=403,
                msg="Forbidden",
                hdrs=None,
                fp=io.BytesIO(b""),
            )

    client = K8sClient(api_server="https://k8s.example:443", token="t", ca_cert_path=None)
    monkeypatch.setattr(client, "_opener", _ErrorOpener)
    with pytest.raises(K8sAPIError, match="HTTP 403"):
        client.list_nodes()


def test_list_nodes_raises_on_invalid_json(monkeypatch):
    _patch_urlopen(monkeypatch, [], b"not json at all")
    client = K8sClient(api_server="https://k8s.example:443", token="t", ca_cert_path=None)
    with pytest.raises(K8sAPIError, match="invalid JSON"):
        client.list_nodes()


def test_client_constructor_rejects_empty_inputs():
    with pytest.raises(ValueError, match="api_server"):
        K8sClient(api_server="", token="t", ca_cert_path=None)
    with pytest.raises(ValueError, match="token"):
        K8sClient(api_server="https://k8s.example", token="", ca_cert_path=None)


def test_in_cluster_raises_without_env(monkeypatch):
    monkeypatch.delenv("KUBERNETES_SERVICE_HOST", raising=False)
    with pytest.raises(K8sAPIError, match="KUBERNETES_SERVICE_HOST not set"):
        K8sClient.in_cluster()


# --- env-var URL injection defences --------------------------------


@pytest.mark.parametrize(
    "host",
    [
        "evil.example.com/foo",            # path injection
        "user@attacker.com",                # userinfo injection
        "kubernetes.default.svc:443",       # smuggled port via host
        "http://evil",                      # scheme smuggling
        "host with spaces",
        "",                                 # caught earlier but exercise the regex
    ],
)
def test_in_cluster_rejects_malformed_host(host, monkeypatch):
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", host)
    monkeypatch.setenv("KUBERNETES_SERVICE_PORT", "443")
    with pytest.raises(K8sAPIError):
        K8sClient.in_cluster()


@pytest.mark.parametrize("port", ["443@attacker", "abc", "70000", "-1"])
def test_in_cluster_rejects_malformed_port(port, monkeypatch):
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc")
    monkeypatch.setenv("KUBERNETES_SERVICE_PORT", port)
    with pytest.raises(K8sAPIError):
        K8sClient.in_cluster()


# --- CA pinning -----------------------------------------------------


def test_constructor_raises_when_ca_file_missing(tmp_path):
    """A non-None ca_cert_path that doesn't exist on disk MUST fail
    loud rather than silently falling back to the system trust store —
    the operator asked to pin to a specific CA, and silently using a
    different one would let an attacker with apiserver-host redirect
    feed forged Node data signed by any public CA."""
    missing = tmp_path / "does-not-exist.crt"
    with pytest.raises(K8sAPIError, match="apiserver CA not found"):
        K8sClient(api_server="https://k8s.example:443", token="t", ca_cert_path=missing)


# --- bearer token rotation -----------------------------------------


def test_token_path_is_reread_on_every_request(monkeypatch, tmp_path):
    """Projected ServiceAccount tokens rotate in place every ~hour.
    The client MUST re-read the file per request — caching at
    construction would silently start failing with 401s after the
    first rotation, and the cache's preserve-on-error logic would
    hide it as "apiserver unreachable" rather than the truth
    ("token expired")."""
    token_file = tmp_path / "token"
    token_file.write_text("token-v1", encoding="utf-8")
    captured: list = []
    _patch_urlopen(
        monkeypatch,
        captured,
        json.dumps({"items": []}).encode("utf-8"),
    )

    client = K8sClient(
        api_server="https://k8s.example:443",
        token_path=token_file,
        ca_cert_path=None,
    )
    client.list_nodes()
    token_file.write_text("token-v2-after-rotation", encoding="utf-8")
    client.list_nodes()

    auth_headers = [
        {k.lower(): v for k, v in c["headers"].items()}["authorization"]
        for c in captured
    ]
    assert auth_headers == [
        "Bearer token-v1",
        "Bearer token-v2-after-rotation",
    ]


def test_empty_token_file_raises_on_use(monkeypatch, tmp_path):
    """An empty token file usually means kubelet is mid-rotation. The
    refresh thread treats this as a transient error (preserve last-
    known snapshot) — but the client itself must signal it loud
    enough to be classified as a refresh failure rather than a
    successful empty-list response."""
    token_file = tmp_path / "token"
    token_file.write_text("", encoding="utf-8")
    client = K8sClient(api_server="https://k8s.example:443", token_path=token_file, ca_cert_path=None)
    with pytest.raises(K8sAPIError, match="empty"):
        client.list_nodes()


def test_constructor_requires_token_or_path():
    with pytest.raises(ValueError, match="token or token_path"):
        K8sClient(api_server="https://k8s.example:443", ca_cert_path=None)


# --- transport error handling --------------------------------------


def test_list_nodes_wraps_incomplete_read(monkeypatch):
    """``http.client.IncompleteRead`` is a transport-layer protocol
    error that bypasses the default URLError/OSError catches.
    Confirmed to be funneled into K8sAPIError so the cache refresh
    thread doesn't die silently."""
    import http.client

    class _BrokenOpener:
        @staticmethod
        def open(request, *, timeout):  # noqa: ARG004
            raise http.client.IncompleteRead(b"partial")

    client = K8sClient(api_server="https://k8s.example:443", token="t", ca_cert_path=None)
    monkeypatch.setattr(client, "_opener", _BrokenOpener)
    with pytest.raises(K8sAPIError, match="IncompleteRead"):
        client.list_nodes()


def test_no_redirect_handler_refuses_redirect_directly():
    """The _NoRedirectHandler is a private symbol but the contract
    matters: it raises K8sAPIError on any 30x so the bearer token
    can't be replayed to an attacker-controlled host. Test the
    handler directly to avoid spinning up a full HTTP test server."""
    from cepheus.server.k8s_client import _NoRedirectHandler

    handler = _NoRedirectHandler()
    with pytest.raises(K8sAPIError, match="refusing to follow"):
        handler.redirect_request(
            req=None, fp=None, code=302, msg="Found",
            headers={}, newurl="https://attacker.example.com/api/v1/nodes",
        )


# --- refresh-interval floor -----------------------------------------


@pytest.mark.parametrize("interval", [0.0, -1.0, 0.5, 4.999])
def test_cache_rejects_too_aggressive_refresh_interval(interval):
    class _NoopClient:
        def list_nodes(self):
            return []

    with pytest.raises(ValueError, match="below the .* floor|positive"):
        NodeKernelCache(_NoopClient(), refresh_interval_sec=interval)


# --- NodeKernelCache -----------------------------------------------


class _StubClient:
    """Records list_nodes() calls + lets a test toggle the response.

    Used in place of a real K8sClient so the cache can be exercised
    without involving urlopen at all.
    """

    def __init__(self, nodes_sequence):
        # nodes_sequence is a list of lists-or-exceptions; the cache
        # pulls one entry per refresh and the last entry sticks.
        self._sequence = list(nodes_sequence)
        self.calls = 0

    def list_nodes(self):
        self.calls += 1
        if not self._sequence:
            return []
        item = self._sequence[0]
        if len(self._sequence) > 1:
            self._sequence.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def test_cache_initial_fetch_populates_snapshot():
    stub = _StubClient(
        nodes_sequence=[
            [
                NodeInfo(name="node-a", kernel_version="5.15.0-76-generic"),
                NodeInfo(name="node-b", kernel_version="6.1.0-13-amd64"),
                NodeInfo(name="node-c", kernel_version="6.1.0-13-amd64"),  # duplicate
            ],
        ]
    )
    cache = NodeKernelCache(stub, refresh_interval_sec=3600.0)
    try:
        cache.start(fetch_now=True)
        snap = cache.snapshot()
        assert snap.kernel_versions == frozenset({"5.15.0-76-generic", "6.1.0-13-amd64"})
        assert snap.last_refresh_at > 0
        assert snap.last_error == ""
    finally:
        cache.stop()


def test_cache_drops_empty_kernel_strings():
    """A node that hasn't reported kernel status yet shows up with an
    empty kernel_version. The cache must drop those — including them
    would produce an unmatched-anything entry in the kernel set."""
    stub = _StubClient(
        nodes_sequence=[
            [
                NodeInfo(name="bootstrapping", kernel_version=""),
                NodeInfo(name="node-a", kernel_version="5.15.0-76-generic"),
            ],
        ]
    )
    cache = NodeKernelCache(stub, refresh_interval_sec=3600.0)
    try:
        cache.start(fetch_now=True)
        assert cache.snapshot().kernel_versions == frozenset({"5.15.0-76-generic"})
    finally:
        cache.stop()


def test_cache_preserves_last_known_set_when_refresh_returns_empty():
    """If the apiserver returns ``{"items": []}`` (RBAC drift, all
    nodes drained, paginated truncation), the cache MUST preserve
    the prior kernel set rather than silently emptying it — going
    from "kernel set known" to "kernel set empty" disables kernel-
    CVE gating without any signal except a DEBUG-level log line."""
    first_nodes = [NodeInfo(name="node-a", kernel_version="5.15.0-76-generic")]
    stub = _StubClient(nodes_sequence=[first_nodes, []])  # second refresh returns empty
    cache = NodeKernelCache(stub, refresh_interval_sec=3600.0)
    try:
        cache.start(fetch_now=True)
        assert cache.snapshot().kernel_versions == frozenset({"5.15.0-76-generic"})
        cache._refresh_once()
        snap = cache.snapshot()
        assert snap.kernel_versions == frozenset({"5.15.0-76-generic"}), (
            "empty refresh must not empty the kernel set"
        )
        assert "preserved prior set" in snap.last_error
    finally:
        cache.stop()


def test_cache_accepts_empty_when_no_prior_data():
    """A fresh start against a 0-node cluster (test envs, scaled-down
    clusters) is a legitimate state — we shouldn't pretend something
    was there before. Only the empty-AFTER-non-empty transition is
    suspicious."""
    stub = _StubClient(nodes_sequence=[[]])
    cache = NodeKernelCache(stub, refresh_interval_sec=3600.0)
    try:
        cache.start(fetch_now=True)
        snap = cache.snapshot()
        assert snap.kernel_versions == frozenset()
        assert snap.last_error == ""
        assert snap.last_refresh_at > 0
    finally:
        cache.stop()


def test_refresh_now_propagates_api_errors():
    """The public ``refresh_now`` API re-raises K8sAPIError so callers
    (CLI fail-fast on opt-in) can distinguish "apiserver reachable +
    RBAC OK" from "silent fallback to empty cache"."""
    stub = _StubClient(nodes_sequence=[K8sAPIError("apiserver returned HTTP 403: Forbidden")])
    cache = NodeKernelCache(stub, refresh_interval_sec=3600.0)
    with pytest.raises(K8sAPIError, match="403"):
        cache.refresh_now()


def test_start_require_initial_fetch_propagates_failure():
    """``start(require_initial_fetch=True)`` is the CLI-facing
    fail-fast path: if the operator opted into kernel-CVE gating, an
    initial fetch failure must be exit 2 rather than a silent
    degraded start."""
    stub = _StubClient(nodes_sequence=[K8sAPIError("apiserver returned HTTP 403: Forbidden")])
    cache = NodeKernelCache(stub, refresh_interval_sec=3600.0)
    with pytest.raises(K8sAPIError, match="403"):
        cache.start(fetch_now=True, require_initial_fetch=True)


def test_one_tick_catches_unexpected_exception_and_records_it():
    """A non-K8sAPIError raised from inside the refresh path must NOT
    kill the daemon thread. The ``_one_tick`` guard catches anything
    that escaped ``_refresh_once`` (which itself only catches
    K8sAPIError) and records it into ``last_error`` so ``/readyz``
    surfaces the failure instead of silently freezing the cache."""
    cache = NodeKernelCache(_StubClient(
        nodes_sequence=[[NodeInfo(name="n", kernel_version="5.15.0-76-generic")]]
    ), refresh_interval_sec=5.0)
    try:
        cache.start(fetch_now=True)
        assert cache.snapshot().kernel_versions == frozenset({"5.15.0-76-generic"})

        # Force the next tick's _refresh_once to raise something
        # K8sAPIError-catch doesn't cover.
        def _raise(*_a, **_kw):
            raise RuntimeError("synthetic non-K8sAPIError bug from refresh path")

        cache._refresh_once = _raise  # type: ignore[method-assign]
        cache._one_tick()  # would crash the daemon thread without the guard

        snap = cache.snapshot()
        assert "RuntimeError" in snap.last_error
        assert "synthetic" in snap.last_error
        # last-known kernel set preserved:
        assert snap.kernel_versions == frozenset({"5.15.0-76-generic"})
    finally:
        cache.stop()


def test_cache_preserves_last_known_set_on_refresh_failure():
    """If a refresh fails (apiserver down, RBAC revoked), the snapshot
    keeps the last-known kernel set + records the error rather than
    silently emptying the cache."""
    first_nodes = [NodeInfo(name="node-a", kernel_version="5.15.0-76-generic")]
    stub = _StubClient(
        nodes_sequence=[
            first_nodes,
            K8sAPIError("apiserver returned HTTP 403: Forbidden"),
        ]
    )
    cache = NodeKernelCache(stub, refresh_interval_sec=3600.0)
    try:
        cache.start(fetch_now=True)
        # Sanity: initial fetch loaded the kernel set.
        assert cache.snapshot().kernel_versions == frozenset({"5.15.0-76-generic"})

        # Trigger a manual refresh that hits the failure.
        cache._refresh_once()
        snap = cache.snapshot()
        assert snap.kernel_versions == frozenset({"5.15.0-76-generic"}), (
            "refresh failure must not empty the kernel set"
        )
        assert "403" in snap.last_error
    finally:
        cache.stop()


def test_cache_stop_is_idempotent_and_quick():
    stub = _StubClient(nodes_sequence=[[NodeInfo(name="n", kernel_version="5.15.0-76-generic")]])
    cache = NodeKernelCache(stub, refresh_interval_sec=3600.0)
    cache.start(fetch_now=True)
    t0 = time.time()
    cache.stop()
    cache.stop()  # second call must be a no-op
    assert time.time() - t0 < 1.0


def test_cache_snapshot_is_thread_safe_under_writes():
    """Sanity: snapshot reads from many threads while refreshes write
    don't crash or yield torn state. Not a stress test — just a smoke
    check that the locking strategy works."""
    stub = _StubClient(
        nodes_sequence=[
            [NodeInfo(name=f"n{i}", kernel_version=f"5.15.0-{i}-generic") for i in range(50)],
        ]
    )
    cache = NodeKernelCache(stub, refresh_interval_sec=3600.0)
    cache.start(fetch_now=True)
    try:
        stop = threading.Event()

        def reader():
            while not stop.is_set():
                snap = cache.snapshot()
                # Every snapshot must be a non-empty frozenset of the
                # expected size — atomic semantics.
                assert isinstance(snap.kernel_versions, frozenset)
                assert len(snap.kernel_versions) == 50

        threads = [threading.Thread(target=reader, daemon=True) for _ in range(8)]
        for t in threads:
            t.start()
        # Run a handful of explicit refreshes against the same data.
        for _ in range(20):
            cache._refresh_once()
        stop.set()
        for t in threads:
            t.join(timeout=2.0)
    finally:
        cache.stop()
