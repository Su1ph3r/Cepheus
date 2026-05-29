"""Best-effort outbound notifications for the admission webhook.

When the webhook denies a pod (or admits one in warn mode), it can
POST a structured event to Slack, PagerDuty, and/or a generic webhook.
Notifications are:

  * **Best-effort.** A failed POST is logged and dropped. We never
    block the admission decision on a notifier — kube-apiserver has
    a tight timeout on validating webhooks (default 10s, the chart
    sets ours to 5s) and a slow notifier would convert a healthy
    deny into a webhook-timeout admit.
  * **Fire-and-forget.** Each notification is dispatched on a daemon
    thread. The admission handler's hot path runs zero network I/O.
  * **Rate-limited per decision.** DENY and WARN events have separate
    token buckets, so a flood of WARN notifications can never starve
    delivery of the security-critical DENY alerts.
  * **Outbound-only.** No webhooks are exposed; we always initiate
    the connection. No inbound auth surface.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from dataclasses import dataclass
from typing import Any

import urllib.error
import urllib.parse
import urllib.request

logger = logging.getLogger("cepheus.notifiers")

# Per-decision rate limits. DENY events are security-critical signals,
# so they get an independent, higher ceiling than WARN events — a flood
# of WARN notifications (e.g. a warn-mode rollout) must never starve the
# delivery of a DENY alert. Each bucket still bounds outbound volume
# against a misconfigured controller that retries an admission rapidly.
_DENY_RATE_MAX_TOKENS = 20.0
_DENY_RATE_REFILL_PER_SEC = 5.0
_WARN_RATE_MAX_TOKENS = 5.0
_WARN_RATE_REFILL_PER_SEC = 1.0

# Outbound HTTP timeout. PagerDuty Events API SLA is "well under one
# second"; Slack's incoming-webhook is similar. Five seconds covers
# any plausible transient latency without blocking the dispatch thread
# longer than is useful — webhook timeouts upstream are 10-30s.
_NOTIFIER_TIMEOUT_SEC = 5.0


@dataclass
class NotifierConfig:
    """Notification endpoints. Empty/None means that channel is
    disabled — operators opt in per-channel via the chart values or
    CLI flags. Any combination can be enabled simultaneously.

    ``webhook_url`` is a generic JSON sink (any HTTP endpoint); Slack
    and PagerDuty use their provider-specific payload shapes."""

    slack_webhook_url: str | None = None
    pagerduty_routing_key: str | None = None
    webhook_url: str | None = None

    @property
    def any_enabled(self) -> bool:
        return bool(self.slack_webhook_url) or bool(self.pagerduty_routing_key) or bool(self.webhook_url)


@dataclass
class AdmissionEvent:
    """The payload notifiers send. Constructed by the admission
    handler from its own decision context — keeps the notifier code
    decoupled from the AdmissionConfig / response shapes."""

    decision: str  # "DENY" | "WARN"
    namespace: str
    pod_name: str
    reason: str
    uid: str
    chain_count: int


class _TokenBucket:
    def __init__(self, max_tokens: float, refill_per_sec: float) -> None:
        self.max_tokens = max_tokens
        self.refill_per_sec = refill_per_sec
        self._tokens = max_tokens
        self._last = time.monotonic()
        self._lock = threading.Lock()

    def try_consume(self, n: float = 1.0) -> bool:
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last
            self._tokens = min(self.max_tokens, self._tokens + elapsed * self.refill_per_sec)
            self._last = now
            if self._tokens >= n:
                self._tokens -= n
                return True
            return False


_DENY_BUCKET = _TokenBucket(_DENY_RATE_MAX_TOKENS, _DENY_RATE_REFILL_PER_SEC)
_WARN_BUCKET = _TokenBucket(_WARN_RATE_MAX_TOKENS, _WARN_RATE_REFILL_PER_SEC)


def _bucket_for(decision: str) -> _TokenBucket:
    """DENY uses the higher-ceiling bucket; everything else (WARN) the lower one."""
    return _DENY_BUCKET if decision == "DENY" else _WARN_BUCKET


def _slack_payload(ev: AdmissionEvent) -> dict[str, Any]:
    return {
        # Plain `text` works on any Slack workspace; richer Block Kit
        # formatting requires the workspace to allow attachments and
        # gracefully degrades anyway, so we keep it simple.
        "text": (
            f":cepheus: Admission {ev.decision} in `{ev.namespace}/{ev.pod_name}`\n"
            f"> {ev.reason}\n"
            f"_chains={ev.chain_count} uid={ev.uid}_"
        ),
    }


def _pagerduty_payload(ev: AdmissionEvent, routing_key: str) -> dict[str, Any]:
    # PagerDuty Events API v2 (https://developer.pagerduty.com/docs/events-api-v2/).
    # WARN-mode events are sent with `severity=warning` so they don't
    # page on-call by default; DENY uses `severity=error`.
    severity = "error" if ev.decision == "DENY" else "warning"
    return {
        "routing_key": routing_key,
        "event_action": "trigger",
        "dedup_key": f"cepheus-{ev.namespace}-{ev.pod_name}-{ev.uid}",
        "payload": {
            "summary": f"Cepheus admission {ev.decision}: {ev.namespace}/{ev.pod_name}",
            "source": "cepheus-admission",
            "severity": severity,
            "component": "kubernetes-admission",
            "group": ev.namespace,
            "class": "container-escape-prevention",
            "custom_details": {
                "reason": ev.reason,
                "chain_count": ev.chain_count,
                "uid": ev.uid,
                "decision": ev.decision,
            },
        },
    }


def _webhook_payload(ev: AdmissionEvent) -> dict[str, Any]:
    """Generic JSON payload for the operator-supplied webhook channel —
    a flat, stable shape any HTTP sink can consume without knowing the
    Slack/PagerDuty schemas."""
    return {
        "source": "cepheus-admission",
        "decision": ev.decision,
        "namespace": ev.namespace,
        "pod": ev.pod_name,
        "reason": ev.reason,
        "uid": ev.uid,
        "chain_count": ev.chain_count,
    }


def _post_json(url: str, body: dict[str, Any]) -> None:
    """Synchronous POST helper. Caller dispatches on a background thread."""
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(  # noqa: S310 - operator-supplied trusted URL
        url,
        data=data,
        method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "cepheus-admission"},
    )
    try:
        with urllib.request.urlopen(req, timeout=_NOTIFIER_TIMEOUT_SEC) as resp:  # noqa: S310
            # Drain a small chunk so the connection isn't held open;
            # we don't care about the response body itself.
            resp.read(1024)
    except (urllib.error.URLError, OSError) as exc:
        logger.warning("notifier POST to %s failed: %s: %s", _redact(url), type(exc).__name__, exc)
    except Exception as exc:  # noqa: BLE001
        # Catch-all so a notifier bug never escapes onto the admission
        # handler's exception path — that would convert a notifier
        # outage into a webhook outage.
        logger.exception("notifier POST to %s raised unexpectedly: %s", _redact(url), exc)


def _redact(url: str) -> str:
    """Drop the secret-bearing portion of a webhook URL before logging
    so it doesn't end up in cluster logs that aren't scoped to operators.

    Slack incoming-webhook secrets live in the path after ``/services/``.
    For any other operator-supplied URL we can't know which component is
    sensitive, so we log scheme + host only and drop the path and query
    string entirely."""
    if "/services/" in url:
        return url.split("/services/")[0] + "/services/<redacted>"
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return "<unparseable-url>"
    if parts.scheme and parts.netloc:
        return f"{parts.scheme}://{parts.netloc}/<redacted>"
    return "<redacted-url>"


def notify(ev: AdmissionEvent, cfg: NotifierConfig) -> None:
    """Dispatch the event to all configured channels. Returns immediately;
    POSTs happen on background daemon threads.

    Rate-limited via a per-decision token bucket (DENY and WARN are
    independent): when the bucket is empty we log + drop rather than
    queueing, because admission events that can't be delivered promptly
    aren't useful to operators (the pod is already denied/admitted by the
    time the queue drains).
    """
    if not cfg.any_enabled:
        return
    # Charge one token per channel that will actually POST, so the rate
    # limit bounds outbound HTTP volume (not just events) — with Slack,
    # PagerDuty, and the generic webhook all enabled an event costs three.
    channels = int(bool(cfg.slack_webhook_url)) + int(bool(cfg.pagerduty_routing_key)) + int(bool(cfg.webhook_url))
    bucket = _bucket_for(ev.decision)
    if not bucket.try_consume(float(channels)):
        logger.warning(
            "notifier rate limit hit for %s events — dropping event for %s/%s",
            ev.decision,
            ev.namespace,
            ev.pod_name,
        )
        return

    if cfg.slack_webhook_url:
        threading.Thread(
            target=_post_json,
            args=(cfg.slack_webhook_url, _slack_payload(ev)),
            name="cepheus-notify-slack",
            daemon=True,
        ).start()

    if cfg.pagerduty_routing_key:
        threading.Thread(
            target=_post_json,
            args=("https://events.pagerduty.com/v2/enqueue", _pagerduty_payload(ev, cfg.pagerduty_routing_key)),
            name="cepheus-notify-pd",
            daemon=True,
        ).start()

    if cfg.webhook_url:
        threading.Thread(
            target=_post_json,
            args=(cfg.webhook_url, _webhook_payload(ev)),
            name="cepheus-notify-webhook",
            daemon=True,
        ).start()
