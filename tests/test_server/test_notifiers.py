"""Tests for cepheus.server.notifiers — outbound notification dispatch."""

from __future__ import annotations

import threading
import time

from cepheus.server.notifiers import (
    AdmissionEvent,
    NotifierConfig,
    _pagerduty_payload,
    _redact,
    _slack_payload,
    _TokenBucket,
    notify,
)


def _ev(decision: str = "DENY") -> AdmissionEvent:
    return AdmissionEvent(
        decision=decision,
        namespace="prod",
        pod_name="api-7c4f",
        reason="Cepheus admission gate (severity=critical) blocked: 2 chain(s) at severity >= critical",
        uid="abc-123",
        chain_count=2,
    )


def test_notifier_config_disabled_by_default():
    cfg = NotifierConfig()
    assert cfg.any_enabled is False


def test_notifier_config_enabled_when_either_set():
    assert NotifierConfig(slack_webhook_url="https://hooks.slack.com/X").any_enabled is True
    assert NotifierConfig(pagerduty_routing_key="key").any_enabled is True


def test_slack_payload_includes_decision_namespace_and_reason():
    body = _slack_payload(_ev())
    text = body["text"]
    assert "DENY" in text
    assert "prod" in text
    assert "api-7c4f" in text
    assert "admission gate" in text


def test_pagerduty_payload_deny_uses_error_severity():
    body = _pagerduty_payload(_ev("DENY"), "rk-123")
    assert body["routing_key"] == "rk-123"
    assert body["event_action"] == "trigger"
    assert body["payload"]["severity"] == "error"
    assert "prod" in body["payload"]["summary"]
    assert body["payload"]["custom_details"]["decision"] == "DENY"


def test_pagerduty_payload_warn_uses_warning_severity():
    body = _pagerduty_payload(_ev("WARN"), "rk-123")
    assert body["payload"]["severity"] == "warning"


def test_token_bucket_allows_initial_burst_then_throttles():
    b = _TokenBucket(max_tokens=3, refill_per_sec=1.0)
    # Three immediate consumes succeed.
    assert b.try_consume() is True
    assert b.try_consume() is True
    assert b.try_consume() is True
    # Fourth one (with no refill window elapsed) fails.
    assert b.try_consume() is False


def test_redact_strips_slack_secret_path():
    url = "https://hooks.slack.com/services/T000/B000/abc-secret"
    assert "abc-secret" not in _redact(url)
    assert _redact(url).endswith("<redacted>")


def test_notify_dispatches_on_background_thread(monkeypatch):
    """notify() must return immediately and POST on a daemon thread."""
    calls: list[tuple[str, dict]] = []

    def _fake_post(url, body):
        # Add a deliberate delay so we can prove the main thread didn't block.
        time.sleep(0.05)
        calls.append((url, body))

    monkeypatch.setattr("cepheus.server.notifiers._post_json", _fake_post)
    # Reset the global rate bucket so prior tests' consumption doesn't
    # cause this dispatch to be dropped.
    monkeypatch.setattr(
        "cepheus.server.notifiers._GLOBAL_BUCKET",
        _TokenBucket(max_tokens=10, refill_per_sec=10),
    )

    cfg = NotifierConfig(
        slack_webhook_url="https://hooks.slack.com/services/x/y/z",
        pagerduty_routing_key="k",
    )
    t0 = time.perf_counter()
    notify(_ev(), cfg)
    elapsed_ms = (time.perf_counter() - t0) * 1000

    # Main thread returned quickly (<10ms even with the daemon-thread setup
    # cost); the fake post sleeps 50ms so this proves async dispatch.
    assert elapsed_ms < 30

    # Give background threads time to finish.
    for t in threading.enumerate():
        if t.name.startswith("cepheus-notify-"):
            t.join(timeout=1.0)

    urls = {url for url, _ in calls}
    assert "https://hooks.slack.com/services/x/y/z" in urls
    assert "https://events.pagerduty.com/v2/enqueue" in urls


def test_notify_drops_when_rate_limited(monkeypatch):
    """When the bucket is empty, notify() must log + drop without
    spawning threads. Verified by ensuring _post_json is never called."""
    calls = []

    def _fake_post(url, body):
        calls.append(url)

    monkeypatch.setattr("cepheus.server.notifiers._post_json", _fake_post)
    monkeypatch.setattr(
        "cepheus.server.notifiers._GLOBAL_BUCKET",
        _TokenBucket(max_tokens=0, refill_per_sec=0),  # Permanently empty
    )

    cfg = NotifierConfig(slack_webhook_url="https://hooks.slack.com/services/a/b/c")
    notify(_ev(), cfg)

    # Brief settle period — nothing should be enqueued.
    time.sleep(0.05)
    assert calls == []
