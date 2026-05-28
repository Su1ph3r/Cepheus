"""Tests for the technique database."""

import threading
import time

from cepheus.engine import technique_db
from cepheus.engine.technique_db import get_all_techniques, get_technique_by_id
from cepheus.engine.poc_templates import POC_TEMPLATES


def test_technique_count():
    """Database should have exactly 65 techniques."""
    assert len(get_all_techniques()) == 65


def test_concurrent_cold_cache_builds_singleton_once(monkeypatch):
    """Double-checked-locking guard: under concurrent cold-cache access
    (the threaded admission server / fleet ThreadPoolExecutor both call
    get_all_techniques()) the singleton must be built exactly once, not
    once per racing thread."""
    real_build = technique_db._build_techniques
    calls: list[int] = []
    calls_lock = threading.Lock()

    def counting_build() -> list:
        with calls_lock:
            calls.append(1)
        time.sleep(0.02)  # widen the race window so an unlocked build would double-fire
        return real_build()

    monkeypatch.setattr(technique_db, "_TECHNIQUES", None)
    monkeypatch.setattr(technique_db, "_build_techniques", counting_build)

    results: list[list] = []
    barrier = threading.Barrier(16)

    def worker() -> None:
        barrier.wait()
        results.append(get_all_techniques())

    threads = [threading.Thread(target=worker) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(calls) == 1, f"_build_techniques ran {len(calls)} times under contention, expected 1"
    assert all(len(r) == 65 for r in results)


def test_no_duplicate_ids():
    """All technique IDs must be unique."""
    ids = [t.id for t in get_all_techniques()]
    assert len(ids) == len(set(ids)), f"Duplicate IDs: {[x for x in ids if ids.count(x) > 1]}"


def test_new_techniques_exist():
    """All v0.2.0 and v0.3.0 techniques must be present."""
    new_ids = [
        "systemd_cgroup_injection",
        "tmpfs_shm_cross_container",
        "lsm_apparmor_unconfined",
        "lsm_selinux_unconfined",
        "ebpf_probe_write_user",
        "cve_2024_53104",
        "cve_2025_21756",
        "containerd_sock_mount",
        "crio_sock_mount",
        "proc_fd_symlink_traversal",
        "device_mapper_access",
        "vm_param_manipulation",
        "cve_2025_31133",
        "cve_2025_52565",
        "cve_2025_52881",
        "cve_2024_23651",
        "cve_2024_23652",
        "cve_2025_23266",
        "cve_2024_0132",
        "cve_2025_1974",
        "cve_2025_9074",
    ]
    for tid in new_ids:
        assert get_technique_by_id(tid) is not None, f"Technique {tid} not found"


def test_all_techniques_have_poc_templates():
    """Every technique must have a PoC template."""
    missing = [t.id for t in get_all_techniques() if t.id not in POC_TEMPLATES]
    assert not missing, f"Missing PoC templates: {missing}"


def test_all_techniques_have_mitre_attack():
    """Every technique should have at least one MITRE ATT&CK ID."""
    for t in get_all_techniques():
        assert len(t.mitre_attack) > 0, f"Technique {t.id} has no MITRE ATT&CK mapping"


def test_all_techniques_have_remediation():
    """Every technique should have remediation text."""
    for t in get_all_techniques():
        assert t.remediation, f"Technique {t.id} has no remediation"


def test_cve_2024_21626_has_runc_version_prereq():
    """CVE-2024-21626 should check runc version."""
    t = get_technique_by_id("cve_2024_21626")
    assert t is not None
    runc_prereqs = [p for p in t.prerequisites if p.check_field == "runtime.runc_version"]
    assert len(runc_prereqs) == 1
    assert runc_prereqs[0].check_type == "version_lte"


def test_get_all_techniques_returns_isolated_objects():
    """Regression guard for S1: pre-0.3.5 `get_all_techniques` returned
    `list(_TECHNIQUES)` — a shallow copy where the inner Pydantic models
    were SHARED across callers. A caller mutating one technique silently
    corrupted the global database for every subsequent caller in the
    process. The deepcopy fix isolates each call."""
    from cepheus.models.technique import Severity

    first_call = get_all_techniques()
    original_severity = first_call[0].severity

    # Mutate a returned technique — this would poison the singleton before the fix.
    first_call[0].severity = Severity.LOW

    # A second call must NOT see the mutation.
    second_call = get_all_techniques()
    assert second_call[0].severity == original_severity, (
        "get_all_techniques must return isolated objects — mutating one "
        "caller's result must not leak into other callers' results"
    )


def test_get_all_techniques_inner_lists_isolated():
    """Same isolation property for nested lists (`prerequisites`,
    `references`, `mitre_attack`) — shallow-copy would have shared
    these too, even if the outer EscapeTechnique objects were distinct."""
    first_call = get_all_techniques()
    first_call[0].references.append("https://attacker.example/poison")
    second_call = get_all_techniques()
    assert "https://attacker.example/poison" not in second_call[0].references
