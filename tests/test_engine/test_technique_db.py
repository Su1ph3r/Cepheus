"""Tests for the technique database."""

from cepheus.engine.technique_db import get_all_techniques, get_technique_by_id
from cepheus.engine.poc_templates import POC_TEMPLATES


def test_technique_count():
    """Database should have exactly 56 techniques."""
    assert len(get_all_techniques()) == 56


def test_no_duplicate_ids():
    """All technique IDs must be unique."""
    ids = [t.id for t in get_all_techniques()]
    assert len(ids) == len(set(ids)), f"Duplicate IDs: {[x for x in ids if ids.count(x) > 1]}"


def test_new_techniques_exist():
    """All v0.2.0 techniques must be present."""
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
