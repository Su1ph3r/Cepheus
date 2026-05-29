"""Tests for the compliance crosswalk applied at technique-DB build time."""

from __future__ import annotations

from cepheus.engine.technique_db import (
    _COMPLIANCE_CROSSWALK,
    get_all_techniques,
    get_technique_by_id,
)


def test_compliance_crosswalk_keys_reference_real_techniques():
    """Every entry in the crosswalk must reference a known technique id —
    a typo'd id otherwise silently disappears."""
    known_ids = {t.id for t in get_all_techniques()}
    for tid in _COMPLIANCE_CROSSWALK:
        assert tid in known_ids, (
            f"Crosswalk references unknown technique id {tid!r} — "
            f"either the id was renamed in technique_db.py or the "
            f"crosswalk entry has a typo."
        )


def test_compliance_crosswalk_applied_to_docker_socket_mount():
    t = get_technique_by_id("docker_socket_mount")
    assert t is not None
    assert "5.1.5" in t.cis_kubernetes_benchmark
    assert t.nist_800_190
    assert t.pci_dss


def test_techniques_without_mapping_have_empty_lists():
    """Techniques NOT in the crosswalk should expose empty lists,
    not None — guarantees SARIF emission code can safely call `if
    technique.cis_kubernetes_benchmark` without a None check."""
    t = get_technique_by_id("cve_2022_0847")  # not in crosswalk
    assert t is not None
    assert t.cis_kubernetes_benchmark == []
    assert t.nist_800_190 == []
    assert t.pci_dss == []


def test_at_least_a_starter_set_is_populated():
    """Don't let the crosswalk shrink below a meaningful set — if someone
    clears it accidentally during a refactor, this fails."""
    populated = sum(1 for t in get_all_techniques() if t.cis_kubernetes_benchmark)
    assert populated >= 30, (
        f"Only {populated} techniques have CIS mappings; expected >= 30 "
        f"(covers capability/socket/mount/cgroup/device/secret families)."
    )


def test_mount_and_capability_families_are_mapped():
    """The mount, device, cgroup, and capability/eBPF families must all
    carry compliance mappings — kernel CVEs are intentionally exempt, but
    these configuration-level techniques map cleanly to CIS controls."""
    must_be_mapped = [
        "cgroupfs_escape",
        "systemd_cgroup_injection",
        "devfs_access",
        "device_mapper_access",
        "sysfs_hugepages",
        "tmpfs_shm_cross_container",
        "vm_param_manipulation",
        "proc_fd_symlink_traversal",
        "ebpf_probe_write_user",
    ]
    for tid in must_be_mapped:
        t = get_technique_by_id(tid)
        assert t is not None, f"technique {tid!r} not found — id renamed?"
        assert t.cis_kubernetes_benchmark, f"{tid} should carry a CIS mapping"
        assert t.nist_800_190, f"{tid} should carry a NIST mapping"
        assert t.pci_dss, f"{tid} should carry a PCI-DSS mapping"


def test_sarif_emits_compliance_fields_when_populated():
    """SARIF rules must surface the crosswalk so external tooling
    (the web viewer, audit pipelines) can consume the IDs directly.
    Driven through the analyzer with a real k8s-goat fixture that
    triggers techniques known to be in the crosswalk."""
    from pathlib import Path

    from cepheus.config import CepheusConfig
    from cepheus.engine.analyzer import analyze
    from cepheus.models.posture import ContainerPosture
    from cepheus.output.sarif import generate_sarif

    # T1-system-monitor is the K8s Goat scenario with docker.sock
    # mounted — the easiest crosswalk-mapped technique to trigger.
    posture = ContainerPosture.model_validate_json(
        Path("tests/fixtures/k8s-goat/T1-system-monitor-posture.json").read_text(encoding="utf-8")
    )
    result = analyze(posture, CepheusConfig())
    sarif = generate_sarif(result)
    rules = sarif["runs"][0]["tool"]["driver"]["rules"]

    # At least one rule with a crosswalk mapping should have surfaced
    # in the SARIF output. We don't pin which one — the fixture's
    # match set may shift as the technique DB grows.
    rules_with_crosswalk = [r for r in rules if (r.get("properties") or {}).get("cis-kubernetes-benchmark")]
    assert rules_with_crosswalk, (
        "Expected at least one matched rule to carry the cis-kubernetes-benchmark "
        "property — verify the crosswalk is wired through SARIF emission. "
        f"Rule ids in SARIF: {[r['id'] for r in rules]}"
    )
    # And the IDs themselves must round-trip correctly (list of strings).
    sample = rules_with_crosswalk[0]["properties"]["cis-kubernetes-benchmark"]
    assert isinstance(sample, list) and all(isinstance(x, str) for x in sample)


def test_html_report_surfaces_compliance_when_populated():
    """The HTML report advertises the crosswalk as a surface (model
    docstring + CHANGELOG). A populated mapping that never renders is a
    silent regression — guard the table's presence."""
    from pathlib import Path

    from cepheus.config import CepheusConfig
    from cepheus.engine.analyzer import analyze
    from cepheus.models.posture import ContainerPosture
    from cepheus.output.html_report import generate_html

    posture = ContainerPosture.model_validate_json(
        Path("tests/fixtures/k8s-goat/T1-system-monitor-posture.json").read_text(encoding="utf-8")
    )
    result = analyze(posture, CepheusConfig())
    html = generate_html(result)
    assert "Compliance Mapping" in html
    assert "CIS Kubernetes Benchmark" in html
