"""Escape technique model with prerequisite DSL."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class TechniqueCategory(str, Enum):
    CAPABILITY = "capability"
    MOUNT = "mount"
    KERNEL = "kernel"
    RUNTIME = "runtime"
    COMBINATORIAL = "combinatorial"
    INFO_DISCLOSURE = "info_disclosure"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


SEVERITY_ORDER = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
}


class Prerequisite(BaseModel):
    check_field: str = Field(description="Dot-path into ContainerPosture, e.g. 'capabilities.effective'")
    check_type: str = Field(
        description="One of: contains, any_of, equals, not_equals, gte, lte, kernel_gte, kernel_lte, kernel_between, exists, not_empty, regex, version_lte"
    )
    check_value: Any = Field(default=None, description="Value to check against")
    confidence_if_met: float = Field(default=1.0, ge=0.0, le=1.0)
    confidence_if_absent: float = Field(default=0.3, ge=0.0, le=1.0)
    description: str = ""


class EscapeTechnique(BaseModel):
    id: str
    name: str
    category: TechniqueCategory
    severity: Severity
    description: str
    prerequisites: list[Prerequisite] = Field(default_factory=list)
    mitre_attack: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    cve: str | None = None
    reliability: float = Field(default=0.5, ge=0.0, le=1.0)
    stealth: float = Field(default=0.5, ge=0.0, le=1.0)
    remediation: str = ""
    cli_flag: str | None = Field(
        default=None,
        description=(
            "Container-runtime flag that closes the primitive when set "
            "at create time (e.g. '--cap-drop=SYS_ADMIN', "
            "'--security-opt=no-new-privileges'). When None, the technique "
            "requires a non-flag remediation (e.g. host-level kernel "
            "upgrade, network policy, RBAC change). Used by the remediation "
            "generator in place of regex-mining `remediation` text."
        ),
    )
    verify_command: str | None = Field(
        default=None,
        description=(
            "Shell one-liner that attempts a NON-DESTRUCTIVE proof of "
            "exploit when run inside a matched container. Used by "
            "`cepheus verify`. Exit code 0 = technique confirmed; non-zero "
            "= technique not exploitable in this concrete container. None "
            "means no automated verifier exists (e.g. kernel CVEs where "
            "the only confirmation is actual exploitation)."
        ),
    )
    # Compliance crosswalk: identifiers in popular control frameworks.
    # Populated incrementally — the absence of a mapping means "not
    # yet enumerated", not "no applicable control". Auditors translate
    # finding ids back into the framework they're being measured
    # against; storing the IDs verbatim lets a SARIF consumer (or the
    # web viewer) surface them inline without a lookup table.
    cis_kubernetes_benchmark: list[str] = Field(
        default_factory=list,
        description=(
            "CIS Kubernetes Benchmark control IDs the technique violates or undermines (e.g. ['5.2.1', '5.2.6'])."
        ),
    )
    nist_800_190: list[str] = Field(
        default_factory=list,
        description=(
            "NIST SP 800-190 (Application Container Security Guide) control references (e.g. ['4.1.1', '4.2.4'])."
        ),
    )
    pci_dss: list[str] = Field(
        default_factory=list,
        description=("PCI DSS v4 requirement IDs (e.g. ['2.2.5', '6.4.1'])."),
    )
