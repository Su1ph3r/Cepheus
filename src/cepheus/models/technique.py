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
    check_type: str = Field(description="One of: contains, equals, not_equals, gte, lte, kernel_gte, kernel_lte, kernel_between, exists, not_empty, regex")
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
