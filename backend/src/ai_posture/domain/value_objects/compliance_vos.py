"""Compliance value objects — Phase 5."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from ai_posture.domain.value_objects.enums import (
    ComplianceFrameworkId,
)


@dataclass(frozen=True, slots=True)
class AIComplianceFrameworkRef:
    framework_id: ComplianceFrameworkId
    control_id: str
    control_title: str


@dataclass(frozen=True, slots=True)
class ApplicableControl:
    framework_ref: AIComplianceFrameworkRef
    requires_human_attestation: bool


@dataclass(frozen=True, slots=True)
class HumanAttestation:
    attestor_id: str
    attested_at: datetime
    notes: str = ""


@dataclass(frozen=True, slots=True)
class ControlEvidenceSnapshot:
    """Evidence facts available at evaluation time (ACL-resolved)."""

    has_threat_profile: bool
    threat_max_exposure: str | None
    provenance_integrity_status: str | None
    has_active_envelope: bool
    open_compliance_gaps: int = 0
