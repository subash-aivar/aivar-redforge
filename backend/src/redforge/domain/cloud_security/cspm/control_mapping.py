"""CSPMControlMapping — links CSPM policies to M24 catalog controls."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID, uuid4

from redforge.domain.cloud_security.cspm.value_objects import ComplianceRef, CSPMPolicyId


@dataclass
class CSPMControlMapping:
    id: UUID
    policy_id: CSPMPolicyId
    compliance_ref: ComplianceRef
    coverage_weight: float
    created_at: datetime
    updated_at: datetime

    @classmethod
    def create(
        cls,
        *,
        policy_id: CSPMPolicyId,
        compliance_ref: ComplianceRef,
        coverage_weight: float = 1.0,
        now: datetime | None = None,
    ) -> CSPMControlMapping:
        if not (0.0 <= coverage_weight <= 1.0):
            raise ValueError("coverage_weight must be 0.0-1.0")
        ts = now or datetime.now(UTC)
        return cls(
            id=uuid4(),
            policy_id=policy_id,
            compliance_ref=compliance_ref,
            coverage_weight=coverage_weight,
            created_at=ts,
            updated_at=ts,
        )
