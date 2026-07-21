"""EradicationVerification — two-role attestation (ADR-M34-006)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from incident.domain.events.incident_events import (
    EradicationVerificationDisputed,
    EradicationVerificationSubmitted,
    EradicationVerificationVerified,
    EradicationVerified,
)
from incident.domain.exceptions.domain_exceptions import (
    DomainInvariantViolation,
    InvalidPhaseTransition,
    TenantMismatch,
)
from incident.domain.value_objects.enums import EradicationVerificationStatus
from incident.domain.value_objects.identifiers import (
    EradicationVerificationId,
    IncidentId,
    TenantId,
)
from incident.domain.value_objects.refs import EradicationEvidenceRef


class EradicationVerification:
    __slots__ = (
        "_pending_events",
        "assertion",
        "dispute_reason",
        "evidence_refs",
        "incident_id",
        "status",
        "submitted_at",
        "submitted_by",
        "tenant_id",
        "verification_id",
        "verified_at",
        "verified_by",
    )

    def __init__(
        self,
        verification_id: EradicationVerificationId,
        tenant_id: TenantId,
        incident_id: IncidentId,
        assertion: str,
        evidence_refs: list[EradicationEvidenceRef],
        status: EradicationVerificationStatus,
        *,
        submitted_by: str | None = None,
        submitted_at: datetime | None = None,
        verified_by: str | None = None,
        verified_at: datetime | None = None,
        dispute_reason: str | None = None,
    ) -> None:
        self.verification_id = verification_id
        self.tenant_id = tenant_id
        self.incident_id = incident_id
        self.assertion = assertion
        self.evidence_refs = list(evidence_refs)
        self.status = status
        self.submitted_by = submitted_by
        self.submitted_at = submitted_at
        self.verified_by = verified_by
        self.verified_at = verified_at
        self.dispute_reason = dispute_reason
        self._pending_events: list[Any] = []

    def pop_events(self) -> list[Any]:
        ev = list(self._pending_events)
        self._pending_events.clear()
        return ev

    def _emit(self, e: Any) -> None:
        self._pending_events.append(e)

    @classmethod
    def submit(
        cls,
        verification_id: EradicationVerificationId,
        tenant_id: TenantId,
        incident_id: IncidentId,
        assertion: str,
        evidence_refs: list[EradicationEvidenceRef],
        submitted_by: str,
        at: datetime,
    ) -> EradicationVerification:
        if not evidence_refs:
            raise DomainInvariantViolation("at least one EradicationEvidenceRef required")
        v = cls(
            verification_id,
            tenant_id,
            incident_id,
            assertion,
            evidence_refs,
            EradicationVerificationStatus.SUBMITTED,
            submitted_by=submitted_by,
            submitted_at=at,
        )
        v._emit(
            EradicationVerificationSubmitted(
                tenant_id=str(tenant_id),
                aggregate_id=str(verification_id),
                verification_id=str(verification_id),
                incident_id=str(incident_id),
                submitted_by=submitted_by,
                submitted_at=at.isoformat(),
            )
        )
        return v

    def verify(self, tenant_id: TenantId, verified_by: str, at: datetime) -> None:
        if self.tenant_id.value != tenant_id.value:
            raise TenantMismatch()
        if self.status != EradicationVerificationStatus.SUBMITTED:
            raise InvalidPhaseTransition("verify only from SUBMITTED")
        if self.submitted_by == verified_by:
            raise DomainInvariantViolation("submitted_by must differ from verified_by")
        self.status = EradicationVerificationStatus.VERIFIED
        self.verified_by = verified_by
        self.verified_at = at
        self._emit(
            EradicationVerificationVerified(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.verification_id),
                verification_id=str(self.verification_id),
                incident_id=str(self.incident_id),
                verified_by=verified_by,
                verified_at=at.isoformat(),
            )
        )
        self._emit(
            EradicationVerified(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.verification_id),
                verification_id=str(self.verification_id),
                incident_id=str(self.incident_id),
            )
        )

    def dispute(self, tenant_id: TenantId, reason: str, at: datetime) -> None:
        del at
        if self.tenant_id.value != tenant_id.value:
            raise TenantMismatch()
        if self.status != EradicationVerificationStatus.SUBMITTED:
            raise InvalidPhaseTransition("dispute only from SUBMITTED")
        if not reason.strip():
            raise DomainInvariantViolation("dispute_reason required")
        self.status = EradicationVerificationStatus.DISPUTED
        self.dispute_reason = reason
        self._emit(
            EradicationVerificationDisputed(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.verification_id),
                verification_id=str(self.verification_id),
                incident_id=str(self.incident_id),
                dispute_reason=reason,
            )
        )
