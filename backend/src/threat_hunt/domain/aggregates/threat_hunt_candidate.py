from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from threat_hunt.domain.events.hunt_events import (
    ThreatHuntCandidateGenerated,
    ThreatHuntCandidatePromoted,
    ThreatHuntCandidateRejected,
)
from threat_hunt.domain.exceptions.domain_exceptions import (
    AuthorizationDenied,
    DomainInvariantViolation,
    InvalidCandidateTransition,
    TenantMismatch,
)
from threat_hunt.domain.value_objects.enums import DetectionRuleFormat, ThreatHuntCandidateStatus
from threat_hunt.domain.value_objects.identifiers import (
    AnomalySignalRef,
    AttckTechniqueRef,
    CandidateId,
    TenantId,
)


class ThreatHuntCandidate:
    __slots__ = (
        "_pending_events",
        "anomaly_signal_refs",
        "candidate_id",
        "candidate_status",
        "confidence_score",
        "detection_logic_draft",
        "detection_rule_format",
        "generated_at",
        "promoted_rule_version_id",
        "review_notes",
        "reviewed_at",
        "reviewed_by",
        "technique_coverage",
        "tenant_id",
    )

    def __init__(
        self,
        candidate_id: CandidateId,
        tenant_id: TenantId,
        anomaly_signal_refs: tuple[AnomalySignalRef, ...],
        technique_coverage: tuple[AttckTechniqueRef, ...],
        detection_logic_draft: str,
        detection_rule_format: DetectionRuleFormat,
        confidence_score: float,
        candidate_status: ThreatHuntCandidateStatus,
        generated_at: datetime,
        *,
        promoted_rule_version_id: UUID | None = None,
        review_notes: str | None = None,
        reviewed_at: datetime | None = None,
        reviewed_by: str | None = None,
    ) -> None:
        self.candidate_id = candidate_id
        self.tenant_id = tenant_id
        self.anomaly_signal_refs = anomaly_signal_refs
        self.technique_coverage = technique_coverage
        self.detection_logic_draft = detection_logic_draft
        self.detection_rule_format = detection_rule_format
        self.confidence_score = confidence_score
        self.candidate_status = candidate_status
        self.generated_at = generated_at
        self.promoted_rule_version_id = promoted_rule_version_id
        self.review_notes = review_notes
        self.reviewed_at = reviewed_at
        self.reviewed_by = reviewed_by
        self._pending_events: list[Any] = []

    def pop_events(self) -> list[Any]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    @classmethod
    def create(
        cls,
        tenant_id: TenantId,
        anomaly_signal_refs: tuple[AnomalySignalRef, ...],
        technique_coverage: tuple[AttckTechniqueRef, ...],
        detection_logic_draft: str,
        detection_rule_format: DetectionRuleFormat,
        confidence_score: float,
    ) -> ThreatHuntCandidate:
        if not anomaly_signal_refs:
            raise DomainInvariantViolation("anomaly_signal_refs required")
        now = datetime.now(UTC)
        candidate = cls(
            CandidateId.generate(),
            tenant_id,
            anomaly_signal_refs,
            technique_coverage,
            detection_logic_draft,
            detection_rule_format,
            confidence_score,
            ThreatHuntCandidateStatus.CANDIDATE,
            now,
        )
        candidate._pending_events.append(
            ThreatHuntCandidateGenerated(
                tenant_id=str(tenant_id),
                aggregate_id=str(candidate.candidate_id),
                candidate_id=str(candidate.candidate_id),
                technique_coverage=tuple(t.technique_id for t in technique_coverage),
                confidence_score=confidence_score,
            )
        )
        return candidate

    def promote(
        self,
        tenant_id: TenantId,
        promoted_by: str,
        roles: tuple[str, ...],
        promoted_rule_version_id: UUID,
    ) -> None:
        if self.tenant_id != tenant_id:
            raise TenantMismatch("tenant mismatch")
        if "soc:detection_engineer" not in roles:
            raise AuthorizationDenied("requires soc:detection_engineer")
        if not promoted_by:
            raise DomainInvariantViolation("reviewed_by required for promotion")
        if self.candidate_status not in {
            ThreatHuntCandidateStatus.CANDIDATE,
            ThreatHuntCandidateStatus.UNDER_REVIEW,
            ThreatHuntCandidateStatus.ACCEPTED,
        }:
            raise InvalidCandidateTransition(self.candidate_status.value)
        now = datetime.now(UTC)
        self.candidate_status = ThreatHuntCandidateStatus.PROMOTED
        self.promoted_rule_version_id = promoted_rule_version_id
        self.reviewed_by = promoted_by
        self.reviewed_at = now
        self._pending_events.append(
            ThreatHuntCandidatePromoted(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.candidate_id),
                candidate_id=str(self.candidate_id),
                promoted_rule_version_id=str(promoted_rule_version_id),
                promoted_by=promoted_by,
            )
        )

    def reject(
        self, tenant_id: TenantId, rejected_by: str, reason: str, roles: tuple[str, ...]
    ) -> None:
        if self.tenant_id != tenant_id:
            raise TenantMismatch("tenant mismatch")
        if "soc:detection_engineer" not in roles:
            raise AuthorizationDenied("requires soc:detection_engineer")
        self.candidate_status = ThreatHuntCandidateStatus.REJECTED
        self.reviewed_by = rejected_by
        self.reviewed_at = datetime.now(UTC)
        self.review_notes = reason
        self._pending_events.append(
            ThreatHuntCandidateRejected(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.candidate_id),
                candidate_id=str(self.candidate_id),
                rejected_by=rejected_by,
                rejection_reason=reason,
            )
        )
