from __future__ import annotations

from uuid import UUID

from threat_hunt.domain.aggregates.threat_hunt_candidate import ThreatHuntCandidate
from threat_hunt.domain.value_objects.identifiers import TenantId


class CandidateReviewService:
    def promote(
        self,
        candidate: ThreatHuntCandidate,
        tenant_id: TenantId,
        promoted_by: str,
        roles: tuple[str, ...],
        rule_version_id: UUID,
    ) -> None:
        candidate.promote(tenant_id, promoted_by, roles, rule_version_id)

    def reject(
        self,
        candidate: ThreatHuntCandidate,
        tenant_id: TenantId,
        rejected_by: str,
        reason: str,
        roles: tuple[str, ...],
    ) -> None:
        candidate.reject(tenant_id, rejected_by, reason, roles)
