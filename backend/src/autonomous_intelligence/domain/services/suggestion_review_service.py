from __future__ import annotations

from autonomous_intelligence.domain.aggregates.intelligence_suggestion import IntelligenceSuggestion
from autonomous_intelligence.domain.value_objects.identifiers import TenantId


class SuggestionReviewService:
    def approve(
        self,
        suggestion: IntelligenceSuggestion,
        tenant_id: TenantId,
        approved_by: str,
        roles: tuple[str, ...],
    ) -> None:
        suggestion.approve(tenant_id, approved_by, roles)

    def reject(
        self,
        suggestion: IntelligenceSuggestion,
        tenant_id: TenantId,
        rejected_by: str,
        reason: str,
        roles: tuple[str, ...],
    ) -> None:
        suggestion.reject(tenant_id, rejected_by, reason, roles)
