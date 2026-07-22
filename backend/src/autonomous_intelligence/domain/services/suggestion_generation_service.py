from __future__ import annotations

from autonomous_intelligence.domain.aggregates.intelligence_suggestion import IntelligenceSuggestion
from autonomous_intelligence.domain.exceptions.domain_exceptions import (
    ConfidenceThresholdNotMet,
    DomainInvariantViolation,
)
from autonomous_intelligence.domain.value_objects.enums import (
    SuggestionPriority,
    SuggestionTargetType,
)
from autonomous_intelligence.domain.value_objects.evidence import (
    SuggestionEvidence,
    SuggestionTargetRef,
)
from autonomous_intelligence.domain.value_objects.identifiers import TenantId


class SuggestionGenerationService:
    def create_if_eligible(
        self,
        tenant_id: TenantId,
        target_ref: SuggestionTargetRef,
        evidence: SuggestionEvidence,
        *,
        min_confidence: float,
        kill_switch_active: bool,
        enabled: bool,
        priority: SuggestionPriority = SuggestionPriority.MEDIUM,
    ) -> IntelligenceSuggestion:
        if kill_switch_active:
            raise DomainInvariantViolation("autonomy kill switch active")
        if not enabled:
            raise DomainInvariantViolation("target type disabled for tenant")
        if evidence.confidence_score < min_confidence:
            raise ConfidenceThresholdNotMet(
                f"{evidence.confidence_score} < {min_confidence} for {target_ref.target_type.value}"
            )
        if target_ref.target_type not in SuggestionTargetType:
            raise DomainInvariantViolation("unknown target type")
        return IntelligenceSuggestion.create(tenant_id, target_ref, evidence, priority=priority)
