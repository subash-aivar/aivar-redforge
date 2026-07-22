"""SuggestionEvidence and related value objects — C4 / ADR-M36-003."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from autonomous_intelligence.domain.exceptions.domain_exceptions import DomainInvariantViolation
from autonomous_intelligence.domain.value_objects.enums import SuggestionTargetType
from autonomous_intelligence.domain.value_objects.identifiers import TenantId


@dataclass(frozen=True, slots=True, kw_only=True)
class SuggestionEvidence:
    model_id: str
    model_version: int
    confidence_score: float
    supporting_signal_refs: tuple[str, ...]
    rationale_summary: str
    generated_at: datetime

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence_score <= 1.0:
            raise DomainInvariantViolation("confidence_score must be in [0.0, 1.0]")
        if len(self.rationale_summary) > 2000:
            raise DomainInvariantViolation("rationale_summary max 2000 chars")


@dataclass(frozen=True, slots=True, kw_only=True)
class SuggestionTargetRef:
    target_context: str
    target_id: UUID | None
    target_type: SuggestionTargetType
    proposed_change_payload: dict[str, object]


@dataclass(frozen=True, slots=True, kw_only=True)
class SuggestionProposal:
    suggestion_id: str
    tenant_id: str
    target_ref: SuggestionTargetRef
    proposal_payload: dict[str, object]


@dataclass(frozen=True, slots=True, kw_only=True)
class TenantScopedDocument:
    tenant_id: TenantId
    content: str
    source_ref: str


@dataclass(frozen=True, slots=True, kw_only=True)
class LLMPrompt:
    tenant_id: TenantId
    system_instruction: str
    context_documents: tuple[TenantScopedDocument, ...]
    task_instruction: str
    max_tokens: int

    def __post_init__(self) -> None:
        from autonomous_intelligence.domain.exceptions.domain_exceptions import (
            TenantIsolationViolation,
        )

        for doc in self.context_documents:
            if doc.tenant_id.value != self.tenant_id.value:
                raise TenantIsolationViolation("LLMPrompt context document tenant mismatch")


@dataclass(frozen=True, slots=True, kw_only=True)
class LLMResponse:
    content: str
    model_id: str
    prompt_token_count: int
    completion_token_count: int
    latency_ms: int


@dataclass(frozen=True, slots=True, kw_only=True)
class PromptHash:
    value: str


@dataclass(frozen=True, slots=True, kw_only=True)
class SuggestionConfidence:
    score: float
    threshold: float

    @property
    def meets_threshold(self) -> bool:
        return self.score >= self.threshold


DEFAULT_MIN_CONFIDENCE: dict[SuggestionTargetType, float] = {
    SuggestionTargetType.DETECTION_RULE_TUNING: 0.75,
    SuggestionTargetType.CAMPAIGN_SCENARIO: 0.65,
    SuggestionTargetType.PLAYBOOK_SYNTHESIS: 0.70,
    SuggestionTargetType.VULNERABILITY_PRIORITY_ADJUSTMENT: 0.60,
}

CONFIDENCE_FLOORS: dict[SuggestionTargetType, float] = {
    SuggestionTargetType.DETECTION_RULE_TUNING: 0.60,
    SuggestionTargetType.CAMPAIGN_SCENARIO: 0.55,
    SuggestionTargetType.PLAYBOOK_SYNTHESIS: 0.60,
    SuggestionTargetType.VULNERABILITY_PRIORITY_ADJUSTMENT: 0.50,
}

REVIEW_ROLES: dict[SuggestionTargetType, str] = {
    SuggestionTargetType.DETECTION_RULE_TUNING: "soc:detection_engineer",
    SuggestionTargetType.CAMPAIGN_SCENARIO: "red_team:architect",
    SuggestionTargetType.PLAYBOOK_SYNTHESIS: "soc:security_engineer",
    SuggestionTargetType.VULNERABILITY_PRIORITY_ADJUSTMENT: "vuln:manager",
}
