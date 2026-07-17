"""Application DTOs for Evidence Recommendation (M24 Phase 3)."""

from __future__ import annotations

from dataclasses import dataclass

from redforge.shared.identifiers import EntityId


@dataclass(frozen=True, slots=True)
class GenerateRecommendationsCommand:
    organization_id: str
    period_id: EntityId
    generated_by: str
    assessment_id: EntityId | None = None


@dataclass(frozen=True, slots=True)
class AcceptRecommendationCommand:
    organization_id: str
    recommendation_id: EntityId
    accepted_by: str
    rationale: str = ""


@dataclass(frozen=True, slots=True)
class RejectRecommendationCommand:
    organization_id: str
    recommendation_id: EntityId
    rejected_by: str
    rationale: str = ""


@dataclass(frozen=True, slots=True)
class LinkRecommendationCommand:
    organization_id: str
    recommendation_id: EntityId
    linked_by: str
    rationale: str = ""
