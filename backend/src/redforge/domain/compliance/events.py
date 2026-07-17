"""Domain events for the Compliance bounded context."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from redforge.domain.compliance.value_objects import (  # noqa: TC001
    FrameworkKey,
    MappingConfidenceHint,
)


@dataclass(frozen=True, slots=True)
class FrameworkPublished:
    """Emitted when a FrameworkDefinition transitions to PUBLISHED."""

    framework_key: FrameworkKey
    framework_name: str
    version: str
    published_by: str  # platform user_id
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True, slots=True)
class FrameworkRetired:
    """Emitted when a FrameworkDefinition transitions to RETIRED."""

    framework_key: FrameworkKey
    framework_name: str
    reason: str
    retired_by: str  # platform user_id
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True, slots=True)
class ControlMappingDefined:
    """Emitted when a new cross-framework ControlMapping is created."""

    mapping_id: str
    source_requirement_id: str
    target_requirement_id: str
    source_framework_key: FrameworkKey
    target_framework_key: FrameworkKey
    confidence: MappingConfidenceHint
    defined_by: str  # platform user_id
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True, slots=True)
class ControlMappingRevoked:
    """Emitted when an active ControlMapping is deactivated."""

    mapping_id: str
    source_requirement_id: str
    target_requirement_id: str
    reason: str
    revoked_by: str  # platform user_id
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))


# ─── M24 Phase 2 — Organization Assessment events ─────────────────────────────


@dataclass(frozen=True, slots=True)
class ComplianceProfileCreated:
    profile_id: str
    organization_id: str
    name: str
    framework_keys: tuple[str, ...]
    created_by: str
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True, slots=True)
class ComplianceProfileActivated:
    profile_id: str
    organization_id: str
    activated_by: str
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True, slots=True)
class AssessmentPeriodOpened:
    period_id: str
    organization_id: str
    profile_id: str
    framework_key: FrameworkKey
    opened_by: str
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True, slots=True)
class AssessmentPeriodClosed:
    period_id: str
    organization_id: str
    profile_id: str
    closed_by: str
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True, slots=True)
class ControlAssessmentCreated:
    assessment_id: str
    organization_id: str
    period_id: str
    requirement_id: str
    framework_key: FrameworkKey
    created_by: str
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True, slots=True)
class ControlEvidenceLinkConfirmed:
    assessment_id: str
    organization_id: str
    evidence_id: str
    confirmed_by: str
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True, slots=True)
class ControlStatusChanged:
    assessment_id: str
    organization_id: str
    previous_status: str
    new_status: str
    changed_by: str
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))


# ─── M24 Phase 3 — Evidence Recommendation events ─────────────────────────────


@dataclass(frozen=True, slots=True)
class RecommendationGenerated:
    recommendation_id: str
    organization_id: str
    batch_id: str
    assessment_id: str
    period_id: str
    requirement_id: str
    source_kind: str
    source_entity_id: str
    confidence: str
    score: float
    generated_by: str
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True, slots=True)
class RecommendationAccepted:
    recommendation_id: str
    organization_id: str
    assessment_id: str
    accepted_by: str
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True, slots=True)
class RecommendationRejected:
    recommendation_id: str
    organization_id: str
    assessment_id: str
    rejected_by: str
    rationale: str
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True, slots=True)
class RecommendationLinked:
    recommendation_id: str
    organization_id: str
    assessment_id: str
    evidence_id: str
    linked_by: str
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))


@dataclass(frozen=True, slots=True)
class RecommendationConfidenceChanged:
    recommendation_id: str
    organization_id: str
    previous_confidence: str
    new_confidence: str
    score: float
    changed_by: str
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))
