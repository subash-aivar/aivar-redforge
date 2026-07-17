"""Application DTOs for Organization Assessment (M24 Phase 2)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime  # noqa: TC003

from redforge.domain.compliance.value_objects import FrameworkKey
from redforge.shared.identifiers import EntityId


@dataclass(frozen=True, slots=True)
class CreateProfileCommand:
    organization_id: str
    name: str
    description: str
    framework_keys: tuple[FrameworkKey, ...]
    created_by: str


@dataclass(frozen=True, slots=True)
class UpdateProfileFrameworksCommand:
    organization_id: str
    profile_id: EntityId
    framework_keys: tuple[FrameworkKey, ...]
    actor_id: str


@dataclass(frozen=True, slots=True)
class ActivateProfileCommand:
    organization_id: str
    profile_id: EntityId
    activated_by: str


@dataclass(frozen=True, slots=True)
class CreatePeriodCommand:
    organization_id: str
    profile_id: EntityId
    name: str
    framework_key: FrameworkKey
    period_start: datetime
    period_end: datetime
    created_by: str


@dataclass(frozen=True, slots=True)
class OpenPeriodCommand:
    organization_id: str
    period_id: EntityId
    opened_by: str


@dataclass(frozen=True, slots=True)
class ClosePeriodCommand:
    organization_id: str
    period_id: EntityId
    closed_by: str


@dataclass(frozen=True, slots=True)
class CreateAssessmentCommand:
    organization_id: str
    period_id: EntityId
    requirement_id: EntityId
    created_by: str
    notes: str = ""


@dataclass(frozen=True, slots=True)
class ConfirmEvidenceLinkCommand:
    organization_id: str
    assessment_id: EntityId
    evidence_id: str
    confirmed_by: str
    rationale: str = ""


@dataclass(frozen=True, slots=True)
class TransitionAssessmentCommand:
    organization_id: str
    assessment_id: EntityId
    actor_id: str
