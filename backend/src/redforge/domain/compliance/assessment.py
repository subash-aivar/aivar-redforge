"""Organization Assessment domain — M24 Phase 2.

Aggregates:
  ComplianceProfile   — tenant selection of catalog frameworks
  AssessmentPeriod    — time-bounded assessment window under a profile
  ControlAssessment   — per-requirement assessment with confirmed evidence links

Boundaries:
  - Reference IDs only for ControlRequirement and Evidence
  - Never owns Findings or Threat Intelligence
  - Never returns or stores CERTIFIED / COMPLIANT
"""

from __future__ import annotations

from collections.abc import Sequence  # noqa: TC003
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from redforge.domain.compliance.events import (
    AssessmentPeriodClosed,
    AssessmentPeriodOpened,
    ComplianceProfileActivated,
    ComplianceProfileCreated,
    ControlAssessmentCreated,
    ControlEvidenceLinkConfirmed,
    ControlStatusChanged,
)
from redforge.domain.compliance.exceptions import (
    AssessmentPeriodCloseBlockedError,
    AssessmentPeriodNotOpenError,
    ControlAssessmentInvariantError,
    DuplicateActiveProfileFrameworkError,
    DuplicateEvidenceLinkError,
    InvalidControlStatusTransitionError,
    ProfileNotActiveError,
)
from redforge.domain.compliance.services import ControlStatusEvaluator
from redforge.domain.compliance.value_objects import (
    AssessmentPeriodStatus,
    ConfirmedEvidenceLink,
    ControlStatus,
    ControlStatusCode,
    FrameworkKey,
    ProfileStatus,
)
from redforge.shared.identifiers import EntityId

_FORBIDDEN_LABELS = frozenset({"CERTIFIED", "COMPLIANT"})


def _assert_no_forbidden_label(label: str) -> None:
    if label.upper() in _FORBIDDEN_LABELS:
        raise ControlAssessmentInvariantError(
            f"Forbidden compliance label '{label}' is not permitted"
        )


# ─── ComplianceProfile ────────────────────────────────────────────────────────


@dataclass
class ComplianceProfile:
    """Organization-scoped compliance program configuration.

    Selects published catalog frameworks by key reference only.  Does not
    embed FrameworkDefinition or ControlRequirement aggregates.

    Invariant: at most one *active* profile may claim any given
    (organization_id, framework_key) pair across the organization.
    """

    id: EntityId
    organization_id: str
    name: str
    description: str
    framework_keys: tuple[FrameworkKey, ...]
    status: ProfileStatus
    created_by: str
    created_at: datetime
    updated_at: datetime
    _pending_events: list[object] = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        _assert_no_forbidden_label(self.name)
        if not self.organization_id.strip():
            raise ControlAssessmentInvariantError("organization_id is required")
        if not self.name.strip():
            raise ControlAssessmentInvariantError("profile name is required")
        if len(self.name) > 200:
            raise ControlAssessmentInvariantError("profile name exceeds 200 characters")
        if len(self.description) > 4000:
            raise ControlAssessmentInvariantError(
                "profile description exceeds 4000 characters"
            )
        if len(set(self.framework_keys)) != len(self.framework_keys):
            raise ControlAssessmentInvariantError(
                "framework_keys must not contain duplicates"
            )

    @classmethod
    def create(
        cls,
        *,
        organization_id: str,
        name: str,
        description: str = "",
        framework_keys: tuple[FrameworkKey, ...] = (),
        created_by: str,
    ) -> ComplianceProfile:
        now = datetime.now(UTC)
        profile = cls(
            id=EntityId.generate(),
            organization_id=organization_id,
            name=name.strip(),
            description=description.strip(),
            framework_keys=framework_keys,
            status=ProfileStatus.DRAFT,
            created_by=created_by,
            created_at=now,
            updated_at=now,
        )
        profile._emit(
            ComplianceProfileCreated(
                profile_id=str(profile.id),
                organization_id=organization_id,
                name=profile.name,
                framework_keys=tuple(k.value for k in framework_keys),
                created_by=created_by,
            )
        )
        return profile

    @classmethod
    def reconstitute(cls, data: dict[str, Any]) -> ComplianceProfile:
        return cls(
            id=EntityId.from_string(data["id"]),
            organization_id=data["organization_id"],
            name=data["name"],
            description=data["description"],
            framework_keys=tuple(FrameworkKey(k) for k in data["framework_keys"]),
            status=ProfileStatus(data["status"]),
            created_by=data["created_by"],
            created_at=data["created_at"],
            updated_at=data["updated_at"],
        )

    def activate(
        self,
        *,
        activated_by: str,
        other_active_profiles: Sequence[ComplianceProfile] = (),
    ) -> None:
        """Activate this profile.

        ``other_active_profiles`` must include every *other* currently active
        profile in the same organization.  Activation is rejected when any
        framework_key overlaps an already-active profile.
        """
        if self.status == ProfileStatus.ARCHIVED:
            raise ProfileNotActiveError(str(self.id), "archived profiles cannot activate")
        if self.status == ProfileStatus.ACTIVE:
            return
        if not self.framework_keys:
            raise ControlAssessmentInvariantError(
                "Cannot activate a profile with no framework_keys"
            )
        self._assert_no_active_framework_overlap(other_active_profiles)
        self.status = ProfileStatus.ACTIVE
        self.updated_at = datetime.now(UTC)
        self._emit(
            ComplianceProfileActivated(
                profile_id=str(self.id),
                organization_id=self.organization_id,
                activated_by=activated_by,
            )
        )

    def archive(self) -> None:
        if self.status == ProfileStatus.ARCHIVED:
            return
        self.status = ProfileStatus.ARCHIVED
        self.updated_at = datetime.now(UTC)

    def replace_framework_keys(
        self,
        keys: tuple[FrameworkKey, ...],
        *,
        other_active_profiles: Sequence[ComplianceProfile] = (),
    ) -> None:
        if self.status == ProfileStatus.ARCHIVED:
            raise ProfileNotActiveError(str(self.id), "archived profile is immutable")
        if len(set(keys)) != len(keys):
            raise ControlAssessmentInvariantError(
                "framework_keys must not contain duplicates"
            )
        previous = self.framework_keys
        self.framework_keys = keys
        if self.status == ProfileStatus.ACTIVE:
            try:
                self._assert_no_active_framework_overlap(other_active_profiles)
            except DuplicateActiveProfileFrameworkError:
                self.framework_keys = previous
                raise
        self.updated_at = datetime.now(UTC)

    def assert_active(self) -> None:
        if self.status != ProfileStatus.ACTIVE:
            raise ProfileNotActiveError(str(self.id), f"status is '{self.status}'")

    def _assert_no_active_framework_overlap(
        self, other_active_profiles: Sequence[ComplianceProfile]
    ) -> None:
        mine = set(self.framework_keys)
        for other in other_active_profiles:
            if other.id == self.id:
                continue
            if other.status != ProfileStatus.ACTIVE:
                continue
            overlap = mine & set(other.framework_keys)
            if overlap:
                key = next(iter(overlap))
                raise DuplicateActiveProfileFrameworkError(
                    self.organization_id,
                    key.value,
                    str(other.id),
                )

    def collect_events(self) -> list[object]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: object) -> None:
        self._pending_events.append(event)


# ─── AssessmentPeriod ─────────────────────────────────────────────────────────


@dataclass
class AssessmentPeriod:
    """Time-bounded assessment window owned by a ComplianceProfile reference."""

    id: EntityId
    organization_id: str
    profile_id: EntityId
    name: str
    framework_key: FrameworkKey
    period_start: datetime
    period_end: datetime
    status: AssessmentPeriodStatus
    created_by: str
    created_at: datetime
    updated_at: datetime
    _pending_events: list[object] = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        _assert_no_forbidden_label(self.name)
        if not self.name.strip():
            raise ControlAssessmentInvariantError("period name is required")
        if self.period_end <= self.period_start:
            raise ControlAssessmentInvariantError(
                "period_end must be after period_start"
            )

    @classmethod
    def create(
        cls,
        *,
        organization_id: str,
        profile_id: EntityId,
        name: str,
        framework_key: FrameworkKey,
        period_start: datetime,
        period_end: datetime,
        created_by: str,
    ) -> AssessmentPeriod:
        now = datetime.now(UTC)
        return cls(
            id=EntityId.generate(),
            organization_id=organization_id,
            profile_id=profile_id,
            name=name.strip(),
            framework_key=framework_key,
            period_start=period_start,
            period_end=period_end,
            status=AssessmentPeriodStatus.PLANNED,
            created_by=created_by,
            created_at=now,
            updated_at=now,
        )

    @classmethod
    def reconstitute(cls, data: dict[str, Any]) -> AssessmentPeriod:
        return cls(
            id=EntityId.from_string(data["id"]),
            organization_id=data["organization_id"],
            profile_id=EntityId.from_string(data["profile_id"]),
            name=data["name"],
            framework_key=FrameworkKey(data["framework_key"]),
            period_start=data["period_start"],
            period_end=data["period_end"],
            status=AssessmentPeriodStatus(data["status"]),
            created_by=data["created_by"],
            created_at=data["created_at"],
            updated_at=data["updated_at"],
        )

    def open(self, *, opened_by: str) -> None:
        if self.status == AssessmentPeriodStatus.CLOSED:
            raise AssessmentPeriodNotOpenError(
                str(self.id), "closed periods cannot be reopened"
            )
        if self.status == AssessmentPeriodStatus.OPEN:
            return
        self.status = AssessmentPeriodStatus.OPEN
        self.updated_at = datetime.now(UTC)
        self._emit(
            AssessmentPeriodOpened(
                period_id=str(self.id),
                organization_id=self.organization_id,
                profile_id=str(self.profile_id),
                framework_key=self.framework_key,
                opened_by=opened_by,
            )
        )

    def close(
        self,
        *,
        closed_by: str,
        assessments: Sequence[ControlAssessment],
    ) -> None:
        """Close the period only when every ControlAssessment is technically_validated.

        An empty assessment set is vacuously complete and may close.
        """
        if self.status == AssessmentPeriodStatus.CLOSED:
            return
        if self.status != AssessmentPeriodStatus.OPEN:
            raise AssessmentPeriodNotOpenError(
                str(self.id), "only open periods can be closed"
            )
        incomplete = tuple(
            str(a.id)
            for a in assessments
            if a.status.value != ControlStatusCode.TECHNICALLY_VALIDATED
        )
        if incomplete:
            raise AssessmentPeriodCloseBlockedError(str(self.id), incomplete)
        self.status = AssessmentPeriodStatus.CLOSED
        self.updated_at = datetime.now(UTC)
        self._emit(
            AssessmentPeriodClosed(
                period_id=str(self.id),
                organization_id=self.organization_id,
                profile_id=str(self.profile_id),
                closed_by=closed_by,
            )
        )

    def assert_open(self) -> None:
        if self.status != AssessmentPeriodStatus.OPEN:
            raise AssessmentPeriodNotOpenError(
                str(self.id), f"status is '{self.status}'"
            )

    def collect_events(self) -> list[object]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: object) -> None:
        self._pending_events.append(event)


# ─── ControlAssessment ────────────────────────────────────────────────────────


@dataclass
class ControlAssessment:
    """Per-requirement assessment within an open AssessmentPeriod.

    Owns ConfirmedEvidenceLink value objects.  References requirement_id and
    evidence_id only — never Findings or threat-intel aggregates.
    """

    id: EntityId
    organization_id: str
    profile_id: EntityId
    period_id: EntityId
    requirement_id: EntityId
    framework_key: FrameworkKey
    status: ControlStatus
    evidence_links: list[ConfirmedEvidenceLink]
    notes: str
    created_by: str
    created_at: datetime
    updated_at: datetime
    _pending_events: list[object] = field(default_factory=list, repr=False)
    _evaluator: ControlStatusEvaluator = field(
        default_factory=ControlStatusEvaluator, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        if len(self.notes) > 4000:
            raise ControlAssessmentInvariantError("notes exceed 4000 characters")
        # Preserve unknown statuses — never rewrite on load.
        ids = [link.evidence_id for link in self.evidence_links]
        if len(ids) != len(set(ids)):
            raise DuplicateEvidenceLinkError("duplicate evidence_id in links")

    @classmethod
    def create(
        cls,
        *,
        organization_id: str,
        profile_id: EntityId,
        period_id: EntityId,
        requirement_id: EntityId,
        framework_key: FrameworkKey,
        created_by: str,
        notes: str = "",
    ) -> ControlAssessment:
        now = datetime.now(UTC)
        assessment = cls(
            id=EntityId.generate(),
            organization_id=organization_id,
            profile_id=profile_id,
            period_id=period_id,
            requirement_id=requirement_id,
            framework_key=framework_key,
            status=ControlStatus.not_assessed(),
            evidence_links=[],
            notes=notes.strip(),
            created_by=created_by,
            created_at=now,
            updated_at=now,
        )
        assessment._emit(
            ControlAssessmentCreated(
                assessment_id=str(assessment.id),
                organization_id=organization_id,
                period_id=str(period_id),
                requirement_id=str(requirement_id),
                framework_key=framework_key,
                created_by=created_by,
            )
        )
        return assessment

    @classmethod
    def reconstitute(cls, data: dict[str, Any]) -> ControlAssessment:
        links = [
            ConfirmedEvidenceLink(
                evidence_id=item["evidence_id"],
                confirmed_by=item["confirmed_by"],
                confirmed_at=item["confirmed_at"],
                rationale=item.get("rationale", ""),
            )
            for item in data.get("evidence_links", [])
        ]
        return cls(
            id=EntityId.from_string(data["id"]),
            organization_id=data["organization_id"],
            profile_id=EntityId.from_string(data["profile_id"]),
            period_id=EntityId.from_string(data["period_id"]),
            requirement_id=EntityId.from_string(data["requirement_id"]),
            framework_key=FrameworkKey(data["framework_key"]),
            status=ControlStatus.parse(data["status"]),
            evidence_links=links,
            notes=data.get("notes", ""),
            created_by=data["created_by"],
            created_at=data["created_at"],
            updated_at=data["updated_at"],
        )

    def confirm_evidence_link(
        self,
        *,
        evidence_id: str,
        confirmed_by: str,
        rationale: str = "",
    ) -> ConfirmedEvidenceLink:
        """Attach a human-confirmed evidence reference (no auto-linking)."""
        if any(link.evidence_id == evidence_id for link in self.evidence_links):
            raise DuplicateEvidenceLinkError(evidence_id)
        if self.status.value == ControlStatusCode.TECHNICALLY_VALIDATED:
            raise ControlAssessmentInvariantError(
                "Cannot add evidence links after technical validation"
            )
        link = ConfirmedEvidenceLink(
            evidence_id=evidence_id,
            confirmed_by=confirmed_by,
            confirmed_at=datetime.now(UTC),
            rationale=rationale,
        )
        self.evidence_links.append(link)
        self.updated_at = datetime.now(UTC)
        self._emit(
            ControlEvidenceLinkConfirmed(
                assessment_id=str(self.id),
                organization_id=self.organization_id,
                evidence_id=evidence_id,
                confirmed_by=confirmed_by,
            )
        )
        # Auto-advance not_assessed → collecting_evidence on first link.
        if self.status.value == ControlStatusCode.NOT_ASSESSED:
            self._transition_to(
                ControlStatus.collecting_evidence(),
                actor_id=confirmed_by,
            )
        return link

    def begin_evidence_collection(self, *, actor_id: str) -> None:
        self._transition_to(
            ControlStatus.collecting_evidence(),
            actor_id=actor_id,
        )

    def submit_for_confirmation(self, *, actor_id: str) -> None:
        self._transition_to(
            ControlStatus.pending_confirmation(),
            actor_id=actor_id,
        )

    def technically_validate(self, *, actor_id: str) -> None:
        self._transition_to(
            ControlStatus.technically_validated(),
            actor_id=actor_id,
        )

    def _transition_to(self, target: ControlStatus, *, actor_id: str) -> None:
        previous = self.status
        if previous.value == target.value:
            return
        try:
            new_status = self._evaluator.evaluate_transition(
                previous,
                target,
                evidence_count=len(self.evidence_links),
            )
        except InvalidControlStatusTransitionError:
            raise
        self.status = new_status
        self.updated_at = datetime.now(UTC)
        self._emit(
            ControlStatusChanged(
                assessment_id=str(self.id),
                organization_id=self.organization_id,
                previous_status=previous.value,
                new_status=new_status.value,
                changed_by=actor_id,
            )
        )

    def collect_events(self) -> list[object]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: object) -> None:
        self._pending_events.append(event)
