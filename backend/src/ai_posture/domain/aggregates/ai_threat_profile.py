"""AIThreatProfile aggregate root — independent of AISystemAsset (ADR-M31-009)."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid4

from ai_posture.domain.events.posture_events import (
    AIThreatProfileCreated,
    ExposureLevelChanged,
    ThreatCategoryAssessed,
    ThreatProfileFlaggedStale,
)
from ai_posture.domain.exceptions.domain_exceptions import (
    CategoryNotApplicable,
    CriticalExposureRequiresEvidence,
    TenantMismatch,
    ThreatProfileArchived,
)
from ai_posture.domain.value_objects.enums import AIThreatCategory, ExposureLevel
from ai_posture.domain.value_objects.posture_vos import KIND_THREAT_TAXONOMY

if TYPE_CHECKING:
    from datetime import datetime

    from ai_posture.domain.events.base import BaseDomainEvent
    from ai_posture.domain.value_objects.enums import AISystemKind
    from ai_posture.domain.value_objects.identifiers import (
        AISystemAssetId,
        AIThreatProfileId,
        TenantId,
    )
    from ai_posture.domain.value_objects.posture_vos import (
        ModelExtractionRiskAssessment,
        PromptInjectionExposureAssessment,
        ThreatCategoryAssessment,
        TrainingDataLeakageAssessment,
    )


class AIThreatProfile:
    __slots__ = (
        "_pending_events",
        "_version",
        "ai_system_asset_id",
        "ai_system_kind",
        "archived",
        "category_assessments",
        "evidence_refs",
        "last_assessed_at",
        "model_extraction",
        "profile_id",
        "prompt_injection",
        "requires_reassessment",
        "tenant_id",
        "training_data_leakage",
    )

    def __init__(
        self,
        profile_id: AIThreatProfileId,
        tenant_id: TenantId,
        ai_system_asset_id: AISystemAssetId,
        ai_system_kind: AISystemKind,
        prompt_injection: PromptInjectionExposureAssessment | None,
        model_extraction: ModelExtractionRiskAssessment | None,
        training_data_leakage: TrainingDataLeakageAssessment | None,
        category_assessments: list[ThreatCategoryAssessment],
        evidence_refs: list[str],
        last_assessed_at: datetime | None,
        requires_reassessment: bool,
        archived: bool,
        version: int,
    ) -> None:
        self.profile_id = profile_id
        self.tenant_id = tenant_id
        self.ai_system_asset_id = ai_system_asset_id
        self.ai_system_kind = ai_system_kind
        self.prompt_injection = prompt_injection
        self.model_extraction = model_extraction
        self.training_data_leakage = training_data_leakage
        self.category_assessments = list(category_assessments)
        self.evidence_refs = list(evidence_refs)
        self.last_assessed_at = last_assessed_at
        self.requires_reassessment = requires_reassessment
        self.archived = archived
        self._version = version
        self._pending_events: list[BaseDomainEvent] = []

    @property
    def version(self) -> int:
        return self._version

    @property
    def applicable_categories(self) -> tuple[AIThreatCategory, ...]:
        return KIND_THREAT_TAXONOMY.get(self.ai_system_kind.value, ())

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: BaseDomainEvent) -> None:
        self._pending_events.append(event)

    def _assert_tenant(self, tenant_id: TenantId) -> None:
        if tenant_id != self.tenant_id:
            raise TenantMismatch(self.tenant_id, tenant_id)

    def _assert_mutable(self) -> None:
        if self.archived:
            raise ThreatProfileArchived(str(self.profile_id))

    def _assert_applicable(self, category: AIThreatCategory) -> None:
        if category not in self.applicable_categories:
            raise CategoryNotApplicable(category.value)

    @classmethod
    def create(
        cls,
        profile_id: AIThreatProfileId,
        tenant_id: TenantId,
        ai_system_asset_id: AISystemAssetId,
        ai_system_kind: AISystemKind,
        now: datetime,
    ) -> AIThreatProfile:
        profile = cls(
            profile_id=profile_id,
            tenant_id=tenant_id,
            ai_system_asset_id=ai_system_asset_id,
            ai_system_kind=ai_system_kind,
            prompt_injection=None,
            model_extraction=None,
            training_data_leakage=None,
            category_assessments=[],
            evidence_refs=[],
            last_assessed_at=None,
            requires_reassessment=True,
            archived=False,
            version=1,
        )
        profile._emit(
            AIThreatProfileCreated(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(profile_id),
                aggregate_type="AIThreatProfile",
                ai_system_asset_id=str(ai_system_asset_id),
                ai_system_kind=ai_system_kind.value,
            )
        )
        return profile

    def record_prompt_injection(
        self,
        tenant_id: TenantId,
        assessment: PromptInjectionExposureAssessment,
        evidence_refs: list[str],
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._assert_mutable()
        self._assert_applicable(AIThreatCategory.PROMPT_INJECTION)
        if assessment.exposure_level == ExposureLevel.CRITICAL and not evidence_refs:
            raise CriticalExposureRequiresEvidence()
        previous = (
            self.prompt_injection.exposure_level.value
            if self.prompt_injection
            else ExposureLevel.NONE.value
        )
        self.prompt_injection = assessment
        self.evidence_refs = list(dict.fromkeys([*self.evidence_refs, *evidence_refs]))
        self.last_assessed_at = now
        self.requires_reassessment = False
        self._version += 1
        self._emit(
            ThreatCategoryAssessed(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.profile_id),
                aggregate_type="AIThreatProfile",
                category=AIThreatCategory.PROMPT_INJECTION.value,
                exposure_level=assessment.exposure_level.value,
            )
        )
        if previous != assessment.exposure_level.value:
            self._emit(
                ExposureLevelChanged(
                    event_id=str(uuid4()),
                    occurred_at=now,
                    tenant_id=tenant_id,
                    aggregate_id=str(self.profile_id),
                    aggregate_type="AIThreatProfile",
                    category=AIThreatCategory.PROMPT_INJECTION.value,
                    previous_level=previous,
                    new_level=assessment.exposure_level.value,
                )
            )

    def record_model_extraction(
        self,
        tenant_id: TenantId,
        assessment: ModelExtractionRiskAssessment,
        evidence_refs: list[str],
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._assert_mutable()
        self._assert_applicable(AIThreatCategory.MODEL_EXTRACTION)
        if assessment.exposure_level == ExposureLevel.CRITICAL and not evidence_refs:
            raise CriticalExposureRequiresEvidence()
        previous = (
            self.model_extraction.exposure_level.value
            if self.model_extraction
            else ExposureLevel.NONE.value
        )
        self.model_extraction = assessment
        self.evidence_refs = list(dict.fromkeys([*self.evidence_refs, *evidence_refs]))
        self.last_assessed_at = now
        self.requires_reassessment = False
        self._version += 1
        self._emit(
            ThreatCategoryAssessed(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.profile_id),
                aggregate_type="AIThreatProfile",
                category=AIThreatCategory.MODEL_EXTRACTION.value,
                exposure_level=assessment.exposure_level.value,
            )
        )
        if previous != assessment.exposure_level.value:
            self._emit(
                ExposureLevelChanged(
                    event_id=str(uuid4()),
                    occurred_at=now,
                    tenant_id=tenant_id,
                    aggregate_id=str(self.profile_id),
                    aggregate_type="AIThreatProfile",
                    category=AIThreatCategory.MODEL_EXTRACTION.value,
                    previous_level=previous,
                    new_level=assessment.exposure_level.value,
                )
            )

    def record_training_data_leakage(
        self,
        tenant_id: TenantId,
        assessment: TrainingDataLeakageAssessment,
        evidence_refs: list[str],
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._assert_mutable()
        self._assert_applicable(AIThreatCategory.TRAINING_DATA_LEAKAGE)
        if assessment.exposure_level == ExposureLevel.CRITICAL and not evidence_refs:
            raise CriticalExposureRequiresEvidence()
        previous = (
            self.training_data_leakage.exposure_level.value
            if self.training_data_leakage
            else ExposureLevel.NONE.value
        )
        self.training_data_leakage = assessment
        self.evidence_refs = list(dict.fromkeys([*self.evidence_refs, *evidence_refs]))
        self.last_assessed_at = now
        self.requires_reassessment = False
        self._version += 1
        self._emit(
            ThreatCategoryAssessed(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.profile_id),
                aggregate_type="AIThreatProfile",
                category=AIThreatCategory.TRAINING_DATA_LEAKAGE.value,
                exposure_level=assessment.exposure_level.value,
            )
        )
        if previous != assessment.exposure_level.value:
            self._emit(
                ExposureLevelChanged(
                    event_id=str(uuid4()),
                    occurred_at=now,
                    tenant_id=tenant_id,
                    aggregate_id=str(self.profile_id),
                    aggregate_type="AIThreatProfile",
                    category=AIThreatCategory.TRAINING_DATA_LEAKAGE.value,
                    previous_level=previous,
                    new_level=assessment.exposure_level.value,
                )
            )

    def record_generic_category(
        self,
        tenant_id: TenantId,
        assessment: ThreatCategoryAssessment,
        evidence_refs: list[str],
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._assert_mutable()
        self._assert_applicable(assessment.category)
        if assessment.exposure_level == ExposureLevel.CRITICAL and not evidence_refs:
            raise CriticalExposureRequiresEvidence()
        previous = next(
            (
                a.exposure_level.value
                for a in self.category_assessments
                if a.category == assessment.category
            ),
            ExposureLevel.NONE.value,
        )
        self.category_assessments = [
            a for a in self.category_assessments if a.category != assessment.category
        ] + [assessment]
        self.evidence_refs = list(dict.fromkeys([*self.evidence_refs, *evidence_refs]))
        self.last_assessed_at = now
        self.requires_reassessment = False
        self._version += 1
        self._emit(
            ThreatCategoryAssessed(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.profile_id),
                aggregate_type="AIThreatProfile",
                category=assessment.category.value,
                exposure_level=assessment.exposure_level.value,
            )
        )
        if previous != assessment.exposure_level.value:
            self._emit(
                ExposureLevelChanged(
                    event_id=str(uuid4()),
                    occurred_at=now,
                    tenant_id=tenant_id,
                    aggregate_id=str(self.profile_id),
                    aggregate_type="AIThreatProfile",
                    category=assessment.category.value,
                    previous_level=previous,
                    new_level=assessment.exposure_level.value,
                )
            )

    def flag_stale(self, tenant_id: TenantId, days_since: int, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        self._assert_mutable()
        if self.requires_reassessment:
            return
        self.requires_reassessment = True
        self._version += 1
        self._emit(
            ThreatProfileFlaggedStale(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.profile_id),
                aggregate_type="AIThreatProfile",
                ai_system_asset_id=str(self.ai_system_asset_id),
                days_since_assessment=days_since,
            )
        )

    def archive(self, tenant_id: TenantId) -> None:
        self._assert_tenant(tenant_id)
        self.archived = True
        self._version += 1

    def max_exposure_level(self) -> ExposureLevel:
        levels = [ExposureLevel.NONE]
        if self.prompt_injection:
            levels.append(self.prompt_injection.exposure_level)
        if self.model_extraction:
            levels.append(self.model_extraction.exposure_level)
        if self.training_data_leakage:
            levels.append(self.training_data_leakage.exposure_level)
        levels.extend(a.exposure_level for a in self.category_assessments)
        order = [
            ExposureLevel.NONE,
            ExposureLevel.LOW,
            ExposureLevel.MEDIUM,
            ExposureLevel.HIGH,
            ExposureLevel.CRITICAL,
        ]
        return max(levels, key=lambda level: order.index(level))
