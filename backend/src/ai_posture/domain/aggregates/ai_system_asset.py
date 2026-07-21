"""AISystemAsset aggregate root — AI-SPM extension to M22 inventory."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid4

from ai_posture.domain.events.posture_events import (
    AISystemAssetClassified,
    AISystemAssetDecommissioned,
    AISystemAssetDeprecated,
    AISystemAssetDiscovered,
    AISystemAssetOwnerAssigned,
    AISystemAssetRegistered,
    ShadowAIStatusAssigned,
)
from ai_posture.domain.exceptions.domain_exceptions import (
    AggregateSealed,
    InvalidLifecycleTransition,
    OwnerRequiredForRegistration,
    ShadowAIBlocksRegistration,
    TenantMismatch,
)
from ai_posture.domain.value_objects.enums import (
    AISystemKind,
    AISystemLifecycleState,
    DataSensitivityClassification,
    RegistrationStatus,
)

if TYPE_CHECKING:
    from datetime import datetime

    from ai_posture.domain.events.base import BaseDomainEvent
    from ai_posture.domain.value_objects.identifiers import AISystemAssetId, TenantId
    from ai_posture.domain.value_objects.posture_vos import (
        AIRiskScoreRef,
        AIThreatProfileRef,
        AssetRef,
        BusinessOwnerRef,
        DiscoverySourceRecord,
    )

_ALLOWED: dict[AISystemLifecycleState, frozenset[AISystemLifecycleState]] = {
    AISystemLifecycleState.DISCOVERED: frozenset({AISystemLifecycleState.PENDING_CLASSIFICATION}),
    AISystemLifecycleState.PENDING_CLASSIFICATION: frozenset({AISystemLifecycleState.UNDER_REVIEW}),
    AISystemLifecycleState.UNDER_REVIEW: frozenset(
        {AISystemLifecycleState.REGISTERED, AISystemLifecycleState.UNDER_REVIEW}
    ),
    AISystemLifecycleState.REGISTERED: frozenset(
        {AISystemLifecycleState.DEPRECATED, AISystemLifecycleState.DECOMMISSIONED}
    ),
    AISystemLifecycleState.DEPRECATED: frozenset({AISystemLifecycleState.DECOMMISSIONED}),
    AISystemLifecycleState.DECOMMISSIONED: frozenset(),
}


class AISystemAsset:
    """Bounded extension record keyed 1:1 to an M22 AssetRef."""

    __slots__ = (
        "_pending_events",
        "_version",
        "ai_system_kind",
        "asset_id",
        "asset_ref",
        "business_owner",
        "created_at",
        "data_sensitivity",
        "discovery_source",
        "lifecycle_state",
        "registration_status",
        "risk_score_ref",
        "tenant_id",
        "threat_profile_ref",
        "updated_at",
    )

    def __init__(
        self,
        asset_id: AISystemAssetId,
        tenant_id: TenantId,
        asset_ref: AssetRef,
        lifecycle_state: AISystemLifecycleState,
        registration_status: RegistrationStatus,
        discovery_source: DiscoverySourceRecord,
        ai_system_kind: AISystemKind | None,
        business_owner: BusinessOwnerRef | None,
        data_sensitivity: DataSensitivityClassification,
        threat_profile_ref: AIThreatProfileRef | None,
        risk_score_ref: AIRiskScoreRef | None,
        created_at: datetime,
        updated_at: datetime,
        version: int,
    ) -> None:
        self.asset_id = asset_id
        self.tenant_id = tenant_id
        self.asset_ref = asset_ref
        self.lifecycle_state = lifecycle_state
        self.registration_status = registration_status
        self.discovery_source = discovery_source
        self.ai_system_kind = ai_system_kind
        self.business_owner = business_owner
        self.data_sensitivity = data_sensitivity
        self.threat_profile_ref = threat_profile_ref
        self.risk_score_ref = risk_score_ref
        self.created_at = created_at
        self.updated_at = updated_at
        self._version = version
        self._pending_events: list[BaseDomainEvent] = []

    @property
    def version(self) -> int:
        return self._version

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
        if self.lifecycle_state == AISystemLifecycleState.DECOMMISSIONED:
            raise AggregateSealed(str(self.asset_id))

    def _transition(self, to_state: AISystemLifecycleState) -> None:
        allowed = _ALLOWED.get(self.lifecycle_state, frozenset())
        if to_state not in allowed and to_state != self.lifecycle_state:
            raise InvalidLifecycleTransition(self.lifecycle_state.value, to_state.value)
        self.lifecycle_state = to_state

    def _mutate(self, now: datetime) -> None:
        self._version += 1
        self.updated_at = now

    @classmethod
    def discover(
        cls,
        asset_id: AISystemAssetId,
        tenant_id: TenantId,
        asset_ref: AssetRef,
        discovery_source: DiscoverySourceRecord,
        data_sensitivity: DataSensitivityClassification,
        now: datetime,
        *,
        as_shadow: bool = False,
    ) -> AISystemAsset:
        status = RegistrationStatus.SHADOW_AI if as_shadow else RegistrationStatus.UNREGISTERED
        asset = cls(
            asset_id=asset_id,
            tenant_id=tenant_id,
            asset_ref=asset_ref,
            lifecycle_state=AISystemLifecycleState.DISCOVERED,
            registration_status=status,
            discovery_source=discovery_source,
            ai_system_kind=None,
            business_owner=None,
            data_sensitivity=data_sensitivity,
            threat_profile_ref=None,
            risk_score_ref=None,
            created_at=now,
            updated_at=now,
            version=1,
        )
        asset._emit(
            AISystemAssetDiscovered(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(asset_id),
                aggregate_type="AISystemAsset",
                asset_ref_id=str(asset_ref.asset_id),
                discovery_source=discovery_source.source.value,
            )
        )
        if as_shadow:
            asset._emit(
                ShadowAIStatusAssigned(
                    event_id=str(uuid4()),
                    occurred_at=now,
                    tenant_id=tenant_id,
                    aggregate_id=str(asset_id),
                    aggregate_type="AISystemAsset",
                    registration_status=status.value,
                )
            )
        return asset

    def mark_pending_classification(self, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        self._assert_mutable()
        self._transition(AISystemLifecycleState.PENDING_CLASSIFICATION)
        self._mutate(now)

    def classify(
        self,
        tenant_id: TenantId,
        kind: AISystemKind,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._assert_mutable()
        if self.lifecycle_state == AISystemLifecycleState.DISCOVERED:
            self._transition(AISystemLifecycleState.PENDING_CLASSIFICATION)
        self.ai_system_kind = kind
        self._transition(AISystemLifecycleState.UNDER_REVIEW)
        self._mutate(now)
        self._emit(
            AISystemAssetClassified(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.asset_id),
                aggregate_type="AISystemAsset",
                ai_system_kind=kind.value,
            )
        )

    def assign_owner(
        self,
        tenant_id: TenantId,
        owner: BusinessOwnerRef,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._assert_mutable()
        self.business_owner = owner
        self._mutate(now)
        self._emit(
            AISystemAssetOwnerAssigned(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.asset_id),
                aggregate_type="AISystemAsset",
                owner_id=owner.owner_id,
            )
        )

    def mark_shadow_ai(self, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        self._assert_mutable()
        self.registration_status = RegistrationStatus.SHADOW_AI
        self._mutate(now)
        self._emit(
            ShadowAIStatusAssigned(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.asset_id),
                aggregate_type="AISystemAsset",
                registration_status=RegistrationStatus.SHADOW_AI.value,
            )
        )

    def clear_shadow_status(self, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        self._assert_mutable()
        if self.registration_status == RegistrationStatus.SHADOW_AI:
            self.registration_status = RegistrationStatus.UNREGISTERED
            self._mutate(now)

    def approve_registration(self, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        self._assert_mutable()
        if self.business_owner is None:
            raise OwnerRequiredForRegistration()
        if self.registration_status == RegistrationStatus.SHADOW_AI:
            raise ShadowAIBlocksRegistration()
        if self.ai_system_kind is None:
            raise InvalidLifecycleTransition(
                self.lifecycle_state.value, AISystemLifecycleState.REGISTERED.value
            )
        self.registration_status = RegistrationStatus.FORMALLY_REGISTERED
        self._transition(AISystemLifecycleState.REGISTERED)
        self._mutate(now)
        self._emit(
            AISystemAssetRegistered(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.asset_id),
                aggregate_type="AISystemAsset",
                ai_system_kind=self.ai_system_kind.value,
            )
        )

    def deprecate(self, tenant_id: TenantId, reason: str, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        self._assert_mutable()
        self._transition(AISystemLifecycleState.DEPRECATED)
        self._mutate(now)
        self._emit(
            AISystemAssetDeprecated(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.asset_id),
                aggregate_type="AISystemAsset",
                reason=reason,
            )
        )

    def decommission(self, tenant_id: TenantId, reason: str, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        self._assert_mutable()
        self._transition(AISystemLifecycleState.DECOMMISSIONED)
        self._mutate(now)
        self._emit(
            AISystemAssetDecommissioned(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.asset_id),
                aggregate_type="AISystemAsset",
                reason=reason,
            )
        )

    def attach_threat_profile_ref(
        self,
        tenant_id: TenantId,
        profile_ref: AIThreatProfileRef,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._assert_mutable()
        self.threat_profile_ref = profile_ref
        self._mutate(now)

    def attach_risk_score_ref(
        self,
        tenant_id: TenantId,
        score_ref: AIRiskScoreRef,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        self._assert_mutable()
        self.risk_score_ref = score_ref
        self._mutate(now)
