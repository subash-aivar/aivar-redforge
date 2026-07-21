"""ShadowAIAlert aggregate root."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid4

from ai_posture.domain.events.posture_events import (
    ShadowAIAlertConfirmed,
    ShadowAIAlertDismissedFalsePositive,
    ShadowAIAlertRaised,
    ShadowAIAlertResolved,
    ShadowAIAlertTriaged,
)
from ai_posture.domain.exceptions.domain_exceptions import (
    FalsePositiveReasonRequired,
    InvalidAlertTransition,
    ResolutionActionRequired,
    TenantMismatch,
)
from ai_posture.domain.value_objects.enums import AlertState, ResolutionAction

if TYPE_CHECKING:
    from datetime import datetime

    from ai_posture.domain.events.base import BaseDomainEvent
    from ai_posture.domain.value_objects.identifiers import (
        AISystemAssetId,
        ShadowAIAlertId,
        TenantId,
    )
    from ai_posture.domain.value_objects.posture_vos import DiscoveredServiceFingerprint


class ShadowAIAlert:
    __slots__ = (
        "_pending_events",
        "_version",
        "alert_id",
        "fingerprint",
        "first_detected_at",
        "last_confirmed_at",
        "linked_asset_id",
        "resolution_action",
        "state",
        "tenant_id",
        "triage_notes",
    )

    def __init__(
        self,
        alert_id: ShadowAIAlertId,
        tenant_id: TenantId,
        fingerprint: DiscoveredServiceFingerprint,
        state: AlertState,
        first_detected_at: datetime,
        last_confirmed_at: datetime,
        triage_notes: str,
        resolution_action: ResolutionAction | None,
        linked_asset_id: AISystemAssetId | None,
        version: int,
    ) -> None:
        self.alert_id = alert_id
        self.tenant_id = tenant_id
        self.fingerprint = fingerprint
        self.state = state
        self.first_detected_at = first_detected_at
        self.last_confirmed_at = last_confirmed_at
        self.triage_notes = triage_notes
        self.resolution_action = resolution_action
        self.linked_asset_id = linked_asset_id
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

    @classmethod
    def raise_alert(
        cls,
        alert_id: ShadowAIAlertId,
        tenant_id: TenantId,
        fingerprint: DiscoveredServiceFingerprint,
        now: datetime,
    ) -> ShadowAIAlert:
        alert = cls(
            alert_id=alert_id,
            tenant_id=tenant_id,
            fingerprint=fingerprint,
            state=AlertState.OPEN,
            first_detected_at=now,
            last_confirmed_at=now,
            triage_notes="",
            resolution_action=None,
            linked_asset_id=None,
            version=1,
        )
        alert._emit(
            ShadowAIAlertRaised(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(alert_id),
                aggregate_type="ShadowAIAlert",
                fingerprint_hash=fingerprint.fingerprint_hash(),
                discovery_source=fingerprint.discovery_source.value,
            )
        )
        return alert

    def confirm_still_present(self, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        self.last_confirmed_at = now
        self._version += 1

    def begin_triage(self, tenant_id: TenantId, triaged_by: str, notes: str, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if self.state != AlertState.OPEN:
            raise InvalidAlertTransition(self.state.value, "begin_triage")
        self.state = AlertState.UNDER_TRIAGE
        self.triage_notes = notes
        self._version += 1
        self._emit(
            ShadowAIAlertTriaged(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.alert_id),
                aggregate_type="ShadowAIAlert",
                alert_id=str(self.alert_id),
                triaged_by=triaged_by,
            )
        )

    def confirm_shadow_ai(self, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if self.state != AlertState.UNDER_TRIAGE:
            raise InvalidAlertTransition(self.state.value, "confirm_shadow_ai")
        self.state = AlertState.CONFIRMED_SHADOW_AI
        self._version += 1
        self._emit(
            ShadowAIAlertConfirmed(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.alert_id),
                aggregate_type="ShadowAIAlert",
                alert_id=str(self.alert_id),
                confirmed_state=self.state.value,
            )
        )

    def confirm_false_positive(self, tenant_id: TenantId, reason: str, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if self.state != AlertState.UNDER_TRIAGE:
            raise InvalidAlertTransition(self.state.value, "confirm_false_positive")
        if not reason.strip():
            raise FalsePositiveReasonRequired()
        self.state = AlertState.CONFIRMED_FALSE_POSITIVE
        self.triage_notes = reason.strip()
        self._version += 1
        self._emit(
            ShadowAIAlertDismissedFalsePositive(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.alert_id),
                aggregate_type="ShadowAIAlert",
                alert_id=str(self.alert_id),
                reason=reason.strip(),
            )
        )

    def resolve(
        self,
        tenant_id: TenantId,
        action: ResolutionAction,
        linked_asset_id: AISystemAssetId | None,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        if self.state not in {
            AlertState.CONFIRMED_SHADOW_AI,
            AlertState.CONFIRMED_FALSE_POSITIVE,
            AlertState.UNDER_TRIAGE,
        }:
            raise InvalidAlertTransition(self.state.value, "resolve")
        if action is None:
            raise ResolutionActionRequired()
        self.resolution_action = action
        self.linked_asset_id = linked_asset_id
        self.state = AlertState.RESOLVED
        self._version += 1
        self._emit(
            ShadowAIAlertResolved(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(self.alert_id),
                aggregate_type="ShadowAIAlert",
                alert_id=str(self.alert_id),
                resolution_action=action.value,
            )
        )
