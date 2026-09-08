"""ThreatActor aggregate root (M51A/M51.1).

The canonical, platform-wide ThreatActor model (ADR-M51.1-01). Owns
identity, attribution metadata (aliases, origin, motivations,
sophistication, derived attribution confidence), and activity
lifecycle for one tracked threat actor. Associates with ATT&CK
techniques and fused indicators owned by `redforge.domain.threat_intel`
only via opaque reference value objects
(`AttackTechniqueReference`/`FusedIndicatorReference`) — this
aggregate never imports or mutates that context's data.

`tenant_id` is `TenantId | None` (ADR-M51.1-02): `None` means this is
a global reference record, sourced from a named external feed, never
fabricated. A real `TenantId` means a tenant-scoped record. There is
no reserved "system tenant" sentinel — a global record's tenant_id is
genuinely `None`, and every tenant-scoped command must be called with
`tenant_id=None` to mutate a global record (symmetric equality check
in `_assert_tenant`), matching the caller's own actual authority
rather than a fictional tenant identity. Whether that caller is
authorized to act as "global" is an application-layer concern
(Phase 2) — this aggregate only enforces that the caller's asserted
tenant context matches the record's own, never who is allowed to
assert it.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid4

from threat_actor_intel.domain.events.threat_actor_events import (
    ThreatActorActivityStatusChanged,
    ThreatActorAliasAdded,
    ThreatActorAttributionConfidenceChanged,
    ThreatActorIndicatorAssociated,
    ThreatActorMotivationUpdated,
    ThreatActorRegistered,
    ThreatActorSophisticationUpdated,
    ThreatActorTechniqueAssociated,
)
from threat_actor_intel.domain.exceptions.domain_exceptions import (
    DuplicateAliasError,
    DuplicateIndicatorAssociationError,
    DuplicateTechniqueAssociationError,
    EmptyMotivationSetError,
    TenantMismatch,
)
from threat_actor_intel.domain.policies.activity_lifecycle_policy import ActivityLifecyclePolicy
from threat_actor_intel.domain.policies.attribution_confidence_policy import (
    AttributionConfidencePolicy,
)
from threat_actor_intel.domain.value_objects.enums import (
    ActivityStatus,
    AttributionConfidence,
    MotivationType,
    SophisticationLevel,
    ThreatActorOrigin,
)

if TYPE_CHECKING:
    from datetime import datetime

    from threat_actor_intel.domain.events.base import BaseDomainEvent
    from threat_actor_intel.domain.value_objects.identifiers import TenantId, ThreatActorId
    from threat_actor_intel.domain.value_objects.identity import Alias, ThreatActorName
    from threat_actor_intel.domain.value_objects.references import (
        AttackTechniqueReference,
        FusedIndicatorReference,
    )


def _tenant_id_str(tenant_id: TenantId | None) -> str:
    """`None` (a global record's tenant context) renders as `""` in an
    event payload, never as the string `"None"` — a global record's
    events must not falsely imply a real tenant identity exists."""
    return "" if tenant_id is None else str(tenant_id)


class ThreatActor:
    __slots__ = (
        "_pending_events",
        "aliases",
        "attribution_confidence",
        "created_at",
        "indicator_refs",
        "motivations",
        "name",
        "origin",
        "sophistication",
        "status",
        "technique_refs",
        "tenant_id",
        "threat_actor_id",
        "updated_at",
    )

    def __init__(
        self,
        threat_actor_id: ThreatActorId,
        tenant_id: TenantId | None,
        name: ThreatActorName,
        origin: ThreatActorOrigin,
        motivations: frozenset[MotivationType],
        sophistication: SophisticationLevel,
        status: ActivityStatus,
        created_at: datetime,
        updated_at: datetime,
        aliases: tuple[Alias, ...] = (),
        technique_refs: tuple[AttackTechniqueReference, ...] = (),
        indicator_refs: tuple[FusedIndicatorReference, ...] = (),
        attribution_confidence: AttributionConfidence = AttributionConfidence.LOW,
    ) -> None:
        if not motivations:
            raise EmptyMotivationSetError()
        self.threat_actor_id = threat_actor_id
        self.tenant_id = tenant_id
        self.name = name
        self.origin = origin
        self.motivations = motivations
        self.sophistication = sophistication
        self.status = status
        self.created_at = created_at
        self.updated_at = updated_at
        self.aliases = aliases
        self.technique_refs = technique_refs
        self.indicator_refs = indicator_refs
        self.attribution_confidence = attribution_confidence
        self._pending_events: list[BaseDomainEvent] = []

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: BaseDomainEvent) -> None:
        self._pending_events.append(event)

    def _assert_tenant(self, tenant_id: TenantId | None) -> None:
        if tenant_id != self.tenant_id:
            raise TenantMismatch(self.tenant_id, tenant_id)

    def _recompute_attribution_confidence(self, tenant_id: TenantId | None, now: datetime) -> None:
        derived = AttributionConfidencePolicy.derive(
            technique_count=len(self.technique_refs),
            indicator_count=len(self.indicator_refs),
            sophistication=self.sophistication,
        )
        if derived == self.attribution_confidence:
            return
        self.attribution_confidence = derived
        self.updated_at = now
        self._emit(
            ThreatActorAttributionConfidenceChanged(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.threat_actor_id),
                aggregate_type="ThreatActor",
                confidence=derived.value,
            )
        )

    @classmethod
    def register(
        cls,
        threat_actor_id: ThreatActorId,
        tenant_id: TenantId | None,
        name: ThreatActorName,
        origin: ThreatActorOrigin,
        motivations: frozenset[MotivationType],
        sophistication: SophisticationLevel,
        now: datetime,
    ) -> ThreatActor:
        actor = cls(
            threat_actor_id=threat_actor_id,
            tenant_id=tenant_id,
            name=name,
            origin=origin,
            motivations=motivations,
            sophistication=sophistication,
            status=ActivityStatus.ACTIVE,
            created_at=now,
            updated_at=now,
        )
        actor._emit(
            ThreatActorRegistered(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(threat_actor_id),
                aggregate_type="ThreatActor",
                name=str(name),
                origin=origin.value,
            )
        )
        return actor

    def add_alias(self, tenant_id: TenantId | None, alias: Alias, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        normalized = alias.normalized()
        if any(existing.normalized() == normalized for existing in self.aliases):
            raise DuplicateAliasError(str(alias))
        self.aliases = (*self.aliases, alias)
        self.updated_at = now
        self._emit(
            ThreatActorAliasAdded(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.threat_actor_id),
                aggregate_type="ThreatActor",
                alias=str(alias),
            )
        )

    def associate_technique(
        self, tenant_id: TenantId | None, technique_ref: AttackTechniqueReference, now: datetime
    ) -> None:
        self._assert_tenant(tenant_id)
        if any(ref.technique_id == technique_ref.technique_id for ref in self.technique_refs):
            raise DuplicateTechniqueAssociationError(technique_ref.technique_id)
        self.technique_refs = (*self.technique_refs, technique_ref)
        self.updated_at = now
        self._emit(
            ThreatActorTechniqueAssociated(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.threat_actor_id),
                aggregate_type="ThreatActor",
                technique_id=technique_ref.technique_id,
            )
        )
        self._recompute_attribution_confidence(tenant_id, now)

    def associate_indicator(
        self, tenant_id: TenantId | None, indicator_ref: FusedIndicatorReference, now: datetime
    ) -> None:
        self._assert_tenant(tenant_id)
        if any(ref.indicator_id == indicator_ref.indicator_id for ref in self.indicator_refs):
            raise DuplicateIndicatorAssociationError(indicator_ref.indicator_id)
        self.indicator_refs = (*self.indicator_refs, indicator_ref)
        self.updated_at = now
        self._emit(
            ThreatActorIndicatorAssociated(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.threat_actor_id),
                aggregate_type="ThreatActor",
                indicator_id=indicator_ref.indicator_id,
            )
        )
        self._recompute_attribution_confidence(tenant_id, now)

    def update_motivations(
        self, tenant_id: TenantId | None, motivations: frozenset[MotivationType], now: datetime
    ) -> None:
        self._assert_tenant(tenant_id)
        if not motivations:
            raise EmptyMotivationSetError()
        self.motivations = motivations
        self.updated_at = now
        self._emit(
            ThreatActorMotivationUpdated(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.threat_actor_id),
                aggregate_type="ThreatActor",
                motivations=tuple(sorted(m.value for m in motivations)),
            )
        )

    def update_sophistication(
        self, tenant_id: TenantId | None, sophistication: SophisticationLevel, now: datetime
    ) -> None:
        self._assert_tenant(tenant_id)
        self.sophistication = sophistication
        self.updated_at = now
        self._emit(
            ThreatActorSophisticationUpdated(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.threat_actor_id),
                aggregate_type="ThreatActor",
                sophistication=sophistication.value,
            )
        )
        self._recompute_attribution_confidence(tenant_id, now)

    def _transition_status(
        self, tenant_id: TenantId | None, target: ActivityStatus, now: datetime
    ) -> None:
        self._assert_tenant(tenant_id)
        ActivityLifecyclePolicy.assert_legal_transition(self.status, target)
        previous = self.status
        self.status = target
        self.updated_at = now
        self._emit(
            ThreatActorActivityStatusChanged(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.threat_actor_id),
                aggregate_type="ThreatActor",
                from_status=previous.value,
                to_status=target.value,
            )
        )

    def mark_dormant(self, tenant_id: TenantId | None, now: datetime) -> None:
        self._transition_status(tenant_id, ActivityStatus.DORMANT, now)

    def reactivate(self, tenant_id: TenantId | None, now: datetime) -> None:
        self._transition_status(tenant_id, ActivityStatus.ACTIVE, now)

    def disband(self, tenant_id: TenantId | None, now: datetime) -> None:
        self._transition_status(tenant_id, ActivityStatus.DISBANDED, now)
