"""ThreatActorAssociation aggregate root (M51.1).

The tenant-scoped link between a (global-or-tenant) `ThreatActor` and
a tenant-owned entity the tenant cites as evidence of the association
— a `SecurityCondition`, an `InvestigationCase`, etc., referenced
only via the opaque `ReferencedEntityRef` value object (never a
typed cross-context import, per ADR-M51.1-03).

Every association carries a required, non-empty `EvidenceCitation`
(ADR-M51.1-08) — this aggregate does not, and must not, validate that
the citation resolves to a real record; that belongs to a future
`IEvidenceValidationPort` ACL adapter at the application layer
(Phase 2). This aggregate only enforces the intrinsic rule that a
citation string is present at all (enforced by `EvidenceCitation`
itself, constructed before `create()` is called).

History is append-only (ADR-M51.1-03): there is no `update()`. A
correction is modeled as `retract()` (a one-way, one-time state
transition, never a destructive delete) followed by creating a new
association if the fact is being re-asserted differently. The
platform-wide uniqueness invariant — exactly one `ACTIVE` association
per `(tenant_id, threat_actor_id, referenced_entity_type,
referenced_entity_id)` tuple — spans multiple aggregate instances and
is therefore enforced by `AssociationUniquenessPolicy`, not by this
aggregate alone (a single instance has no visibility into its
siblings).
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid4

from threat_actor_intel.domain.events.association_events import (
    ThreatActorAssociationCreated,
    ThreatActorAssociationRetracted,
)
from threat_actor_intel.domain.exceptions.domain_exceptions import (
    AlreadyRetractedAssociationError,
    MissingTenantIdError,
    MissingThreatActorReferenceError,
)
from threat_actor_intel.domain.value_objects.enums import AssociationState

if TYPE_CHECKING:
    from datetime import datetime

    from threat_actor_intel.domain.events.base import BaseDomainEvent
    from threat_actor_intel.domain.value_objects.evidence import EvidenceCitation
    from threat_actor_intel.domain.value_objects.identifiers import (
        TenantId,
        ThreatActorAssociationId,
        ThreatActorId,
    )
    from threat_actor_intel.domain.value_objects.references import ReferencedEntityRef


class ThreatActorAssociation:
    __slots__ = (
        "_pending_events",
        "association_id",
        "created_at",
        "evidence_citation",
        "referenced_entity",
        "retracted_at",
        "state",
        "tenant_id",
        "threat_actor_id",
        "updated_at",
    )

    def __init__(
        self,
        association_id: ThreatActorAssociationId,
        tenant_id: TenantId,
        threat_actor_id: ThreatActorId,
        referenced_entity: ReferencedEntityRef,
        evidence_citation: EvidenceCitation,
        state: AssociationState,
        created_at: datetime,
        updated_at: datetime,
        retracted_at: datetime | None = None,
    ) -> None:
        if tenant_id is None:
            raise MissingTenantIdError()
        if threat_actor_id is None:
            raise MissingThreatActorReferenceError()
        self.association_id = association_id
        self.tenant_id = tenant_id
        self.threat_actor_id = threat_actor_id
        self.referenced_entity = referenced_entity
        self.evidence_citation = evidence_citation
        self.state = state
        self.created_at = created_at
        self.updated_at = updated_at
        self.retracted_at = retracted_at
        self._pending_events: list[BaseDomainEvent] = []

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: BaseDomainEvent) -> None:
        self._pending_events.append(event)

    @classmethod
    def create(
        cls,
        association_id: ThreatActorAssociationId,
        tenant_id: TenantId,
        threat_actor_id: ThreatActorId,
        referenced_entity: ReferencedEntityRef,
        evidence_citation: EvidenceCitation,
        now: datetime,
    ) -> ThreatActorAssociation:
        association = cls(
            association_id=association_id,
            tenant_id=tenant_id,
            threat_actor_id=threat_actor_id,
            referenced_entity=referenced_entity,
            evidence_citation=evidence_citation,
            state=AssociationState.ACTIVE,
            created_at=now,
            updated_at=now,
        )
        association._emit(
            ThreatActorAssociationCreated(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=str(tenant_id),
                aggregate_id=str(association_id),
                aggregate_type="ThreatActorAssociation",
                threat_actor_id=str(threat_actor_id),
                referenced_entity_type=referenced_entity.entity_type,
                referenced_entity_id=referenced_entity.entity_id,
                evidence_citation=str(evidence_citation),
            )
        )
        return association

    def is_active(self) -> bool:
        return self.state == AssociationState.ACTIVE

    def retract(self, now: datetime) -> None:
        """Append-only correction: transitions `ACTIVE` -> `RETRACTED`.
        Never deletes or mutates the original creation facts (tenant,
        actor, referenced entity, citation) — only the state and
        `retracted_at` change. Retraction is terminal; retracting an
        already-retracted association raises rather than silently
        no-op-ing, so a caller can never lose track of a double-retract
        attempt (e.g. two concurrent corrections racing)."""
        if self.state == AssociationState.RETRACTED:
            raise AlreadyRetractedAssociationError(str(self.association_id))
        self.state = AssociationState.RETRACTED
        self.retracted_at = now
        self.updated_at = now
        self._emit(
            ThreatActorAssociationRetracted(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=str(self.tenant_id),
                aggregate_id=str(self.association_id),
                aggregate_type="ThreatActorAssociation",
                threat_actor_id=str(self.threat_actor_id),
                referenced_entity_type=self.referenced_entity.entity_type,
                referenced_entity_id=self.referenced_entity.entity_id,
            )
        )
