"""IntelligenceRelationship aggregate root (M51.4 Phase C1).

The sole aggregate in the intelligence_relationships bounded context.
It owns the typed, evidence-first, epistemically-graded *edge* between
two threat intelligence entities — never the entities themselves. Both
endpoints are opaque `EntityRef`s; existence of the three
RedForge-native endpoint kinds is validated by the application layer
via the ACL ports BEFORE this aggregate is ever constructed. This
aggregate never imports, mirrors, or re-validates another bounded
context's domain classes.

`tenant_id` is `TenantId | None`: `None` means a global
RedForge-curated relationship (requires `platform:*` permission to
mutate); a real `TenantId` means a tenant-scoped relationship.

Identity is `(scope, relationship_type, source_entity, target_entity)`
and is IMMUTABLE after creation — enforced two ways:
`RelationshipIdentityPolicy` here in the domain, and a repository
existence check in the application service, mirroring
`attack_pattern_intel`'s exact dedup discipline. Only the
RedForge-native claim fields (confidence, epistemic state, lifecycle,
validity, evidence, attributions, version history) ever mutate.

Two independent state axes are tracked deliberately:
`epistemic_state` (how strongly the claim is *believed*, governed by
`EpistemicTransitionPolicy`) and `lifecycle_status` (whether the
record is *operationally current*, governed by
`LifecycleTransitionPolicy`). Neither constrains the other.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid4

from intelligence_relationships.domain.events.relationship_events import (
    EpistemicStateTransitioned,
    EvidenceCitationAdded,
    IntelligenceRelationshipDeprecated,
    IntelligenceRelationshipObserved,
    IntelligenceRelationshipReactivated,
    IntelligenceRelationshipRevoked,
    IntelligenceRelationshipSuperseded,
    SourceAttributionAdded,
)
from intelligence_relationships.domain.exceptions.domain_exceptions import (
    MissingSupersededByError,
    TenantMismatchError,
)
from intelligence_relationships.domain.policies.epistemic_transition_policy import (
    EpistemicTransitionPolicy,
)
from intelligence_relationships.domain.policies.identity_policy import identity_key
from intelligence_relationships.domain.policies.lifecycle_transition_policy import (
    LifecycleTransitionPolicy,
)
from intelligence_relationships.domain.policies.type_compatibility_policy import (
    RelationshipTypeCompatibilityPolicy,
)
from intelligence_relationships.domain.value_objects.enums import (
    EpistemicState,
    RelationshipLifecycleStatus,
)
from intelligence_relationships.domain.value_objects.version_record import VersionRecord

if TYPE_CHECKING:
    from datetime import datetime

    from intelligence_relationships.domain.events.base import BaseDomainEvent
    from intelligence_relationships.domain.value_objects.entity_ref import EntityRef
    from intelligence_relationships.domain.value_objects.enums import (
        RelationshipConfidence,
        RelationshipDirection,
        RelationshipType,
    )
    from intelligence_relationships.domain.value_objects.evidence import (
        EvidenceCitation,
        SourceAttribution,
    )
    from intelligence_relationships.domain.value_objects.identifiers import (
        IntelligenceRelationshipId,
        TenantId,
    )
    from intelligence_relationships.domain.value_objects.validity import Validity


def _tenant_id_str(tenant_id: TenantId | None) -> str:
    """`None` (a global record's tenant context) renders as `""` in an
    event payload, never as the string `"None"`."""
    return "" if tenant_id is None else str(tenant_id)


class IntelligenceRelationship:
    __slots__ = (
        "_pending_events",
        "confidence",
        "created_at",
        "direction",
        "epistemic_state",
        "evidence_citations",
        "lifecycle_status",
        "relationship_id",
        "relationship_type",
        "row_version",
        "source_attributions",
        "source_entity",
        "superseded_by",
        "target_entity",
        "tenant_id",
        "updated_at",
        "validity",
        "version_history",
    )

    def __init__(
        self,
        relationship_id: IntelligenceRelationshipId,
        tenant_id: TenantId | None,
        relationship_type: RelationshipType,
        source_entity: EntityRef,
        target_entity: EntityRef,
        direction: RelationshipDirection,
        confidence: RelationshipConfidence,
        epistemic_state: EpistemicState,
        lifecycle_status: RelationshipLifecycleStatus,
        validity: Validity,
        created_at: datetime,
        updated_at: datetime,
        evidence_citations: tuple[EvidenceCitation, ...] = (),
        source_attributions: tuple[SourceAttribution, ...] = (),
        version_history: tuple[VersionRecord, ...] = (),
        superseded_by: IntelligenceRelationshipId | None = None,
        row_version: int = 1,
    ) -> None:
        self.relationship_id = relationship_id
        self.tenant_id = tenant_id
        self.relationship_type = relationship_type
        self.source_entity = source_entity
        self.target_entity = target_entity
        self.direction = direction
        self.confidence = confidence
        self.epistemic_state = epistemic_state
        self.lifecycle_status = lifecycle_status
        self.validity = validity
        self.created_at = created_at
        self.updated_at = updated_at
        self.evidence_citations = evidence_citations
        self.source_attributions = source_attributions
        self.version_history = version_history
        self.superseded_by = superseded_by
        # Persistence-only bookkeeping — never read by any domain
        # policy/invariant; a repository's optimistic-concurrency guard
        # is the only legitimate reader/writer of this field.
        self.row_version = row_version
        self._pending_events: list[BaseDomainEvent] = []

    # ── Identity ─────────────────────────────────────────────────────────

    @property
    def identity_key(self) -> str:
        """`(relationship_type, source_entity, target_entity)` rendered
        canonically. Scope (`tenant_id`) is the fourth identity
        component but is compared separately by the repository/policy,
        never folded into this string."""
        return identity_key(self.relationship_type, self.source_entity, self.target_entity)

    # ── Event plumbing ───────────────────────────────────────────────────

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: BaseDomainEvent) -> None:
        self._pending_events.append(event)

    def _assert_tenant(self, tenant_id: TenantId | None) -> None:
        if tenant_id != self.tenant_id:
            raise TenantMismatchError(self.tenant_id, tenant_id)

    def _record_version(self, now: datetime, summary: str, source: str) -> None:
        next_version = len(self.version_history) + 1
        self.version_history = (
            *self.version_history,
            VersionRecord(
                version=next_version, changed_at=now, change_summary=summary, source=source
            ),
        )
        self.updated_at = now

    # ── Construction ─────────────────────────────────────────────────────

    @classmethod
    def observe(
        cls,
        relationship_id: IntelligenceRelationshipId,
        tenant_id: TenantId | None,
        relationship_type: RelationshipType,
        source_entity: EntityRef,
        target_entity: EntityRef,
        direction: RelationshipDirection,
        confidence: RelationshipConfidence,
        validity: Validity,
        now: datetime,
        epistemic_state: EpistemicState = EpistemicState.OBSERVATION,
        evidence_citations: tuple[EvidenceCitation, ...] = (),
        source_attributions: tuple[SourceAttribution, ...] = (),
    ) -> IntelligenceRelationship:
        RelationshipTypeCompatibilityPolicy.assert_compatible(
            relationship_type, source_entity, target_entity
        )
        relationship = cls(
            relationship_id=relationship_id,
            tenant_id=tenant_id,
            relationship_type=relationship_type,
            source_entity=source_entity,
            target_entity=target_entity,
            direction=direction,
            confidence=confidence,
            epistemic_state=epistemic_state,
            lifecycle_status=RelationshipLifecycleStatus.ACTIVE,
            validity=validity,
            created_at=now,
            updated_at=now,
            evidence_citations=evidence_citations,
            source_attributions=source_attributions,
            version_history=(
                VersionRecord(
                    version=1,
                    changed_at=now,
                    change_summary="Observed",
                    source="intelligence_relationships",
                ),
            ),
        )
        relationship._emit(
            IntelligenceRelationshipObserved(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(relationship_id),
                aggregate_type="IntelligenceRelationship",
                relationship_type=relationship_type.value,
                source_entity=source_entity.key,
                target_entity=target_entity.key,
                direction=direction.value,
                confidence=confidence.value,
                epistemic_state=epistemic_state.value,
            )
        )
        return relationship

    # ── Evidence enrichment ──────────────────────────────────────────────

    def add_evidence_citation(
        self,
        tenant_id: TenantId | None,
        citation: EvidenceCitation,
        now: datetime,
        source: str = "intelligence_relationships",
    ) -> None:
        self._assert_tenant(tenant_id)
        self.evidence_citations = (*self.evidence_citations, citation)
        self._record_version(now, f"Evidence citation added: {citation.value}", source)
        self._emit(
            EvidenceCitationAdded(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.relationship_id),
                aggregate_type="IntelligenceRelationship",
                citation=citation.value,
            )
        )

    def add_source_attribution(
        self, tenant_id: TenantId | None, attribution: SourceAttribution, now: datetime
    ) -> None:
        self._assert_tenant(tenant_id)
        self.source_attributions = (*self.source_attributions, attribution)
        self._record_version(
            now,
            f"Source attribution added: {attribution.source_system}",
            attribution.source_system,
        )
        self._emit(
            SourceAttributionAdded(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.relationship_id),
                aggregate_type="IntelligenceRelationship",
                source_system=attribution.source_system,
                confidence=attribution.confidence.value,
            )
        )

    # ── Epistemic axis ───────────────────────────────────────────────────

    def transition_epistemic_state(
        self,
        tenant_id: TenantId | None,
        target: EpistemicState,
        evidence: SourceAttribution,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        EpistemicTransitionPolicy.assert_legal_transition(self.epistemic_state, target)
        previous = self.epistemic_state
        self.epistemic_state = target
        self._record_version(
            now,
            f"Epistemic state {previous.value} -> {target.value}",
            evidence.source_system,
        )
        self._emit(
            EpistemicStateTransitioned(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.relationship_id),
                aggregate_type="IntelligenceRelationship",
                from_state=previous.value,
                to_state=target.value,
            )
        )

    # ── Lifecycle axis ───────────────────────────────────────────────────

    def _transition(self, tenant_id: TenantId | None, target: RelationshipLifecycleStatus) -> None:
        self._assert_tenant(tenant_id)
        LifecycleTransitionPolicy.assert_legal_transition(self.lifecycle_status, target)
        self.lifecycle_status = target

    def deprecate(
        self, tenant_id: TenantId | None, evidence: SourceAttribution, now: datetime
    ) -> None:
        self._transition(tenant_id, RelationshipLifecycleStatus.DEPRECATED)
        self._record_version(now, "Deprecated", evidence.source_system)
        self._emit(
            IntelligenceRelationshipDeprecated(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.relationship_id),
                aggregate_type="IntelligenceRelationship",
            )
        )

    def revoke(
        self, tenant_id: TenantId | None, evidence: SourceAttribution, now: datetime
    ) -> None:
        self._transition(tenant_id, RelationshipLifecycleStatus.REVOKED)
        self._record_version(now, "Revoked", evidence.source_system)
        self._emit(
            IntelligenceRelationshipRevoked(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.relationship_id),
                aggregate_type="IntelligenceRelationship",
            )
        )

    def supersede(
        self,
        tenant_id: TenantId | None,
        by: IntelligenceRelationshipId,
        evidence: SourceAttribution,
        now: datetime,
    ) -> None:
        if by is None:
            raise MissingSupersededByError()
        self._transition(tenant_id, RelationshipLifecycleStatus.SUPERSEDED)
        self.superseded_by = by
        self._record_version(now, f"Superseded by {by}", evidence.source_system)
        self._emit(
            IntelligenceRelationshipSuperseded(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.relationship_id),
                aggregate_type="IntelligenceRelationship",
                superseded_by=str(by),
            )
        )

    def reactivate(
        self, tenant_id: TenantId | None, evidence: SourceAttribution, now: datetime
    ) -> None:
        """Legal only from `DEPRECATED` (see `LifecycleTransitionPolicy`)
        — a `REVOKED` or `SUPERSEDED` relationship is terminal/redirected
        and cannot be reactivated."""
        self._transition(tenant_id, RelationshipLifecycleStatus.ACTIVE)
        self.superseded_by = None
        self._record_version(now, "Reactivated", evidence.source_system)
        self._emit(
            IntelligenceRelationshipReactivated(
                event_id=str(uuid4()),
                occurred_at=now,
                tenant_id=_tenant_id_str(tenant_id),
                aggregate_id=str(self.relationship_id),
                aggregate_type="IntelligenceRelationship",
            )
        )
