"""AssociationUniquenessPolicy — enforces the platform-wide invariant
that exactly one `ACTIVE` `ThreatActorAssociation` may exist for a
given `(tenant_id, threat_actor_id, referenced_entity_type,
referenced_entity_id)` tuple (M51.1).

This invariant spans multiple aggregate instances, so no single
`ThreatActorAssociation` can enforce it alone (mirrors why
`ActivityLifecyclePolicy` and `AttributionConfidencePolicy` are
standalone policies rather than inlined `if` checks — but here the
reason is breadth of state, not reuse). A caller (the future
application-layer use case, Phase 2) must supply the candidate
tuple's already-tenant/actor/entity-filtered set of existing
associations; this policy does not itself know how to query a
repository.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from threat_actor_intel.domain.exceptions.domain_exceptions import (
    DuplicateActiveAssociationError,
)

if TYPE_CHECKING:
    from collections.abc import Iterable

    from threat_actor_intel.domain.aggregates.threat_actor_association import (
        ThreatActorAssociation,
    )
    from threat_actor_intel.domain.value_objects.identifiers import TenantId, ThreatActorId
    from threat_actor_intel.domain.value_objects.references import ReferencedEntityRef


class AssociationUniquenessPolicy:
    @staticmethod
    def assert_no_active_duplicate(
        existing: Iterable[ThreatActorAssociation],
        tenant_id: TenantId,
        threat_actor_id: ThreatActorId,
        referenced_entity: ReferencedEntityRef,
    ) -> None:
        for candidate in existing:
            if (
                candidate.is_active()
                and candidate.tenant_id == tenant_id
                and candidate.threat_actor_id == threat_actor_id
                and candidate.referenced_entity == referenced_entity
            ):
                raise DuplicateActiveAssociationError(
                    threat_actor_id=str(threat_actor_id),
                    entity_type=referenced_entity.entity_type,
                    entity_id=referenced_entity.entity_id,
                )
