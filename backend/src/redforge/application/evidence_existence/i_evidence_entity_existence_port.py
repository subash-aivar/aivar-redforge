"""IEvidenceEntityExistencePort (M51.1 Phase 4.5).

The smallest honest, read-only application port `redforge` (the owner
of `SecurityCondition` and `InvestigationCase`) can expose so an
external bounded context — `threat_actor_intel`, via its own
infrastructure/acl adapter — can ask "does entity X exist for tenant
Y" without importing `redforge`'s domain/repository/ORM types
directly and without `redforge` importing anything about the caller.

This is the resolution of the gap `threat_actor_intel.infrastructure.
acl.infrastructure_evidence_validation_adapter`'s M51.1 Phase 3
docstring explicitly flagged: "no port on the evidence/exposure/
investigations side lets an external bounded context ask this
question." `redforge` is the actual owner of both entity types (they
live in the monolith package, not a standalone bounded context), so
the smallest honest addition is here, not inside `exposure` or
`investigations` (neither of which owns this data).
"""

from __future__ import annotations

from abc import ABC, abstractmethod


class IEvidenceEntityExistencePort(ABC):
    @abstractmethod
    async def exists(self, entity_type: str, entity_id: str, organization_id: str) -> bool: ...
