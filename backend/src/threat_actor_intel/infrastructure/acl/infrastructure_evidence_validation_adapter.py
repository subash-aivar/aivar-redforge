"""InfrastructureEvidenceValidationAdapter — real, production
implementation of `IEvidenceValidationPort` (M51.1 Phase 4.5).

ADR-M51.1-08 calls for this adapter to validate a cited
`(referenced_entity_type, referenced_entity_id)` against the real
`redforge`-owned `SecurityCondition`/`InvestigationCase` data, without
`threat_actor_intel` importing `redforge`'s domain/repository/ORM
types directly. This is now real: the adapter depends only on
`redforge.application.evidence_existence.IEvidenceEntityExistencePort`
— an application-layer port, not a domain/repository/ORM import —
injected at construction time by the composition root
(`ThreatActorIntelContainer`, wired per-request with a real,
session-bound `SqlAlchemyEvidenceEntityExistenceService`).

`threat_actor_intel` never imports `redforge.domain.*` or
`redforge.infrastructure.database.*` anywhere in this file — only the
port interface. No cross-context domain/repository/ORM import, no new
event system, no shared database join; a single async method call
through a dependency-injected port, exactly the ACL pattern
`exposure.infrastructure.acl.threat_intelligence_m21_adapter` already
established for the equivalent (opposite-direction) problem.

Fail-closed by contract, inherited from the port: an unsupported
`entity_type`, a missing entity, or a cross-tenant entity all resolve
to `False` — this adapter never catches an exception from the port
and treats it as "valid"; a raised exception propagates uncaught,
which the application-service caller must also never swallow (see
`ThreatActorApplicationService.create_association`).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from threat_actor_intel.domain.ports.i_evidence_validation_port import IEvidenceValidationPort

if TYPE_CHECKING:
    from redforge.application.evidence_existence.i_evidence_entity_existence_port import (
        IEvidenceEntityExistencePort,
    )
    from threat_actor_intel.domain.value_objects.identifiers import TenantId


class InfrastructureEvidenceValidationAdapter(IEvidenceValidationPort):
    def __init__(self, entity_existence_port: IEvidenceEntityExistencePort) -> None:
        self._entity_existence = entity_existence_port

    async def validate(
        self,
        tenant_id: TenantId,
        referenced_entity_type: str,
        referenced_entity_id: str,
        evidence_citation: str,
    ) -> bool:
        del evidence_citation
        return await self._entity_existence.exists(
            entity_type=referenced_entity_type,
            entity_id=referenced_entity_id,
            organization_id=str(tenant_id),
        )
