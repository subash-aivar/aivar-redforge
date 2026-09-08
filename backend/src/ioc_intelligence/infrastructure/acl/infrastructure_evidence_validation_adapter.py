"""InfrastructureEvidenceValidationAdapter — real, production
implementation of `IIocEvidenceValidationPort` (M51.2 Phase A3),
reusing the exact proven pattern `threat_actor_intel.infrastructure.
acl.infrastructure_evidence_validation_adapter.
InfrastructureEvidenceValidationAdapter` already established: depend
only on `redforge.application.evidence_existence.
IEvidenceEntityExistencePort` — an application-layer port, never
`redforge`'s domain/repository/ORM types directly — injected at
construction by the composition root (`IocIntelContainer`, wired
per-request with a real, session-bound
`SqlAlchemyEvidenceEntityExistenceService`).

`IIocEvidenceValidationPort.validate` takes a bare `evidence_citation`
string (`EvidenceCitation`'s domain shape has no separate entity-type
field, unlike `threat_actor_intel`'s `(referenced_entity_type,
referenced_entity_id)` pair). This adapter's documented citation
format is therefore `"{entity_type}:{entity_id}"` — e.g.
`"InvestigationCase:INV-2026-0142"` — where `entity_type` must be one
of `SqlAlchemyEvidenceEntityExistenceService.SUPPORTED_ENTITY_TYPES`.
A citation that doesn't parse into that shape, or names an
unsupported entity type, fails closed (`False`) — never an exception
swallowed into "valid", and never a silent partial match.

`ioc_intelligence` never imports `redforge.domain.*` or
`redforge.infrastructure.database.*` anywhere in this file — only the
port interface. Fail-closed by contract: an exception raised by the
port propagates uncaught; the application-service caller must also
never swallow it."""

from __future__ import annotations

from typing import TYPE_CHECKING

from ioc_intelligence.application.ports.i_ioc_evidence_validation_port import (
    IIocEvidenceValidationPort,
)

if TYPE_CHECKING:
    from ioc_intelligence.domain.value_objects.identifiers import TenantId
    from redforge.application.evidence_existence.i_evidence_entity_existence_port import (
        IEvidenceEntityExistencePort,
    )


class InfrastructureEvidenceValidationAdapter(IIocEvidenceValidationPort):
    def __init__(self, entity_existence_port: IEvidenceEntityExistencePort) -> None:
        self._entity_existence = entity_existence_port

    async def validate(self, tenant_id: TenantId, evidence_citation: str) -> bool:
        entity_type, separator, entity_id = evidence_citation.partition(":")
        if not separator or not entity_type or not entity_id:
            return False
        return await self._entity_existence.exists(
            entity_type=entity_type,
            entity_id=entity_id,
            organization_id=str(tenant_id),
        )
