"""IEvidenceValidationPort — ADR-M51.1-08's evidence-trust ACL seam.

Validates that a tenant-supplied `(referenced_entity_type,
referenced_entity_id)` cited by a `ThreatActorAssociation` actually
resolves to a real entity owned by the calling tenant, before the
association is ever created. `threat_actor_intel` never imports
`exposure`/`investigations`/`evidence` domain modules to perform this
check itself — a concrete adapter (Phase 3+) implements this port by
calling out to those contexts' own read APIs/ports.

Fail-closed by contract: a `False` result, or an exception raised by
a concrete implementation, must both result in the association being
rejected — the application-service caller must never catch and
proceed past either outcome (see `ThreatActorApplicationService.
create_association`)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from threat_actor_intel.domain.value_objects.identifiers import TenantId


class IEvidenceValidationPort(ABC):
    @abstractmethod
    async def validate(
        self,
        tenant_id: TenantId,
        referenced_entity_type: str,
        referenced_entity_id: str,
        evidence_citation: str,
    ) -> bool: ...
