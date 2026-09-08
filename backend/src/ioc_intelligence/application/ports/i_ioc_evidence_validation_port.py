"""IIocEvidenceValidationPort — the evidence-trust ACL seam for
ioc_intelligence (M51.2 Phase A2), mirroring `threat_actor_intel.
domain.ports.i_evidence_validation_port.IEvidenceValidationPort`'s
established contract and fail-closed discipline.

Validates that a tenant-supplied evidence citation actually resolves
to a real, tenant-owned evidence record before it is ever attached to
an IOC. `ioc_intelligence` never imports `exposure`/`investigations`/
`evidence` domain modules to perform this check itself — a concrete
adapter (a later phase) implements this port by calling out to those
contexts' own read APIs/ports.

Fail-closed by contract: a `False` result, or an exception raised by a
concrete implementation, must both result in the mutation being
rejected — `IOCApplicationService` must never catch and proceed past
either outcome."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ioc_intelligence.domain.value_objects.identifiers import TenantId


class IIocEvidenceValidationPort(ABC):
    @abstractmethod
    async def validate(self, tenant_id: TenantId, evidence_citation: str) -> bool: ...
