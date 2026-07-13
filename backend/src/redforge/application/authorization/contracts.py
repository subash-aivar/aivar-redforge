"""Protocol contracts for the Security Authorization bounded context.

All collaborators injected into SecurityAuthorizationService and
ExecutionPolicyService are defined here as @runtime_checkable Protocols
— this is the seam layer, matching application/campaigns/contracts.py's
convention.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class EntityOwnershipPort(Protocol):
    """Verifies a canonical scope entity (AITarget, AIAsset, ...) is
    actually owned by the given organization before it is ever attached
    to an AuthorizationScope, and again defensively at evaluate() time.
    No display-name or substring matching — this checks real, canonical
    tenant-owned identity."""

    async def is_owned_by_organization(
        self, entity_type: str, entity_id: str, organization_id: str
    ) -> bool: ...
