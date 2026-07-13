"""Concrete EntityOwnershipPort backed by the existing canonical entity
services (AITargetService for ScopeEntityType.AI_TARGET,
TenantAssetService for ScopeEntityType.AI_ASSET).

This is the ONLY place that decides whether a scope entity is real and
tenant-owned — both authorization-scope creation and
ExecutionPolicyService.evaluate() go through the same check, so there
is exactly one answer to "does this entity belong to this org".
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from redforge.core.exceptions import NotFoundError
from redforge.domain.ai_targets.exceptions import TargetNotFoundError

if TYPE_CHECKING:
    from redforge.application.ai_targets import AITargetService
    from redforge.application.inventory.tenant_asset_service import TenantAssetService


class TenantEntityOwnershipChecker:
    def __init__(
        self, ai_target_service: AITargetService, tenant_asset_service: TenantAssetService,
    ) -> None:
        self._ai_target_service = ai_target_service
        self._tenant_asset_service = tenant_asset_service

    async def is_owned_by_organization(
        self, entity_type: str, entity_id: str, organization_id: str
    ) -> bool:
        try:
            if entity_type == "ai_target":
                await self._ai_target_service.get_by_id(entity_id, organization_id)
                return True
            if entity_type == "ai_asset":
                await self._tenant_asset_service.get_for_org(entity_id, organization_id)
                return True
        except (NotFoundError, TargetNotFoundError):
            return False
        except ValueError:
            # Malformed EntityId string — not a valid canonical entity.
            return False
        return False
