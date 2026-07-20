"""Degraded ACL adapters for operation Phase 2."""

from __future__ import annotations

from typing import TYPE_CHECKING

from operation.domain.ports.i_engagement_query_port import IEngagementQueryPort
from operation.domain.ports.i_vulnerability_query_port import (
    AttackSurfaceContext,
    IVulnerabilityQueryPort,
)

if TYPE_CHECKING:
    from uuid import UUID

    from operation.domain.value_objects.identifiers import EngagementId, TenantId


class DegradedEngagementQueryAdapter(IEngagementQueryPort):
    """
    Phase 2 stub: treats engagements as Active with empty scope/techniques.

    Real engagement ACL replaces this when engagement context is wired.
    Empty authorized sets cause plan validation to reject any targeted steps —
    callers in tests should inject a configured adapter.
    """

    async def get_engagement_state(
        self,
        engagement_id: EngagementId,
        tenant_id: TenantId,
    ) -> str:
        _ = (engagement_id, tenant_id)
        return "Active"

    async def is_active(
        self,
        engagement_id: EngagementId,
        tenant_id: TenantId,
    ) -> bool:
        _ = (engagement_id, tenant_id)
        return True

    async def get_authorized_targets(
        self,
        engagement_id: EngagementId,
        tenant_id: TenantId,
    ) -> set[UUID]:
        _ = (engagement_id, tenant_id)
        return set()

    async def get_allowed_techniques(
        self,
        engagement_id: EngagementId,
        tenant_id: TenantId,
    ) -> set[str]:
        _ = (engagement_id, tenant_id)
        return set()


class DegradedVulnerabilityQueryAdapter(IVulnerabilityQueryPort):
    """Degraded M27 adapter — empty attack surface for planning only."""

    async def get_attack_surface_context(
        self,
        engagement_id: EngagementId,
        tenant_id: TenantId,
    ) -> AttackSurfaceContext:
        _ = (engagement_id, tenant_id)
        return AttackSurfaceContext(
            vulnerability_instance_refs=(),
            technique_hints=(),
            degraded=True,
        )
