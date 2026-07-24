"""Background worker entrypoint for projection rebuild / repair."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ai_posture.domain.value_objects.identifiers import TenantId

if TYPE_CHECKING:

    from ai_posture.application.projections.rebuild_service import ProjectionRebuildService


async def run_projection_rebuild(
    rebuild_service: ProjectionRebuildService,
    tenant_id: TenantId,
    actor_roles: tuple[str, ...],
) -> dict[str, Any]:
    from ai_posture.infrastructure.observability.metrics import METRICS

    result = await rebuild_service.rebuild_tenant(tenant_id, actor_roles)
    METRICS.projection_rebuild_total += 1
    return result
