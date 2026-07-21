"""M30 ACL adapter — wraps M32 ExposureScopeService (Finalization D4)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from campaign.domain.ports.i_exposure_scope_query_port import (
    ExposureScopeRequest,
    ExposureScopeResponse,
    IExposureScopeQueryPort,
    ScopedAsset,
)

if TYPE_CHECKING:
    from exposure.application.services.exposure_scope_service import ExposureScopeService


class ExposureScopeM32Adapter(IExposureScopeQueryPort):
    """In-process adapter translating M32 scope dicts → M30 DTOs."""

    def __init__(
        self,
        scope_service: ExposureScopeService,
        *,
        actor_roles: tuple[str, ...] = ("exposure:viewer",),
    ) -> None:
        self._scope = scope_service
        self._actor_roles = actor_roles

    async def query_scope(self, request: ExposureScopeRequest) -> ExposureScopeResponse:
        raw = await self._scope.query_scope(
            tenant_id=request.tenant_id,
            actor_roles=self._actor_roles,
            max_assets=request.max_assets,
            min_exposure_score=request.min_exposure_score,
            amplifier_filter=list(request.amplifier_filter),
            asset_kind_filter=list(request.asset_kind_filter),
            include_stale_scores=request.include_stale_scores,
        )
        assets_raw = raw.get("assets", [])
        assets: list[ScopedAsset] = []
        if isinstance(assets_raw, list):
            for row in assets_raw:
                if not isinstance(row, dict):
                    continue
                dominant = row.get("dominant_amplifiers", [])
                assets.append(
                    ScopedAsset(
                        asset_ref_id=str(row.get("asset_ref_id", "")),
                        exposure_score=float(row.get("exposure_score", 0.0)),
                        dominant_amplifiers=tuple(
                            str(x) for x in dominant if isinstance(dominant, list)
                        ),
                        business_criticality=(
                            str(row["business_criticality"])
                            if row.get("business_criticality") is not None
                            else None
                        ),
                        snapshot_computed_at=str(row.get("snapshot_computed_at", "")),
                        is_score_stale=bool(row.get("is_score_stale", False)),
                    )
                )
        total_eligible_raw = raw.get("total_eligible", 0)
        duration_raw = raw.get("query_duration_ms", 0)
        total_eligible = (
            int(total_eligible_raw) if isinstance(total_eligible_raw, (int, float, str)) else 0
        )
        query_duration_ms = int(duration_raw) if isinstance(duration_raw, (int, float, str)) else 0
        return ExposureScopeResponse(
            tenant_id=str(raw.get("tenant_id", request.tenant_id)),
            assets=tuple(assets),
            total_eligible=total_eligible,
            score_version=str(raw.get("score_version", "0")),
            queried_at=str(raw.get("queried_at", "")),
            has_stale_scores=bool(raw.get("has_stale_scores", False)),
            query_duration_ms=query_duration_ms,
        )
