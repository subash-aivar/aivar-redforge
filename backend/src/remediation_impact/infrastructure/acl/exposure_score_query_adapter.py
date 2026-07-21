"""ACL adapter — reads asset scores via exposure InMemory UoW / profile."""

from __future__ import annotations

from typing import TYPE_CHECKING

from remediation_impact.application.ports.i_exposure_score_query_port import (
    IExposureScoreQueryPort,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from uuid import UUID

    from exposure.application.ports.i_unit_of_work import IUnitOfWork


class ExposureScoreQueryAdapter(IExposureScoreQueryPort):
    """In-process adapter for composition-root wiring (tests / single process)."""

    def __init__(self, uow_factory: Callable[[], IUnitOfWork]) -> None:
        self._uow_factory = uow_factory

    async def get_asset_scores(self, tenant_id: UUID) -> dict[str, float]:
        from exposure.domain.value_objects.identifiers import TenantId as ExpTenantId

        async with self._uow_factory() as uow:
            profile = await uow.profiles.load(ExpTenantId(tenant_id))
            return dict(profile.asset_scores)

    async def get_score_input_version(self, tenant_id: UUID) -> int:
        from exposure.domain.value_objects.identifiers import TenantId as ExpTenantId

        async with self._uow_factory() as uow:
            cfg = await uow.weights.find_current(ExpTenantId(tenant_id))
            return int(cfg.version) if cfg else 1


class StaticExposureScoreQueryAdapter(IExposureScoreQueryPort):
    """Seedable stub for unit tests without exposure UoW."""

    def __init__(
        self,
        scores: dict[str, float] | None = None,
        version: int = 1,
    ) -> None:
        self._scores = scores or {}
        self._version = version

    async def get_asset_scores(self, tenant_id: UUID) -> dict[str, float]:
        del tenant_id
        return dict(self._scores)

    async def get_score_input_version(self, tenant_id: UUID) -> int:
        del tenant_id
        return self._version
