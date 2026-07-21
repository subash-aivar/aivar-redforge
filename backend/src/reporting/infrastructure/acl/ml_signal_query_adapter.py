"""IMLSignalQueryPort adapters — stub + seedable in-memory (no ml_pipeline.domain imports)."""

from __future__ import annotations

from typing import TYPE_CHECKING

from reporting.domain.ports.i_ml_signal_query_port import (
    IMLSignalQueryPort,
    MLSignalBundleDTO,
)

if TYPE_CHECKING:
    from uuid import UUID


class StubMLSignalQueryAdapter(IMLSignalQueryPort):
    """Cold-start default: no deployed model / empty signals."""

    def __init__(self) -> None:
        self._by_tenant: dict[str, MLSignalBundleDTO] = {}

    def seed(self, tenant_id: UUID, bundle: MLSignalBundleDTO) -> None:
        self._by_tenant[str(tenant_id)] = bundle

    async def load_active_signals(self, tenant_id: UUID) -> MLSignalBundleDTO:
        return self._by_tenant.get(
            str(tenant_id), MLSignalBundleDTO(signals=(), model_deployed=False)
        )


class InMemoryMLSignalQueryAdapter(StubMLSignalQueryAdapter):
    """Alias for Phase 4/5 integration tests."""
