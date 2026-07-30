"""RiskCorrelationRepository — an async ABC port for tenant-scoped
persistence of `RiskCorrelationSet` aggregates (M48C, converted from a
sync `Protocol` to an async `ABC` in the M48C contract correction
authorized alongside M48E — see `docs/architecture/m48/M48E_ADR.md`).
`ABC` (not `Protocol`) matches every mature bounded context's
repository port convention exactly."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

    from risk_engine.domain.aggregates.risk_correlation_set import RiskCorrelationSet
    from risk_engine.domain.value_objects.identifiers import CorrelationSetId, TenantId


class RiskCorrelationRepository(ABC):
    @abstractmethod
    async def save(self, correlation_set: RiskCorrelationSet) -> None: ...

    @abstractmethod
    async def get(
        self, tenant_id: TenantId, correlation_set_id: CorrelationSetId
    ) -> RiskCorrelationSet | None: ...

    @abstractmethod
    async def list(self, tenant_id: TenantId) -> Sequence[RiskCorrelationSet]: ...
