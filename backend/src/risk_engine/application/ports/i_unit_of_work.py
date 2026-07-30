"""IUnitOfWork — transactional boundary for risk_engine application
services (M48C), aligned to the platform-wide convention used by
`operation`, `exposure`, `credential_vault`, `campaign`, and every
other mature bounded context: an `ABC` with async
`commit`/`rollback`/`__aenter__`/`__aexit__`, bundling the context's
own repository ports as attributes rather than passing them
separately. No implementation lives in `src/` at this milestone —
only the contract.

Subclasses must call ``super().__init__()`` so ``_committed`` is
initialized. Concrete ``commit()`` implementations must call
``super().commit()`` (or set ``self._committed = True``) after a
successful commit — matching `credential_vault`'s `IUnitOfWork`
precedent exactly.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from types import TracebackType

    from risk_engine.application.ports.i_risk_correlation_repository import (
        RiskCorrelationRepository,
    )
    from risk_engine.application.ports.i_risk_profile_repository import (
        EnterpriseRiskProfileRepository,
    )


class IUnitOfWork(ABC):
    risk_profiles: EnterpriseRiskProfileRepository
    correlation_sets: RiskCorrelationRepository

    def __init__(self) -> None:
        self._committed = False

    async def __aenter__(self) -> IUnitOfWork:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if not self._committed:
            await self.rollback()

    @abstractmethod
    async def commit(self) -> None:
        """Persist all changes in the unit of work."""
        self._committed = True

    @abstractmethod
    async def rollback(self) -> None:
        """Discard all uncommitted changes in the unit of work."""
