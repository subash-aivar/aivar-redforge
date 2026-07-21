from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from types import TracebackType

    from ai_agent_governance.domain.repositories.i_agent_deviation_event_repository import (
        IAgentDeviationEventRepository,
    )
    from ai_agent_governance.domain.repositories.i_agent_operational_envelope_repository import (
        IAgentOperationalEnvelopeRepository,
    )


class IUnitOfWork(ABC):
    envelopes: IAgentOperationalEnvelopeRepository
    deviations: IAgentDeviationEventRepository

    def __init__(self) -> None:
        self._committed = False

    @abstractmethod
    async def commit(self) -> None: ...

    @abstractmethod
    async def rollback(self) -> None: ...

    @abstractmethod
    async def __aenter__(self) -> IUnitOfWork: ...

    @abstractmethod
    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None: ...
