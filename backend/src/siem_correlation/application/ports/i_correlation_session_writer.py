"""ICorrelationSessionWriter — the Correlation Engine's one outbound
port.

`CorrelationApplicationService` never persists a `CorrelationSession`
itself; handing the mutated aggregate to whatever implements this port
is the last thing it does with it after accumulate/match/expire. No
implementation lives in this milestone.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from siem_correlation.domain.aggregates.correlation_session import CorrelationSession


class ICorrelationSessionWriter(Protocol):
    def write(self, session: CorrelationSession) -> None: ...
