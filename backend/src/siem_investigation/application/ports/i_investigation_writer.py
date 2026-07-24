"""IInvestigationWriter — the Investigation Engine's one outbound port.

`InvestigationApplicationService` never persists an
`InvestigationTimeline` itself; handing the created/updated aggregate
to whatever implements this port is the last thing it does with it. No
implementation lives in this milestone.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from siem_investigation.domain.aggregates.investigation_timeline import InvestigationTimeline


class IInvestigationWriter(Protocol):
    def write(self, timeline: InvestigationTimeline) -> None: ...
