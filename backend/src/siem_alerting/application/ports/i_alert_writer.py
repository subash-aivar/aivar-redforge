"""IAlertWriter — the Alert Engine's one outbound port.

`AlertApplicationService` never persists an `Alert` itself; handing the
newly-raised/suppressed/deduplicated aggregate to whatever implements
this port is the last thing it does with it. No implementation lives
in this milestone.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from siem_alerting.domain.aggregates.alert import Alert


class IAlertWriter(Protocol):
    def write(self, alert: Alert) -> None: ...
