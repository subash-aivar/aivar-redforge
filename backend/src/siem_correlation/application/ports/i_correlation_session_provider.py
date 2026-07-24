"""ICorrelationSessionProvider — the Correlation Engine's one inbound
port for loading an in-flight `CorrelationSession` (M44B §2's "Load
CorrelationSession").

No persistence, no repository implementation lives in this milestone —
`CorrelationApplicationService` never queries a database itself; it
asks this port for the tenant's currently open session for a given
correlation rule (if one exists) and accumulates into exactly that one,
per M37 §12's session-partitioning-by-(tenant, rule) scalability rule.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from redforge.shared.identifiers import EntityId
    from siem_correlation.domain.aggregates.correlation_session import CorrelationSession


class ICorrelationSessionProvider(Protocol):
    def find_open_session(
        self, tenant_id: EntityId, correlation_rule_id: str
    ) -> CorrelationSession | None: ...
