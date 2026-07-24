"""IDetectionRuleProvider — the Detection Engine's one inbound port for
loading `DetectionRule` aggregates (M44A §2's "loading DetectionRule").

No persistence, no repository implementation lives in this milestone —
`DetectionApplicationService` never queries a database itself; it asks
this port for the tenant's currently active rules and evaluates the
event against exactly those.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Sequence

    from redforge.shared.identifiers import EntityId
    from siem_detection.domain.aggregates.detection_rule import DetectionRule


class IDetectionRuleProvider(Protocol):
    def get_rules(self, tenant_id: EntityId) -> Sequence[DetectionRule]:
        """Every rule registered for `tenant_id`, in any lifecycle state
        — `DetectionApplicationService` filters for `ACTIVE` itself
        (M44A §7's "rule enabled state" validation), so a `DRAFT` or
        `DEPRECATED` rule handed back here becomes a `RULE_DISABLED`
        outcome rather than being silently omitted."""
        ...
