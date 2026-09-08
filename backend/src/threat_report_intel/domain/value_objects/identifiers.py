"""Typed identifiers for threat_report_intel.

`TenantId` reuses the shared platform `EntityId` (ULID-backed) per
ADR-0005 — the same shared-kernel reuse `ioc_intelligence`,
`threat_actor_intel`, `attack_pattern_intel`, `malware_intel`,
`campaign_intel`, `tool_intel` and `infrastructure_intel` already
established.

`ThreatReportId` is deliberately an opaque UUID: it is exactly what
`intelligence_relationships`' `THREAT_REPORT_TO_*` `RelationshipType`
values (added M51.9 Phase H1) carry as their `entity_id` for the
already-defined `EntityType.THREAT_REPORT` — see the aggregate's module
docstring for the full picture.
"""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID, uuid4

from redforge.shared.identifiers import EntityId

# TenantId is the shared platform EntityId (ULID-backed) per ADR-0005.
TenantId = EntityId


@dataclass(frozen=True, slots=True)
class ThreatReportId:
    value: UUID

    def __post_init__(self) -> None:
        if self.value.int == 0:
            raise ValueError("ThreatReportId must not be nil UUID")

    @classmethod
    def generate(cls) -> ThreatReportId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)
