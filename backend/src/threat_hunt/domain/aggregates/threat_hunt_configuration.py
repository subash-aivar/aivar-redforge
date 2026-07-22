from __future__ import annotations

from dataclasses import dataclass, field

from threat_hunt.domain.value_objects.identifiers import TenantId


@dataclass
class ThreatHuntConfiguration:
    tenant_id: TenantId
    min_signal_strength: float = 0.5
    enabled_signal_types: list[str] = field(default_factory=lambda: ["anomaly", "beaconing"])

    @classmethod
    def default(cls, tenant_id: TenantId) -> ThreatHuntConfiguration:
        return cls(tenant_id)
