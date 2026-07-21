"""ThreatActorMatchCache — per-tenant projection (Finalization D3)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID

STALE_AFTER = timedelta(hours=48)


@dataclass(slots=True)
class ThreatActorMatchCache:
    tenant_id: UUID
    entries: dict[str, list[str]] = field(default_factory=dict)  # cve → actors
    asset_class_entries: dict[str, list[str]] = field(default_factory=dict)
    technique_entries: dict[str, list[str]] = field(default_factory=dict)  # ATT&CK/TTP
    ioc_entries: dict[str, list[str]] = field(default_factory=dict)
    last_event_update_at: datetime | None = None
    last_poll_update_at: datetime | None = None

    def is_stale(self, now: datetime | None = None) -> bool:
        now = now or datetime.now(UTC)
        latest: datetime | None = None
        for ts in (self.last_event_update_at, self.last_poll_update_at):
            if ts is None:
                continue
            if latest is None or ts > latest:
                latest = ts
        if latest is None:
            return True
        return (now - latest) > STALE_AFTER

    def apply_targeting(
        self,
        *,
        threat_actor_ref: str,
        cve_ids: list[str],
        asset_classes: list[str],
        techniques: list[str] | None = None,
        iocs: list[str] | None = None,
        at: datetime,
        from_event: bool,
    ) -> None:
        for cve in cve_ids:
            actors = self.entries.setdefault(cve, [])
            if threat_actor_ref not in actors:
                actors.append(threat_actor_ref)
        for cls in asset_classes:
            actors = self.asset_class_entries.setdefault(cls, [])
            if threat_actor_ref not in actors:
                actors.append(threat_actor_ref)
        for tech in techniques or []:
            actors = self.technique_entries.setdefault(tech, [])
            if threat_actor_ref not in actors:
                actors.append(threat_actor_ref)
        for ioc in iocs or []:
            actors = self.ioc_entries.setdefault(ioc, [])
            if threat_actor_ref not in actors:
                actors.append(threat_actor_ref)
        if from_event:
            self.last_event_update_at = at
        else:
            self.last_poll_update_at = at

    def actors_for_record(self, *, cve_ids: list[str], asset_classes: list[str]) -> list[str]:
        found: set[str] = set()
        for cve in cve_ids:
            found.update(self.entries.get(cve, []))
        for cls in asset_classes:
            found.update(self.asset_class_entries.get(cls, []))
        return sorted(found)

    def to_dict(self) -> dict[str, object]:
        return {
            "tenant_id": str(self.tenant_id),
            "entries": {k: list(v) for k, v in self.entries.items()},
            "asset_class_entries": {k: list(v) for k, v in self.asset_class_entries.items()},
            "technique_entries": {k: list(v) for k, v in self.technique_entries.items()},
            "ioc_entries": {k: list(v) for k, v in self.ioc_entries.items()},
            "last_event_update_at": (
                self.last_event_update_at.isoformat() if self.last_event_update_at else None
            ),
            "last_poll_update_at": (
                self.last_poll_update_at.isoformat() if self.last_poll_update_at else None
            ),
            "is_stale": self.is_stale(),
        }
