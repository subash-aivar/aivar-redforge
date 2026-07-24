"""In-memory analytics event projection store + idempotency (Phase 1)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from analytics.domain.value_objects.identifiers import TenantId

DOMAIN_TABLES = (
    "vulnerability",
    "detection",
    "execution",
    "campaign",
    "exposure",
    "ai_posture",
)


@dataclass
class EventProjectionStore:
    """Idempotent projection engine backing AnalyticsProjectionWorker."""

    events: dict[str, dict[str, list[dict[str, Any]]]] = field(default_factory=dict)
    processed: dict[str, set[str]] = field(default_factory=dict)
    kpi_snapshots: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    anomalies: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    checkpoints: dict[str, dict[str, str]] = field(default_factory=dict)

    def _tenant_bucket(self, tenant_id: TenantId) -> dict[str, list[dict[str, Any]]]:
        key = str(tenant_id)
        if key not in self.events:
            self.events[key] = {d: [] for d in DOMAIN_TABLES}
            self.processed[key] = set()
            self.kpi_snapshots[key] = []
            self.anomalies[key] = []
            self.checkpoints[key] = {}
        return self.events[key]

    def already_processed(self, tenant_id: TenantId, event_id: str) -> bool:
        self._tenant_bucket(tenant_id)
        return event_id in self.processed[str(tenant_id)]

    def ingest(
        self,
        tenant_id: TenantId,
        *,
        domain: str,
        event_id: str,
        event_type: str,
        event_ts: datetime,
        payload: dict[str, Any],
    ) -> bool:
        bucket = self._tenant_bucket(tenant_id)
        tid = str(tenant_id)
        if event_id in self.processed[tid]:
            return False
        if domain not in bucket:
            raise ValueError(f"unknown domain: {domain}")
        row = {
            "event_id": event_id,
            "tenant_id": tid,
            "event_type": event_type,
            "event_ts": event_ts,
            "payload": dict(payload),
            "ingested_at": datetime.now(UTC),
            "archived": False,
            **{k: v for k, v in payload.items() if k != "payload"},
        }
        bucket[domain].append(row)
        self.processed[tid].add(event_id)
        self.checkpoints[tid][domain] = event_id
        return True

    def list_events(
        self, tenant_id: TenantId, domain: str, *, include_archived: bool = False
    ) -> list[dict[str, Any]]:
        bucket = self._tenant_bucket(tenant_id)
        rows = bucket.get(domain, [])
        if include_archived:
            return list(rows)
        return [r for r in rows if not r.get("archived")]

    def all_domain_events(self, tenant_id: TenantId) -> dict[str, list[dict[str, Any]]]:
        return {d: self.list_events(tenant_id, d) for d in DOMAIN_TABLES}

    def clear_domain(self, tenant_id: TenantId, domain: str) -> int:
        bucket = self._tenant_bucket(tenant_id)
        n = len(bucket.get(domain, []))
        bucket[domain] = []
        return n

    def append_kpi_snapshot(self, tenant_id: TenantId, snapshot: dict[str, Any]) -> None:
        self._tenant_bucket(tenant_id)
        self.kpi_snapshots[str(tenant_id)].append(snapshot)

    def list_kpi_snapshots(
        self, tenant_id: TenantId, kpi_type: str | None = None
    ) -> list[dict[str, Any]]:
        self._tenant_bucket(tenant_id)
        rows = self.kpi_snapshots[str(tenant_id)]
        if kpi_type:
            return [r for r in rows if r.get("kpi_type") == kpi_type]
        return list(rows)

    def append_anomaly(self, tenant_id: TenantId, anomaly: dict[str, Any]) -> None:
        self._tenant_bucket(tenant_id)
        self.anomalies[str(tenant_id)].append(anomaly)

    def list_anomalies(self, tenant_id: TenantId) -> list[dict[str, Any]]:
        self._tenant_bucket(tenant_id)
        return list(self.anomalies[str(tenant_id)])

    def mark_archived_before(self, tenant_id: TenantId, domain: str, before: datetime) -> int:
        count = 0
        for row in self._tenant_bucket(tenant_id).get(domain, []):
            ts = row.get("event_ts")
            if isinstance(ts, datetime) and ts < before and not row.get("archived"):
                row["archived"] = True
                count += 1
        return count
