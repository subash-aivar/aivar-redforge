"""Operational metrics + worker health (Phase 5)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4


@dataclass
class OperationalMetricsStore:
    metrics: list[dict[str, Any]] = field(default_factory=list)
    worker_health: dict[str, dict[str, Any]] = field(default_factory=dict)

    def record(
        self,
        metric_name: str,
        value: float,
        *,
        unit: str = "count",
        tenant_id: UUID | None = None,
        labels: dict[str, str] | None = None,
    ) -> None:
        self.metrics.append(
            {
                "id": str(uuid4()),
                "tenant_id": str(tenant_id) if tenant_id else None,
                "metric_name": metric_name,
                "metric_value": value,
                "unit": unit,
                "labels": labels or {},
                "recorded_at": datetime.now(UTC).isoformat(),
            }
        )

    def mark_worker(self, worker_name: str, *, ok: bool, error: str | None = None) -> None:
        row = self.worker_health.setdefault(
            worker_name,
            {
                "worker_name": worker_name,
                "status": "unknown",
                "last_success_at": None,
                "last_error": None,
                "success_count": 0,
                "failure_count": 0,
                "updated_at": datetime.now(UTC).isoformat(),
            },
        )
        now = datetime.now(UTC).isoformat()
        if ok:
            row["status"] = "healthy"
            row["last_success_at"] = now
            row["success_count"] = int(row["success_count"]) + 1
            row["last_error"] = None
        else:
            row["status"] = "degraded"
            row["failure_count"] = int(row["failure_count"]) + 1
            row["last_error"] = error
        row["updated_at"] = now

    def snapshot(self) -> dict[str, Any]:
        return {
            "metrics": list(self.metrics[-100:]),
            "workers": list(self.worker_health.values()),
        }
