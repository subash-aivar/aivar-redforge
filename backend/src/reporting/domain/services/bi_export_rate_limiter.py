"""BI export rate limiting — 10 requests per tenant per window → 11th is denied."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from reporting.domain.value_objects.identifiers import TenantId

DEFAULT_LIMIT = 10
DEFAULT_WINDOW_SECONDS = 60


@dataclass
class RateLimitDecision:
    allowed: bool
    window_key: str
    request_count_in_window: int
    retry_after_seconds: int = 0


@dataclass
class BIExportRateLimiter:
    limit: int = DEFAULT_LIMIT
    window_seconds: int = DEFAULT_WINDOW_SECONDS
    _windows: dict[str, list[datetime]] = field(default_factory=dict)
    audit_log: list[dict[str, object]] = field(default_factory=list)

    def _window_key(self, tenant_id: TenantId, at: datetime) -> str:
        bucket = int(at.timestamp()) // self.window_seconds
        return f"{tenant_id}:{bucket}"

    def check(
        self,
        tenant_id: TenantId,
        *,
        actor: str,
        export_format: str,
        dataset_or_instance_ref: str,
        at: datetime | None = None,
    ) -> RateLimitDecision:
        now = at or datetime.now(UTC)
        key = self._window_key(tenant_id, now)
        stamps = self._windows.setdefault(key, [])
        cutoff = now - timedelta(seconds=self.window_seconds)
        stamps[:] = [t for t in stamps if t >= cutoff]
        count = len(stamps) + 1
        allowed = count <= self.limit
        if allowed:
            stamps.append(now)
        decision = RateLimitDecision(
            allowed=allowed,
            window_key=key,
            request_count_in_window=count,
            retry_after_seconds=0 if allowed else self.window_seconds,
        )
        self.audit_log.append(
            {
                "id": str(uuid4()),
                "tenant_id": str(tenant_id),
                "actor": actor,
                "export_format": export_format,
                "dataset_or_instance_ref": dataset_or_instance_ref,
                "allowed": allowed,
                "window_key": key,
                "request_count_in_window": count,
                "requested_at": now.isoformat(),
            }
        )
        return decision
