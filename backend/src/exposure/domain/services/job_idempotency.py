"""Score recomputation job_id derivation (Finalization D2)."""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta
from uuid import UUID

DEBOUNCE_WINDOW = timedelta(minutes=5)


def dispatch_window_bucket(dispatched_at: datetime) -> datetime:
    epoch = int(dispatched_at.timestamp())
    window = int(DEBOUNCE_WINDOW.total_seconds())
    bucket = (epoch // window) * window
    return datetime.fromtimestamp(bucket, tz=dispatched_at.tzinfo)


def derive_job_id(tenant_id: UUID, asset_ref_id: UUID, dispatched_at: datetime) -> str:
    bucket = dispatch_window_bucket(dispatched_at)
    raw = f"{tenant_id}:{asset_ref_id}:{bucket.isoformat()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
