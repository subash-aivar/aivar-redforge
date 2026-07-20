"""Batch / pagination helpers for platform orchestration.

Batch orchestration reuses the same pipeline per account — no N+1 health
queries: callers should pass a shared session for table-count checks.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from uuid import UUID


@dataclass(frozen=True, slots=True)
class BatchOrchestrationPlan:
    """Documented plan for organization-wide account orchestration."""

    organization_id: str
    account_ids: tuple[UUID, ...]
    fail_fast: bool = False
    include_k8s: bool = False
    include_runtime: bool = False

    @property
    def batch_size(self) -> int:
        return len(self.account_ids)


def paginate_offset(*, page: int, size: int) -> tuple[int, int]:
    """Return (limit, offset) clamped for list-runs queries."""
    safe_page = max(1, page)
    safe_size = max(1, min(size, 200))
    return safe_size, (safe_page - 1) * safe_size


def chunk_ids(ids: list[UUID], *, chunk_size: int = 25) -> list[list[UUID]]:
    """Split account/asset id lists into bounded chunks for batch runs."""
    size = max(1, min(chunk_size, 100))
    return [ids[i : i + size] for i in range(0, len(ids), size)]


def merge_diagnostics(*parts: dict[str, Any]) -> dict[str, Any]:
    """Shallow-merge diagnostic dicts (later keys win)."""
    out: dict[str, Any] = {}
    for part in parts:
        out.update(part)
    return out
