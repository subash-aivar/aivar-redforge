"""In-memory BI export page source — NOT a Tableau/PowerBI/Looker vendor adapter.

Implements IBIExportPort for platform-owned projection rows only (Phase 4 freeze).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from reporting.domain.value_objects.identifiers import TenantId

from reporting.domain.ports.i_bi_export_port import (
    BIExportPage,
    BIExportRequest,
    IBIExportPort,
)


class InMemoryBIExportAdapter(IBIExportPort):
    """Generic row store for BI pagination tests — vendor-agnostic."""

    def __init__(self) -> None:
        self._rows: dict[str, list[dict[str, Any]]] = {}

    def seed(self, tenant_id: TenantId, dataset_ref: str, rows: list[dict[str, Any]]) -> None:
        self._rows[f"{tenant_id}:{dataset_ref}"] = list(rows)

    async def export_page(self, request: BIExportRequest) -> BIExportPage:
        key = f"{request.tenant_id}:{request.dataset_ref}"
        all_rows = self._rows.get(key, [])
        start = max(0, (request.page - 1) * request.page_size)
        end = start + request.page_size
        page_rows = all_rows[start:end]
        return BIExportPage(
            rows=page_rows,
            page=request.page,
            page_size=request.page_size,
            total_rows=len(all_rows),
            has_more=end < len(all_rows),
        )
