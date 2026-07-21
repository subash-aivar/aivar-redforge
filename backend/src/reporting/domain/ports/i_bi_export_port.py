"""IBIExportPort — abstract BI connector (Tableau/Power BI/Looker).

ADR / Phase 4 freeze: interface only in M33 — no vendor-specific implementations.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from uuid import UUID


@dataclass(frozen=True, slots=True)
class BIExportRequest:
    tenant_id: UUID
    dataset_ref: str
    page: int
    page_size: int
    actor: str


@dataclass(frozen=True, slots=True)
class BIExportPage:
    rows: list[dict[str, Any]]
    page: int
    page_size: int
    total_rows: int
    has_more: bool


class IBIExportPort(ABC):
    """Vendor-agnostic BI export contract. M33 ships no Tableau/PowerBI/Looker adapters."""

    @abstractmethod
    async def export_page(self, request: BIExportRequest) -> BIExportPage: ...
