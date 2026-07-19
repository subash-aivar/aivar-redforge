"""Audit log query dataclasses (CQRS read side)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime  # noqa: TC003 — runtime type for frozen dataclass fields
from uuid import UUID  # noqa: TC003 — runtime type for frozen dataclass fields


@dataclass(frozen=True, slots=True)
class ListAuditEntriesQuery:
    tenant_id: UUID
    credential_id: UUID
    principal_id: UUID
    since: datetime | None = None
    operations: list[str] | None = None
    limit: int = 100
    offset: int = 0
