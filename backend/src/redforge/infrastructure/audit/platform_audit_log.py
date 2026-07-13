"""PostgreSQL-backed audit log for platform privilege events.

Implements the existing `AuditLog` protocol (contracts.py) rather than
inventing a second audit abstraction. Prior to this, only
`InMemoryAuditLog` (tests) and `StructlogAuditLog` (stdout JSON, not
queryable) existed — neither backs a queryable `GET /platform/audit`
endpoint, so this adds the first queryable implementation, scoped to
platform events specifically (not a general-purpose replacement for
StructlogAuditLog's broader AuditAction coverage).

Honest terminology: "append-only" here means the repository exposes no
update/delete method — it is an application-level convention, not a
cryptographically-immutable ledger. No stronger claim is made.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from sqlalchemy import select

from redforge.infrastructure.audit.contracts import AuditAction, AuditEntry
from redforge.infrastructure.database.models.platform_identity import (
    PlatformAuditLogModel,
)
from redforge.shared.identifiers import EntityId

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class PostgresPlatformAuditLog:
    """Append-only-by-convention platform audit log, backed by
    `platform_audit_log`. Does not commit — caller's UnitOfWork owns
    the transaction, so a bootstrap/grant/revoke and its audit record
    are written atomically in the same transaction.
    """

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def record(self, entry: AuditEntry) -> None:
        model = PlatformAuditLogModel(
            id=str(EntityId.generate()),
            action=entry.action.value,
            actor_id=entry.actor_id,
            target_id=entry.resource_id,
            role=entry.metadata.get("role"),
            outcome=str(entry.metadata.get("outcome", "success")),
            correlation_id=entry.correlation_id,
            metadata_json=json.dumps(entry.metadata),
            created_at=entry.timestamp,
        )
        self._session.add(model)
        await self._session.flush()

    async def query(
        self,
        *,
        actor_id: str | None = None,
        resource_type: str | None = None,
        resource_id: str | None = None,
        action: AuditAction | None = None,
        since: object = None,
        limit: int = 100,
    ) -> list[AuditEntry]:
        stmt = select(PlatformAuditLogModel).order_by(
            PlatformAuditLogModel.created_at.desc()
        )
        if actor_id is not None:
            stmt = stmt.where(PlatformAuditLogModel.actor_id == actor_id)
        if action is not None:
            stmt = stmt.where(PlatformAuditLogModel.action == action.value)
        stmt = stmt.limit(limit)

        result = await self._session.execute(stmt)
        entries = []
        for model in result.scalars().all():
            metadata = json.loads(model.metadata_json) if model.metadata_json else {}
            metadata.setdefault("role", model.role)
            metadata.setdefault("outcome", model.outcome)
            entries.append(
                AuditEntry(
                    action=AuditAction(model.action),
                    actor_id=model.actor_id,
                    resource_type="platform_assignment",
                    resource_id=model.target_id,
                    timestamp=model.created_at,
                    correlation_id=model.correlation_id,
                    metadata=metadata,
                )
            )
        return entries
