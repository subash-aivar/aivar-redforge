"""PostgreSQL-backed audit log for organization-scoped RBAC
administrative events — M17.

Deliberately NOT the same table/class as `PostgresPlatformAuditLog`
(M1): that log is platform-wide and has no organization_id column at
all — mixing tenant-scoped events into it would either force a nullable
organization_id (silently unsafe to query "is this leaking cross-
tenant?") or bloat a platform-wide table with per-tenant volume. This
adapter is intentionally tenant-scoped from its own dedicated table
(`organization_admin_audit_log`, migration 0026) and every query is
mandatorily filtered by organization_id — there is no method that can
return another tenant's rows.

Honest terminology: "append-only" here means the repository exposes no
update/delete method — an application-level convention, not a
cryptographically-immutable ledger. Same disclosure as the platform
audit log (no stronger claim made here either).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from sqlalchemy import select

from redforge.infrastructure.audit.contracts import AuditAction
from redforge.infrastructure.database.models.rbac import OrganizationAdminAuditLogModel
from redforge.shared.identifiers import EntityId
from redforge.shared.timestamps import utc_now

if TYPE_CHECKING:
    from datetime import datetime

    from sqlalchemy.ext.asyncio import AsyncSession


@dataclass(frozen=True, slots=True)
class OrganizationAdminAuditEntry:
    organization_id: str
    actor_id: str
    action: str
    target_type: str
    target_id: str
    metadata: dict[str, Any]
    occurred_at: datetime


class PostgresOrganizationAdminAuditLog:
    """Does not commit — caller's UnitOfWork owns the transaction, so a
    mutation and its audit record are written atomically together."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def record(
        self,
        *,
        organization_id: str,
        actor_id: str,
        action: AuditAction,
        target_type: str,
        target_id: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        model = OrganizationAdminAuditLogModel(
            id=str(EntityId.generate()),
            organization_id=organization_id,
            actor_id=actor_id,
            action=action.value,
            target_type=target_type,
            target_id=target_id,
            metadata_=metadata or {},
            occurred_at=utc_now(),
        )
        self._session.add(model)
        await self._session.flush()

    async def query_for_organization(
        self, organization_id: str, limit: int = 100, offset: int = 0,
    ) -> list[OrganizationAdminAuditEntry]:
        stmt = (
            select(OrganizationAdminAuditLogModel)
            .where(OrganizationAdminAuditLogModel.organization_id == organization_id)
            .order_by(OrganizationAdminAuditLogModel.occurred_at.desc())
            .limit(limit).offset(offset)
        )
        result = await self._session.execute(stmt)
        return [
            OrganizationAdminAuditEntry(
                organization_id=m.organization_id, actor_id=m.actor_id, action=m.action,
                target_type=m.target_type, target_id=m.target_id, metadata=m.metadata_,
                occurred_at=m.occurred_at,
            )
            for m in result.scalars().all()
        ]
