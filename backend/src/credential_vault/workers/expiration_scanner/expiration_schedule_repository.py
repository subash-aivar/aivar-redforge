"""Expiration schedule state repository."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from sqlalchemy import text

from credential_vault.domain.value_objects.identifiers import TenantId

if TYPE_CHECKING:
    from datetime import datetime
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


@dataclass(frozen=True, slots=True)
class ExpirationScheduleItem:
    credential_id: UUID
    tenant_id: TenantId


class ExpirationScheduleRepository:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def reconcile_missing_entries(self) -> None:
        async with self._session_factory() as session:
            await session.execute(
                text(
                    """
                    INSERT INTO credential_vault_expiration_schedule_state
                        (credential_id, tenant_id, last_scanned_at, next_scan_at, expires_at)
                    SELECT c.id, c.tenant_id, NOW(), NOW(), v.expires_at
                    FROM credential_vault_credentials c
                    JOIN credential_vault_versions v ON v.id = c.active_version_id
                    WHERE c.state = 'ACTIVE'
                      AND c.id NOT IN (
                          SELECT credential_id FROM credential_vault_expiration_schedule_state
                      )
                    ON CONFLICT (credential_id) DO NOTHING
                    """
                )
            )
            await session.commit()

    async def claim_batch(self, batch_size: int) -> list[ExpirationScheduleItem]:
        async with self._session_factory() as session:
            result = await session.execute(
                text(
                    """
                    SELECT credential_id, tenant_id
                    FROM credential_vault_expiration_schedule_state
                    WHERE next_scan_at <= NOW()
                      AND (claimed_at IS NULL OR claim_expires_at < NOW())
                    ORDER BY next_scan_at ASC
                    LIMIT :batch_size
                    FOR UPDATE SKIP LOCKED
                    """
                ),
                {"batch_size": batch_size},
            )
            rows = result.all()
            if not rows:
                await session.commit()
                return []
            for credential_id, tenant_id in rows:
                await session.execute(
                    text(
                        """
                        UPDATE credential_vault_expiration_schedule_state
                        SET claimed_at = NOW(),
                            claim_expires_at = NOW() + INTERVAL '10 minutes'
                        WHERE credential_id = :cid AND tenant_id = :tid
                        """
                    ),
                    {"cid": credential_id, "tid": tenant_id},
                )
            await session.commit()
            return [ExpirationScheduleItem(credential_id=row[0], tenant_id=row[1]) for row in rows]

    async def release_claim(self, credential_id: UUID, tenant_id: TenantId) -> None:
        async with self._session_factory() as session:
            await session.execute(
                text(
                    """
                    UPDATE credential_vault_expiration_schedule_state
                    SET claimed_at = NULL, claim_expires_at = NULL
                    WHERE credential_id = :cid AND tenant_id = :tid
                    """
                ),
                {"cid": credential_id, "tid": tenant_id},
            )
            await session.commit()

    async def mark_scanned(
        self,
        credential_id: UUID,
        tenant_id: TenantId,
        next_scan_at: datetime,
        expires_at: datetime | None,
    ) -> None:
        async with self._session_factory() as session:
            await session.execute(
                text(
                    """
                    UPDATE credential_vault_expiration_schedule_state
                    SET last_scanned_at = NOW(),
                        next_scan_at = :next_scan,
                        expires_at = :expires_at,
                        claimed_at = NULL,
                        claim_expires_at = NULL
                    WHERE credential_id = :cid AND tenant_id = :tid
                    """
                ),
                {
                    "cid": credential_id,
                    "tid": tenant_id,
                    "next_scan": next_scan_at,
                    "expires_at": expires_at,
                },
            )
            await session.commit()
