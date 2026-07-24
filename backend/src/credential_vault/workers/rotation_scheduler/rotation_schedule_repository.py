"""Rotation schedule state repository."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from sqlalchemy import text

from credential_vault.domain.value_objects.identifiers import TenantId

if TYPE_CHECKING:
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker


@dataclass(frozen=True, slots=True)
class RotationScheduleItem:
    credential_id: UUID
    tenant_id: TenantId


class RotationScheduleRepository:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def reconcile_missing_entries(self) -> None:
        async with self._session_factory() as session:
            await session.execute(
                text(
                    """
                    INSERT INTO credential_vault_rotation_schedule_state
                        (credential_id, tenant_id, last_checked_at, next_due_at)
                    SELECT c.id, c.tenant_id, NOW(),
                           v.created_at + (p.interval_days * INTERVAL '1 day')
                    FROM credential_vault_credentials c
                    JOIN credential_vault_versions v ON v.id = c.active_version_id
                    JOIN credential_vault_rotation_policies p ON p.id = c.rotation_policy_id
                    WHERE c.rotation_policy_id IS NOT NULL
                      AND c.state = 'ACTIVE'
                      AND p.auto_rotate = TRUE
                      AND p.interval_days IS NOT NULL
                      AND c.id NOT IN (
                          SELECT credential_id FROM credential_vault_rotation_schedule_state
                      )
                    ON CONFLICT (credential_id) DO NOTHING
                    """
                )
            )
            await session.commit()

    async def claim_batch(self, batch_size: int) -> list[RotationScheduleItem]:
        async with self._session_factory() as session:
            result = await session.execute(
                text(
                    """
                    SELECT credential_id, tenant_id
                    FROM credential_vault_rotation_schedule_state
                    WHERE next_due_at <= NOW()
                      AND (claimed_at IS NULL OR claim_expires_at < NOW())
                    ORDER BY next_due_at ASC
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
                        UPDATE credential_vault_rotation_schedule_state
                        SET claimed_at = NOW(),
                            claim_expires_at = NOW() + INTERVAL '10 minutes'
                        WHERE credential_id = :cid AND tenant_id = :tid
                        """
                    ),
                    {"cid": credential_id, "tid": tenant_id},
                )
            await session.commit()
            return [RotationScheduleItem(credential_id=row[0], tenant_id=row[1]) for row in rows]

    async def release_claim(self, credential_id: UUID, tenant_id: TenantId) -> None:
        async with self._session_factory() as session:
            await session.execute(
                text(
                    """
                    UPDATE credential_vault_rotation_schedule_state
                    SET claimed_at = NULL, claim_expires_at = NULL
                    WHERE credential_id = :cid AND tenant_id = :tid
                    """
                ),
                {"cid": credential_id, "tid": tenant_id},
            )
            await session.commit()

    async def mark_rotated(
        self,
        credential_id: UUID,
        tenant_id: TenantId,
        next_due_at: datetime,
    ) -> None:
        async with self._session_factory() as session:
            await session.execute(
                text(
                    """
                    UPDATE credential_vault_rotation_schedule_state
                    SET last_rotated_at = NOW(),
                        last_checked_at = NOW(),
                        next_due_at = :next_due,
                        claimed_at = NULL,
                        claim_expires_at = NULL
                    WHERE credential_id = :cid AND tenant_id = :tid
                    """
                ),
                {"cid": credential_id, "tid": tenant_id, "next_due": next_due_at},
            )
            await session.commit()

    @staticmethod
    def default_next_due(interval_days: int, from_time: datetime | None = None) -> datetime:
        base = from_time or datetime.now(UTC)
        return base + timedelta(days=interval_days)
