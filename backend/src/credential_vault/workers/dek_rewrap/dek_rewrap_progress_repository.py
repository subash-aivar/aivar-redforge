"""DekRewrapProgressRepository — tracks DEK rewrap progress."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

from sqlalchemy import text

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from credential_vault.domain.value_objects.identifiers import TenantId


@dataclass(frozen=True, slots=True)
class RewrapCandidate:
    version_id: UUID
    tenant_id: TenantId
    old_master_key_id: str


class DekRewrapProgressRepository:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self._session_factory = session_factory

    async def claim_batch(
        self, target_master_key_id: str, batch_size: int
    ) -> list[RewrapCandidate]:
        async with self._session_factory() as session:
            result = await session.execute(
                text(
                    """
                    SELECT v.id, v.tenant_id, v.master_key_id
                    FROM credential_vault_versions v
                    LEFT JOIN credential_vault_dek_rewrap_progress p ON p.version_id = v.id
                    WHERE v.master_key_id != :target
                      AND (p.rewrapped_at IS NULL)
                    ORDER BY v.created_at ASC
                    LIMIT :batch_size
                    """
                ),
                {"target": target_master_key_id, "batch_size": batch_size},
            )
            rows = result.all()
            await session.commit()
            return [
                RewrapCandidate(version_id=row[0], tenant_id=row[1], old_master_key_id=row[2])
                for row in rows
            ]

    async def mark_rewrapped(
        self,
        version_id: UUID,
        tenant_id: TenantId,
        old_master_key_id: str,
        new_master_key_id: str,
    ) -> None:
        async with self._session_factory() as session:
            await session.execute(
                text(
                    """
                    INSERT INTO credential_vault_dek_rewrap_progress
                        (id, version_id, tenant_id, old_master_key_id,
                         new_master_key_id, started_at, rewrapped_at)
                    VALUES (:id, :vid, :tid, :old, :new, :started, NOW())
                    ON CONFLICT (version_id) DO UPDATE
                    SET rewrapped_at = NOW(), new_master_key_id = EXCLUDED.new_master_key_id
                    """
                ),
                {
                    "id": uuid4(),
                    "vid": version_id,
                    "tid": tenant_id,
                    "old": old_master_key_id,
                    "new": new_master_key_id,
                    "started": datetime.now(UTC),
                },
            )
            await session.commit()
