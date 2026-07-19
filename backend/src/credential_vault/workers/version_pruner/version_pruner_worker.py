"""VersionPrunerWorker — deletes excess SUPERSEDED credential versions."""

from __future__ import annotations

import asyncio
import contextlib
from typing import TYPE_CHECKING

import structlog
from sqlalchemy import delete, select, text

from credential_vault.domain.value_objects.identifiers import VersionId
from credential_vault.domain.value_objects.states import VersionState
from credential_vault.infrastructure import metrics
from credential_vault.infrastructure.persistence.models.credential_version_model import (
    CredentialVersionModel,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

logger = structlog.get_logger(__name__)


class VersionPrunerWorker:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        worker_id: str = "version-pruner-1",
        poll_interval_s: float = 3600.0,
        batch_size: int = 50,
    ) -> None:
        self._session_factory = session_factory
        self._worker_id = worker_id
        self._poll_interval_s = poll_interval_s
        self._batch_size = batch_size
        self._running = False
        self._task: asyncio.Task[None] | None = None
        self._stats = {"processed": 0, "failed": 0, "cycles": 0}

    @property
    def worker_id(self) -> str:
        return self._worker_id

    @property
    def is_running(self) -> bool:
        return self._running and self._task is not None and not self._task.done()

    def stats(self) -> dict[str, int]:
        return dict(self._stats)

    async def start(self) -> None:
        self._running = True
        self._task = asyncio.create_task(self._poll_loop(), name=self._worker_id)

    async def stop(self) -> None:
        self._running = False
        if self._task is not None:
            self._task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._task

    async def _poll_loop(self) -> None:
        while self._running:
            try:
                await self._run_cycle()
            except Exception as exc:
                logger.warning("version_pruner_cycle_failed", error=str(exc))
                metrics.worker_cycles_total.labels(worker=self._worker_id, outcome="failure").inc()
            else:
                metrics.worker_cycles_total.labels(worker=self._worker_id, outcome="success").inc()
            await asyncio.sleep(self._poll_interval_s)

    async def _run_cycle(self) -> None:
        async with self._session_factory() as session:
            result = await session.execute(
                text(
                    """
                    SELECT c.id, c.tenant_id, p.max_versions_kept,
                           COUNT(v.id) FILTER (
                               WHERE v.version_state = 'SUPERSEDED'
                           ) AS superseded_count
                    FROM credential_vault_credentials c
                    JOIN credential_vault_rotation_policies p
                        ON p.id = c.rotation_policy_id
                    LEFT JOIN credential_vault_versions v
                        ON v.credential_id = c.id
                    GROUP BY c.id, c.tenant_id, p.max_versions_kept
                    HAVING COUNT(v.id) FILTER (
                        WHERE v.version_state = 'SUPERSEDED'
                    ) > p.max_versions_kept
                    LIMIT :batch_size
                    """
                ),
                {"batch_size": self._batch_size},
            )
            rows = result.all()
            if not rows:
                return
            self._stats["cycles"] += 1
            for credential_id, tenant_id, max_kept, superseded_count in rows:
                try:
                    to_delete = int(superseded_count) - int(max_kept)
                    versions = await session.execute(
                        select(CredentialVersionModel.id)
                        .where(
                            CredentialVersionModel.credential_id == credential_id,
                            CredentialVersionModel.tenant_id == tenant_id,
                            CredentialVersionModel.version_state == VersionState.SUPERSEDED.value,
                        )
                        .order_by(CredentialVersionModel.version_number.asc())
                        .limit(to_delete)
                    )
                    version_ids = [VersionId(v) for v in versions.scalars().all()]
                    if version_ids:
                        await session.execute(
                            delete(CredentialVersionModel).where(
                                CredentialVersionModel.id.in_([vid.value for vid in version_ids]),
                                CredentialVersionModel.tenant_id == tenant_id,
                                CredentialVersionModel.version_state
                                == VersionState.SUPERSEDED.value,
                            )
                        )
                        logger.info(
                            "versions_pruned",
                            credential_id=str(credential_id),
                            tenant_id=str(tenant_id),
                            pruned_count=len(version_ids),
                        )
                    self._stats["processed"] += 1
                except Exception as exc:
                    self._stats["failed"] += 1
                    logger.warning(
                        "version_prune_failed",
                        credential_id=str(credential_id),
                        error=str(exc),
                    )
            await session.commit()
