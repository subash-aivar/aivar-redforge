"""DekRewrapWorker — rewraps key envelopes to a new master key."""

from __future__ import annotations

import asyncio
import contextlib
from typing import TYPE_CHECKING

import structlog
from sqlalchemy import text

from credential_vault.infrastructure import metrics

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from credential_vault.domain.ports.i_key_management_port import IKeyManagementPort
    from credential_vault.workers.dek_rewrap.dek_rewrap_progress_repository import (
        DekRewrapProgressRepository,
    )

logger = structlog.get_logger(__name__)


class DekRewrapWorker:
    def __init__(
        self,
        kms_adapter: IKeyManagementPort,
        rewrap_repo: DekRewrapProgressRepository,
        session_factory: async_sessionmaker[AsyncSession],
        target_master_key_id: str,
        worker_id: str = "dek-rewrap-1",
        batch_size: int = 100,
        rate_limit_delay_ms: int = 50,
    ) -> None:
        self._kms = kms_adapter
        self._rewrap_repo = rewrap_repo
        self._session_factory = session_factory
        self._target_master_key_id = target_master_key_id
        self._worker_id = worker_id
        self._batch_size = batch_size
        self._rate_limit_delay_ms = rate_limit_delay_ms
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
                processed = await self._run_cycle()
                if processed == 0:
                    await asyncio.sleep(30.0)
            except Exception as exc:
                logger.warning("dek_rewrap_cycle_failed", error=str(exc))
                metrics.worker_cycles_total.labels(worker=self._worker_id, outcome="failure").inc()
            else:
                metrics.worker_cycles_total.labels(worker=self._worker_id, outcome="success").inc()
            await asyncio.sleep(self._rate_limit_delay_ms / 1000.0)

    async def _run_cycle(self) -> int:
        candidates = await self._rewrap_repo.claim_batch(
            self._target_master_key_id, self._batch_size
        )
        if not candidates:
            self._running = False
            return 0
        self._stats["cycles"] += 1
        processed = 0
        for candidate in candidates:
            await asyncio.sleep(self._rate_limit_delay_ms / 1000.0)
            try:
                async with self._session_factory() as session:
                    row = await session.execute(
                        text(
                            """
                            SELECT wrapped_dek, master_key_id, wrapping_algorithm, key_created_at
                            FROM credential_vault_versions
                            WHERE id = :vid AND tenant_id = :tid
                            """
                        ),
                        {"vid": candidate.version_id, "tid": candidate.tenant_id},
                    )
                    version_row = row.one()
                    from credential_vault.domain.value_objects.payloads import KeyEnvelope

                    old_envelope = KeyEnvelope(
                        wrapped_dek=bytes(version_row[0]),
                        master_key_id=version_row[1],
                        wrapping_algorithm=version_row[2],
                        created_at=version_row[3],
                    )
                    new_envelope = await self._kms.rewrap_dek(
                        old_envelope, self._target_master_key_id
                    )
                    await session.execute(
                        text(
                            """
                            UPDATE credential_vault_versions
                            SET wrapped_dek = :wrapped,
                                master_key_id = :kid,
                                wrapping_algorithm = :algo,
                                key_created_at = NOW(),
                                row_version = row_version + 1
                            WHERE id = :vid AND tenant_id = :tid
                            """
                        ),
                        {
                            "wrapped": new_envelope.wrapped_dek,
                            "kid": new_envelope.master_key_id,
                            "algo": new_envelope.wrapping_algorithm,
                            "vid": candidate.version_id,
                            "tid": candidate.tenant_id,
                        },
                    )
                    await session.commit()
                await self._rewrap_repo.mark_rewrapped(
                    candidate.version_id,
                    candidate.tenant_id,
                    candidate.old_master_key_id,
                    self._target_master_key_id,
                )
                processed += 1
                self._stats["processed"] += 1
            except Exception as exc:
                self._stats["failed"] += 1
                logger.warning(
                    "dek_rewrap_failed",
                    version_id=str(candidate.version_id),
                    error=str(exc),
                )
        if len(candidates) < self._batch_size:
            self._running = False
        return processed
