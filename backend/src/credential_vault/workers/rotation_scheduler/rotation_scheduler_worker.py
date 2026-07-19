"""RotationSchedulerWorker — triggers scheduled credential rotations."""

from __future__ import annotations

import asyncio
import contextlib
import os
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import UUID

import structlog

from credential_vault.application.commands.credential_commands import (
    CommitRotationCommand,
    RotateCredentialCommand,
)
from credential_vault.domain.value_objects.identifiers import (
    CredentialId,
    TenantId,
)
from credential_vault.infrastructure import metrics
from credential_vault.workers.rotation_scheduler.rotation_schedule_repository import (
    RotationScheduleItem,
    RotationScheduleRepository,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from credential_vault.application.services.credential_application_service import (
        CredentialApplicationService,
    )
    from credential_vault.domain.repositories.i_credential_repository import (
        ICredentialRepository,
    )
    from credential_vault.domain.repositories.i_credential_version_repository import (
        ICredentialVersionRepository,
    )
    from credential_vault.domain.repositories.i_rotation_policy_repository import (
        IRotationPolicyRepository,
    )
    from credential_vault.domain.services.rotation_planner import RotationPlannerService

logger = structlog.get_logger(__name__)


class RotationSchedulerWorker:
    def __init__(
        self,
        credential_service: CredentialApplicationService,
        schedule_repo: RotationScheduleRepository,
        rotation_planner: RotationPlannerService,
        credential_repo_factory: async_sessionmaker[AsyncSession],
        worker_id: str = "rotation-scheduler-1",
        poll_interval_s: float = 60.0,
        batch_size: int = 10,
        max_concurrent: int = 3,
        system_principal_id: UUID | None = None,
    ) -> None:
        self._credential_service = credential_service
        self._schedule_repo = schedule_repo
        self._rotation_planner = rotation_planner
        self._session_factory = credential_repo_factory
        self._worker_id = worker_id
        self._poll_interval_s = poll_interval_s
        self._batch_size = batch_size
        self._max_concurrent = max_concurrent
        self._system_principal_id = system_principal_id or UUID(
            os.environ.get(
                "CREDENTIAL_VAULT_SYSTEM_PRINCIPAL_ID",
                "00000000-0000-4000-8000-000000000099",
            )
        )
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
        await self._schedule_repo.reconcile_missing_entries()
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
                logger.warning("rotation_scheduler_cycle_failed", error=str(exc))
                metrics.worker_cycles_total.labels(worker=self._worker_id, outcome="failure").inc()
            else:
                metrics.worker_cycles_total.labels(worker=self._worker_id, outcome="success").inc()
            await asyncio.sleep(self._poll_interval_s)

    async def _run_cycle(self) -> None:
        claimed = await self._schedule_repo.claim_batch(self._batch_size)
        if not claimed:
            return
        self._stats["cycles"] += 1
        semaphore = asyncio.Semaphore(self._max_concurrent)

        async def _process_one(item: RotationScheduleItem) -> None:
            async with semaphore:
                try:
                    await self._process_credential(item)
                    self._stats["processed"] += 1
                except Exception as exc:
                    self._stats["failed"] += 1
                    logger.warning(
                        "rotation_failed",
                        credential_id=str(item.credential_id),
                        error=str(exc),
                    )
                    await self._schedule_repo.release_claim(item.credential_id, item.tenant_id)

        await asyncio.gather(*[_process_one(item) for item in claimed])

    async def _process_credential(self, item: RotationScheduleItem) -> None:
        from credential_vault.infrastructure.persistence.repositories.pg_credential_repository import (  # noqa: E501
            PgCredentialRepository,
        )
        from credential_vault.infrastructure.persistence.repositories.pg_credential_version_repository import (  # noqa: E501
            PgCredentialVersionRepository,
        )
        from credential_vault.infrastructure.persistence.repositories.pg_rotation_policy_repository import (  # noqa: E501
            PgRotationPolicyRepository,
        )

        async with self._session_factory() as session:
            cred_repo: ICredentialRepository = PgCredentialRepository(session)
            version_repo: ICredentialVersionRepository = PgCredentialVersionRepository(session)
            policy_repo: IRotationPolicyRepository = PgRotationPolicyRepository(session)

            tenant_id = TenantId(item.tenant_id)
            credential_id = CredentialId(item.credential_id)
            credential = await cred_repo.get_by_id(credential_id, tenant_id)
            if credential.rotation_policy_id is None:
                await self._schedule_repo.release_claim(item.credential_id, item.tenant_id)
                return
            active = await version_repo.get_active_version(credential_id, tenant_id)
            policy = await policy_repo.get_by_id(credential.rotation_policy_id, tenant_id)

        now = datetime.now(UTC)
        if not self._rotation_planner.is_rotation_due(credential, policy, active.created_at, now):
            await self._schedule_repo.release_claim(item.credential_id, item.tenant_id)
            return

        payload_size = active.encrypted_payload.payload_size
        new_secret = os.urandom(payload_size or 32)
        principal = self._system_principal_id
        await self._credential_service.rotate_credential(
            RotateCredentialCommand(
                tenant_id=item.tenant_id,
                credential_id=item.credential_id,
                principal_id=principal,
                new_plaintext_secret=new_secret,
                trigger="SCHEDULED",
                policy_id=policy.policy_id.value,
                notes="scheduled rotation",
            )
        )
        if policy.auto_commit:
            await self._credential_service.commit_rotation(
                CommitRotationCommand(item.tenant_id, item.credential_id, principal)
            )

        next_due = RotationScheduleRepository.default_next_due(
            policy.interval_days or 30, active.created_at
        )
        await self._schedule_repo.mark_rotated(item.credential_id, item.tenant_id, next_due)
