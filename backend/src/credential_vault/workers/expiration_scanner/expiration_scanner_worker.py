"""ExpirationScannerWorker — expires credentials past their active version expiry."""

from __future__ import annotations

import asyncio
import contextlib
import os
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING
from uuid import UUID, uuid7

import structlog

from credential_vault.application.commands.credential_commands import ExpireCredentialCommand
from credential_vault.domain.events.credential_events import CredentialExpirationWarning
from credential_vault.domain.value_objects.identifiers import CredentialId, TenantId
from credential_vault.domain.value_objects.states import CredentialState
from credential_vault.infrastructure import metrics

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

    from credential_vault.application.ports.i_event_publisher import IEventPublisher
    from credential_vault.application.services.credential_application_service import (
        CredentialApplicationService,
    )
    from credential_vault.domain.services.policy_evaluator import PolicyEvaluatorService
    from credential_vault.workers.expiration_scanner.expiration_schedule_repository import (
        ExpirationScheduleItem,
        ExpirationScheduleRepository,
    )

logger = structlog.get_logger(__name__)


class ExpirationScannerWorker:
    def __init__(
        self,
        credential_service: CredentialApplicationService,
        schedule_repo: ExpirationScheduleRepository,
        policy_evaluator: PolicyEvaluatorService,
        session_factory: async_sessionmaker[AsyncSession],
        event_publisher: IEventPublisher,
        worker_id: str = "expiration-scanner-1",
        poll_interval_s: float = 300.0,
        batch_size: int = 20,
        max_concurrent: int = 5,
        system_principal_id: UUID | None = None,
    ) -> None:
        self._credential_service = credential_service
        self._schedule_repo = schedule_repo
        self._policy_evaluator = policy_evaluator
        self._event_publisher = event_publisher
        self._session_factory = session_factory
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
                logger.warning("expiration_scanner_cycle_failed", error=str(exc))
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

        async def _process_one(item: ExpirationScheduleItem) -> None:
            async with semaphore:
                try:
                    await self._process_credential(item)
                    self._stats["processed"] += 1
                except Exception as exc:
                    self._stats["failed"] += 1
                    logger.warning(
                        "expiration_failed",
                        credential_id=str(item.credential_id),
                        error=str(exc),
                    )
                    await self._schedule_repo.release_claim(item.credential_id, item.tenant_id)

        await asyncio.gather(*[_process_one(item) for item in claimed])

    async def _process_credential(self, item: ExpirationScheduleItem) -> None:
        from credential_vault.infrastructure.persistence.repositories.pg_credential_repository import (  # noqa: E501
            PgCredentialRepository,
        )
        from credential_vault.infrastructure.persistence.repositories.pg_credential_version_repository import (  # noqa: E501
            PgCredentialVersionRepository,
        )
        from credential_vault.infrastructure.persistence.repositories.pg_expiration_policy_repository import (  # noqa: E501
            PgExpirationPolicyRepository,
        )

        now = datetime.now(UTC)
        async with self._session_factory() as session:
            cred_repo = PgCredentialRepository(session)
            version_repo = PgCredentialVersionRepository(session)
            policy_repo = PgExpirationPolicyRepository(session)

            tenant_id = TenantId(item.tenant_id)
            credential_id = CredentialId(item.credential_id)
            credential = await cred_repo.get_by_id(credential_id, tenant_id)
            active = await version_repo.get_active_version(credential_id, tenant_id)
            expiration_policy = None
            if credential.expiration_policy_id is not None:
                expiration_policy = await policy_repo.get_by_id(
                    credential.expiration_policy_id, tenant_id
                )

        if credential.state != CredentialState.ACTIVE:
            await self._schedule_repo.mark_scanned(
                item.credential_id,
                item.tenant_id,
                now + timedelta(hours=1),
                active.expires_at,
            )
            return

        if self._policy_evaluator.is_version_expired(active, expiration_policy, now):
            await self._credential_service.expire_credential(
                ExpireCredentialCommand(
                    item.tenant_id, item.credential_id, self._system_principal_id
                )
            )
            await self._schedule_repo.mark_scanned(
                item.credential_id,
                item.tenant_id,
                now + timedelta(days=1),
                active.expires_at,
            )
            return

        if expiration_policy is not None and self._policy_evaluator.should_warn_expiration(
            active, expiration_policy, now
        ):
            expiry = active.expires_at or self._policy_evaluator.compute_version_expiry(
                active.created_at, expiration_policy
            )
            days_remaining = (expiry - now).days
            await self._event_publisher.publish_batch(
                [
                    CredentialExpirationWarning(
                        event_id=str(uuid7()),
                        occurred_at=now,
                        tenant_id=tenant_id,
                        aggregate_id=str(item.credential_id),
                        aggregate_type="Credential",
                        credential_id=credential_id,
                        version_id=active.version_id,
                        days_until_expiry=days_remaining,
                        expiry_at=expiry,
                    )
                ]
            )

        await self._schedule_repo.mark_scanned(
            item.credential_id,
            item.tenant_id,
            now + timedelta(hours=1),
            active.expires_at,
        )
