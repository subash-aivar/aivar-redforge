"""CredentialVaultWorkerHost — lifecycle manager for background workers."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from credential_vault.workers.dek_rewrap.dek_rewrap_worker import DekRewrapWorker
    from credential_vault.workers.expiration_scanner.expiration_scanner_worker import (
        ExpirationScannerWorker,
    )
    from credential_vault.workers.rotation_scheduler.rotation_scheduler_worker import (
        RotationSchedulerWorker,
    )
    from credential_vault.workers.version_pruner.version_pruner_worker import (
        VersionPrunerWorker,
    )


class CredentialVaultWorkerHost:
    def __init__(
        self,
        rotation_worker: RotationSchedulerWorker,
        expiration_worker: ExpirationScannerWorker,
        pruner_worker: VersionPrunerWorker,
        rewrap_worker: DekRewrapWorker | None = None,
    ) -> None:
        self._workers = [
            w
            for w in (
                rotation_worker,
                expiration_worker,
                pruner_worker,
                rewrap_worker,
            )
            if w is not None
        ]

    async def start(self) -> None:
        for worker in self._workers:
            await worker.start()

    async def stop(self) -> None:
        for worker in reversed(self._workers):
            await worker.stop()

    @property
    def is_healthy(self) -> bool:
        return all(w.is_running for w in self._workers)

    def stats(self) -> dict[str, object]:
        return {
            worker.worker_id: {"running": worker.is_running, **worker.stats()}
            for worker in self._workers
        }
