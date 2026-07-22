from __future__ import annotations

from typing import Any
from uuid import UUID

from threat_hunt.application.commands.hunt_commands import GenerateThreatHuntCandidate


class ThreatHuntCandidateWorker:
    def __init__(self, app: Any) -> None:
        self._app = app
        self.processed = 0

    async def handle(
        self,
        tenant_id: UUID,
        signal_ids: tuple[str, ...],
        technique_ids: tuple[str, ...] = ("T1059",),
    ) -> Any:
        self.processed += 1
        return await self._app.generate(
            GenerateThreatHuntCandidate(
                tenant_id,
                signal_ids,
                technique_ids,
                "title: generated\ndetection: selection",
                0.82,
                ("system",),
            )
        )


class HuntScheduler:
    def __init__(self, worker: ThreatHuntCandidateWorker) -> None:
        self.worker = worker

    async def tick(self, tenant_id: UUID) -> int:
        await self.worker.handle(tenant_id, ("sig-auto",))
        return self.worker.processed
