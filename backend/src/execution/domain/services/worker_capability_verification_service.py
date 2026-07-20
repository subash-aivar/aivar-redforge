"""WorkerCapabilityVerificationService — signed manifest + trust vs impact."""

from __future__ import annotations

from typing import TYPE_CHECKING

from execution.domain.exceptions.domain_exceptions import (
    WorkerCapabilityInsufficient,
    WorkerDecommissioned,
    WorkerTrustInsufficient,
)
from execution.domain.value_objects.enums import trust_allows_impact

if TYPE_CHECKING:
    from execution.domain.aggregates.execution_worker import ExecutionWorker
    from execution.domain.value_objects.execution_vos import TechniqueRef


class WorkerCapabilityVerificationService:
    def verify(self, worker: ExecutionWorker, technique: TechniqueRef) -> bool:
        try:
            worker.assert_can_execute(technique)
        except (WorkerCapabilityInsufficient, WorkerTrustInsufficient, WorkerDecommissioned):
            return False
        if technique.technique_id not in worker.capabilities:
            return False
        return trust_allows_impact(worker.trust_level, technique.impact_ceiling)
