"""Application commands for evaluation context."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID

    from evaluation.domain.value_objects.evaluation_vos import (
        KillChainPhaseOutcome,
        ObjectiveSpec,
    )


@dataclass(frozen=True, slots=True)
class EvaluateCampaignCommand:
    """Trigger post-completion evaluation for a campaign instance."""

    tenant_id: UUID
    campaign_instance_id: UUID
    campaign_id: UUID
    run_number: int
    objective_specs: list[ObjectiveSpec]
    execution_failed: bool = False
    correlation_window_minutes: int = 30
    started_at: str = ""  # ISO-8601 campaign instance start
    completed_at: str = ""  # ISO-8601 campaign instance terminal
    kill_chain_phases: list[KillChainPhaseOutcome] = field(default_factory=list)


@dataclass(frozen=True, slots=True)
class ResolveEvaluationReviewCommand:
    tenant_id: UUID
    evaluation_id: UUID
    documented_reason: str


@dataclass(frozen=True, slots=True)
class GetEvaluationQuery:
    tenant_id: UUID
    campaign_instance_id: UUID


@dataclass(frozen=True, slots=True)
class GetMetricsTrendQuery:
    tenant_id: UUID
    campaign_id: UUID
    limit: int = 5
