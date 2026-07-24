"""Evaluation bounded context value objects."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from evaluation.domain.value_objects.identifiers import TenantId

if TYPE_CHECKING:
    from uuid import UUID


@dataclass(frozen=True, slots=True)
class CampaignInstanceRef:
    """Reference to a CampaignInstance (campaign context)."""

    instance_id: UUID
    campaign_id: UUID
    tenant_id: TenantId
    run_number: int


@dataclass(frozen=True, slots=True)
class MitreAttackRef:
    """Reference to a MITRE ATT&CK technique."""

    technique_id: str  # e.g. "T1566.001"
    technique_name: str


@dataclass(frozen=True, slots=True)
class AttackActionRecord:
    """Lightweight reference to a completed M29 AttackAction — obtained via ACL port."""

    action_id: str
    operation_id: str
    technique_id: str
    asset_ref: str
    started_at: str  # ISO-8601
    completed_at: str  # ISO-8601
    outcome: str  # "Success" | "Failure" | "PartialSuccess"
    kill_chain_phase: str = "Unknown"


@dataclass(frozen=True, slots=True)
class DetectionFindingRecord:
    """Lightweight reference to an M28 DetectionFinding — obtained via ACL port."""

    finding_id: str
    rule_id: str
    technique_id: str
    asset_ref: str
    detected_at: str  # ISO-8601
    linked_action_id: str | None = None  # explicit graph link from M29/M28 correlation


@dataclass(frozen=True, slots=True)
class ComplianceMappingResult:
    """Compliance control mapping from M24 — obtained via ACL port."""

    control_id: str
    control_name: str
    framework: str  # e.g. "SOC2", "ISO27001", "NIST"
    outcome: str  # "Pass" | "Fail" | "Inconclusive"
    objective_id: str


@dataclass(frozen=True, slots=True)
class DetectionCorrelationConfig:
    """Configuration controlling detection coverage correlation window."""

    correlation_window_minutes: int = 30  # configurable per campaign
    include_graph_linked_findings: bool = True


@dataclass(frozen=True, slots=True)
class KillChainPhaseOutcome:
    phase_name: str
    tasks_planned: int
    tasks_completed: int
    tasks_failed: int

    @property
    def completion_rate(self) -> float:
        if self.tasks_planned == 0:
            return 0.0
        return self.tasks_completed / self.tasks_planned


@dataclass(frozen=True, slots=True)
class KillChainProgressionMap:
    """Per kill-chain phase: tasks completed vs. planned."""

    phase_outcomes: tuple[KillChainPhaseOutcome, ...]

    @property
    def phases_covered(self) -> frozenset[str]:
        return frozenset(p.phase_name for p in self.phase_outcomes if p.tasks_completed > 0)


@dataclass(frozen=True, slots=True)
class ObjectiveSpec:
    """Frozen objective definition copied from campaign at evaluation start."""

    objective_id: str
    objective_type: str
    is_required: bool
    # FindingPresent | EvidencePresent | AttackActionCompleted | DetectionAbsent
    condition_type: str
    parameters: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    """Lightweight ExecutionEvidence reference from M29 — refs/metadata only."""

    evidence_id: str
    action_id: str
    evidence_type: str
    created_at: str  # ISO-8601


@dataclass(frozen=True, slots=True)
class EvaluationMetrics:
    """Computed metrics for a campaign evaluation."""

    detection_coverage_percent: float = 0.0  # (techniques_detected / techniques_executed) * 100
    technique_success_rate: float = 0.0  # (techniques_succeeded / techniques_attempted) * 100
    evasion_rate: float = 0.0  # (techniques_evaded / techniques_executed) * 100
    mean_time_to_detect_seconds: float | None = None
    actions_executed_count: int = 0
    actions_failed_count: int = 0
    objectives_achieved_count: int = 0
    objectives_failed_count: int = 0
    campaign_duration_seconds: float | None = None
    kill_chain_phases_covered: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        for pct_field in (
            "detection_coverage_percent",
            "technique_success_rate",
            "evasion_rate",
        ):
            val = getattr(self, pct_field)
            if not (0.0 <= val <= 100.0):
                raise ValueError(f"{pct_field} must be in [0, 100], got {val}")
