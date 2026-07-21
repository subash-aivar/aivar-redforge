"""Value objects for the TaskGraph domain."""

from __future__ import annotations

from dataclasses import dataclass

from taskgraph.domain.value_objects.enums import DependencyPredicate


@dataclass(frozen=True, slots=True)
class TaskGraphVersion:
    major: int
    minor: int
    patch: int

    def __post_init__(self) -> None:
        if self.major < 0 or self.minor < 0 or self.patch < 0:
            raise ValueError("TaskGraphVersion components must be non-negative")

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"

    def is_greater_than(self, other: TaskGraphVersion) -> bool:
        return (self.major, self.minor, self.patch) > (other.major, other.minor, other.patch)

    @classmethod
    def from_string(cls, s: str) -> TaskGraphVersion:
        parts = s.split(".")
        if len(parts) != 3:
            raise ValueError(f"Invalid version string: {s}")
        return cls(major=int(parts[0]), minor=int(parts[1]), patch=int(parts[2]))


@dataclass(frozen=True, slots=True)
class TaskOperationTemplate:
    technique_id: str
    technique_name: str
    parameters: dict[str, str]
    timeout_seconds: int

    def __post_init__(self) -> None:
        if not self.technique_id.strip():
            raise ValueError("TaskOperationTemplate.technique_id must not be empty")
        if self.timeout_seconds <= 0:
            raise ValueError("TaskOperationTemplate.timeout_seconds must be positive")


@dataclass(frozen=True, slots=True)
class RollbackConfiguration:
    rollback_technique_id: str
    rollback_parameters: dict[str, str]
    rollback_not_possible: bool
    rollback_not_possible_reason: str | None


@dataclass(frozen=True, slots=True)
class HumanApprovalTaskConfig:
    gate_timeout_seconds: int
    required_approver_role: str
    default_on_timeout: str
    timeout_justification: str | None

    def __post_init__(self) -> None:
        if self.default_on_timeout not in {"proceed", "abort"}:
            raise ValueError(
                "HumanApprovalTaskConfig.default_on_timeout must be 'proceed' or 'abort'"
            )
        if self.default_on_timeout == "proceed" and not self.timeout_justification:
            raise ValueError(
                "HumanApprovalTaskConfig.timeout_justification is required "
                "when default_on_timeout is 'proceed'"
            )


@dataclass(frozen=True, slots=True)
class BarrierPolicy:
    task_group_id: str

    def __post_init__(self) -> None:
        if not self.task_group_id.strip():
            raise ValueError("BarrierPolicy.task_group_id must not be empty")


@dataclass(frozen=True, slots=True)
class ConditionalBranchConfig:
    predicate: DependencyPredicate
    objective_ref: str | None = None

    def __post_init__(self) -> None:
        objective_predicates = {
            DependencyPredicate.EXECUTE_IF_OBJECTIVE_MET,
            DependencyPredicate.EXECUTE_IF_OBJECTIVE_FAILED,
        }
        if self.predicate in objective_predicates and not self.objective_ref:
            raise ValueError(
                f"ConditionalBranchConfig.objective_ref is required for predicate {self.predicate}"
            )
