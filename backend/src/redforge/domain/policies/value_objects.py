"""Value objects for the Validation Policy bounded context.

Policies orchestrate which attacks run, when, against which targets,
and with what execution strategy.
"""

from dataclasses import dataclass
from enum import StrEnum, unique


@unique
class PolicyStatus(StrEnum):
    """Lifecycle status of a Validation Policy."""

    DRAFT = "draft"
    PUBLISHED = "published"
    ARCHIVED = "archived"
    SUPERSEDED = "superseded"


@unique
class ExecutionStrategy(StrEnum):
    """How attacks within the policy are executed.

    - SEQUENTIAL: Attacks run one after another in order.
    - PARALLEL: Attacks run concurrently (max throughput).
    - ADAPTIVE: Engine decides based on target capacity.
    """

    SEQUENTIAL = "sequential"
    PARALLEL = "parallel"
    ADAPTIVE = "adaptive"


@unique
class TriggerRule(StrEnum):
    """When a policy-based validation is triggered.

    - ON_DEMAND: Manual or API-triggered.
    - SCHEDULED: Recurring schedule (cron-like).
    - ON_CHANGE: When the AI target configuration changes.
    - ON_DEPLOY: When a new version of the target is deployed.
    - CONTINUOUS: Always running at defined intervals.
    """

    ON_DEMAND = "on_demand"
    SCHEDULED = "scheduled"
    ON_CHANGE = "on_change"
    ON_DEPLOY = "on_deploy"
    CONTINUOUS = "continuous"


@dataclass(frozen=True, slots=True)
class PolicyVersion:
    """Semantic version for a policy."""

    major: int
    minor: int
    patch: int

    def __post_init__(self) -> None:
        if self.major < 0 or self.minor < 0 or self.patch < 0:
            raise ValueError("Version components must be non-negative")

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"

    @classmethod
    def initial(cls) -> "PolicyVersion":
        return cls(1, 0, 0)

    @classmethod
    def from_string(cls, value: str) -> "PolicyVersion":
        parts = value.split(".")
        if len(parts) != 3:
            raise ValueError(f"Invalid version: '{value}'")
        try:
            return cls(int(parts[0]), int(parts[1]), int(parts[2]))
        except ValueError as exc:
            raise ValueError(f"Invalid version: '{value}'") from exc


@dataclass(frozen=True, slots=True)
class TargetScope:
    """Defines which AI targets this policy applies to.

    An empty set means "all targets" (universal scope).
    Scoping can be by target type, provider, or explicit target IDs.
    """

    target_types: frozenset[str] = frozenset()
    providers: frozenset[str] = frozenset()
    target_ids: frozenset[str] = frozenset()

    @classmethod
    def universal(cls) -> "TargetScope":
        """Policy applies to all targets."""
        return cls()

    @property
    def is_universal(self) -> bool:
        return (
            len(self.target_types) == 0
            and len(self.providers) == 0
            and len(self.target_ids) == 0
        )
