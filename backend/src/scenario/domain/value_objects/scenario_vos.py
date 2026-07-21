"""Scenario bounded context value objects."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_SEMVER_PATTERN = re.compile(
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-"
    r"((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-]"
    r"[0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"
)
_SCENARIO_KEY_PATTERN = re.compile(r"^[a-z][a-z0-9_-]*\.[a-z][a-z0-9_-]*$")


@dataclass(frozen=True, slots=True)
class ScenarioKey:
    """Stable identifier in `{namespace}.{scenario_name}` format."""

    value: str

    def __post_init__(self) -> None:
        normalized = self.value.strip().lower()
        if not _SCENARIO_KEY_PATTERN.match(normalized):
            raise ValueError(
                "ScenarioKey must match '{namespace}.{scenario_name}' "
                "(lowercase alphanumeric, underscores, hyphens)"
            )
        object.__setattr__(self, "value", normalized)


@dataclass(frozen=True, slots=True)
class ScenarioTemplateVersion:
    value: str

    def __post_init__(self) -> None:
        if not _SEMVER_PATTERN.match(self.value.strip()):
            raise ValueError(
                f"ScenarioTemplateVersion must be valid semver, got '{self.value}'"
            )


@dataclass(frozen=True, slots=True)
class ThreatActorRef:
    threat_actor_id: str | None
    name: str

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("ThreatActorRef.name is required")


@dataclass(frozen=True, slots=True)
class MitreAttackRef:
    technique_id: str
    technique_name: str

    def __post_init__(self) -> None:
        if not self.technique_id.strip():
            raise ValueError("MitreAttackRef.technique_id is required")
        if not self.technique_name.strip():
            raise ValueError("MitreAttackRef.technique_name is required")


@dataclass(frozen=True, slots=True)
class CoveredAttackTechniques:
    techniques: tuple[MitreAttackRef, ...]

    def __len__(self) -> int:
        return len(self.techniques)


@dataclass(frozen=True, slots=True)
class ScenarioObjectiveBlueprint:
    objective_type: str
    condition_type: str
    parameters: dict[str, str] = field(default_factory=dict)
    is_required: bool = True


@dataclass(frozen=True, slots=True)
class DefaultSafetyPolicy:
    max_concurrent_actions: int
    auto_abort_on_detection: bool
    auto_abort_on_objective_failure: bool
    blast_radius_ceiling: str

    def __post_init__(self) -> None:
        if self.max_concurrent_actions < 1:
            raise ValueError("max_concurrent_actions must be at least 1")


@dataclass(frozen=True, slots=True)
class TaskGraphTopologyBlueprint:
    tasks: list[dict[str, object]]

    def __post_init__(self) -> None:
        seen: set[str] = set()
        for task in self.tasks:
            task_key = task.get("task_key")
            if not isinstance(task_key, str) or not task_key.strip():
                raise ValueError("Each task must have a non-empty task_key")
            if task_key in seen:
                raise ValueError(f"Duplicate task_key '{task_key}' in topology")
            seen.add(task_key)
            if not isinstance(task.get("task_type"), str):
                raise ValueError(f"Task '{task_key}' must have task_type")
            if not isinstance(task.get("technique_id"), str):
                raise ValueError(f"Task '{task_key}' must have technique_id")
            depends_on = task.get("depends_on", [])
            if not isinstance(depends_on, list) or not all(
                isinstance(dep, str) for dep in depends_on
            ):
                raise ValueError(f"Task '{task_key}' depends_on must be list[str]")
            parameters = task.get("parameters", {})
            if not isinstance(parameters, dict):
                raise ValueError(f"Task '{task_key}' parameters must be a dict")


@dataclass(frozen=True, slots=True)
class ScenarioParameterSpec:
    name: str
    description: str
    required: bool
    default_value: str | None
    parameter_type: str

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("ScenarioParameterSpec.name is required")
        if not self.parameter_type.strip():
            raise ValueError("ScenarioParameterSpec.parameter_type is required")
