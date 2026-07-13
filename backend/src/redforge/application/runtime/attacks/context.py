"""Attack Execution Context — immutable context for one attack execution.

Contains all metadata needed by strategy, payload generator, renderer,
and conversation builder. Passed through the attack pipeline.

Immutable by design: no stage can modify the context for another stage.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class TargetMetadata:
    """Information about the AI target being attacked."""

    target_id: str
    name: str
    target_type: str
    provider: str
    endpoint: str
    model: str = ""
    system_prompt: str = ""
    capabilities: frozenset[str] = field(default_factory=frozenset)
    extra: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class AttackMetadata:
    """Information about the attack being executed."""

    attack_id: str
    attack_name: str
    category: str
    technique: str
    severity: str
    version: str = "1.0.0"
    extra: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class RuntimeOptions:
    """Execution options for this attack run."""

    timeout_seconds: int = 60
    max_retries: int = 0
    correlation_id: str = ""
    run_id: str = ""
    step_index: int = 0
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class AttackExecutionContext:
    """Complete immutable context for one attack execution.

    Assembled by the orchestrator, consumed by strategy/generator/renderer.
    No stage modifies this — it is read-only throughout the pipeline.
    """

    target: TargetMetadata
    attack: AttackMetadata
    options: RuntimeOptions

    @property
    def step_id(self) -> str:
        return f"{self.options.run_id}-step-{self.options.step_index}"
