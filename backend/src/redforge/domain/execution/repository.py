"""Repository and adapter interfaces for the Execution Engine."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from redforge.domain.execution.entity import ExecutionPlan
    from redforge.domain.execution.value_objects import StepResult
    from redforge.shared.identifiers import EntityId


@runtime_checkable
class ExecutionPlanRepository(Protocol):
    """Port for ExecutionPlan persistence operations."""

    async def get_by_id(self, plan_id: EntityId) -> ExecutionPlan | None:
        """Retrieve an execution plan by its unique identifier."""
        ...

    async def list_by_run(self, run_id: EntityId) -> list[ExecutionPlan]:
        """List all plans for a validation run."""
        ...

    async def save(self, plan: ExecutionPlan) -> None:
        """Persist a new or updated execution plan."""
        ...


@runtime_checkable
class ProviderAdapter(Protocol):
    """Port for AI provider integrations.

    Each provider (OpenAI, Anthropic, etc.) implements this interface.
    The execution engine dispatches steps through this port without
    knowing which provider is being used.
    """

    @property
    def provider_name(self) -> str:
        """Unique name identifying this provider adapter."""
        ...

    async def execute_step(
        self, step_id: str, attack_id: str, target_id: str, context: dict[str, str]
    ) -> StepResult:
        """Execute a single attack step against a target.

        Returns a StepResult — the engine records this as evidence.
        This method NEVER executes prompts directly; it dispatches
        to the provider's inference API.
        """
        ...

    async def health_check(self) -> bool:
        """Verify the provider is reachable and authenticated."""
        ...
