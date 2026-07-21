"""RollbackPlanComputer — ordered rollback actions in reverse dependency order."""

from __future__ import annotations

from uuid import UUID


class RollbackPlanComputer:
    """Produces rollback order from completed tasks.

    Only tasks present in ``rollback_eligible`` participate. Order is reverse
    completion order (most recently completed first), which matches reverse
    dependency order for a linear execution path.
    """

    def compute(
        self,
        completed_task_ids_in_order: list[UUID],
        rollback_eligible: set[UUID],
    ) -> list[UUID]:
        """Return eligible completed task IDs in reverse completion order."""
        return [
            task_id
            for task_id in reversed(completed_task_ids_in_order)
            if task_id in rollback_eligible
        ]
