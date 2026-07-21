"""BranchResolutionService — resolves conditional branch predicates at task completion."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from campaignexecution.domain.value_objects.enums import TaskOutcome
    from campaignexecution.domain.value_objects.execution_vos import ObjectiveStateMap
    from campaignexecution.domain.value_objects.identifiers import CampaignTaskId


class BranchResolutionService:
    """Evaluates DependencyPredicate conditions against task outcome and objective states.

    Given a completed task and its successors with their predicates, produces:
    - ready_task_ids: successors whose predicate evaluates to True
    - skipped_task_ids: successors whose predicate evaluates to False

    This service is stateless and pure; it does not mutate the execution.
    It is called by the application service inside the TaskGraphExecution aggregate's
    record_task_completion boundary.
    """

    def resolve(
        self,
        completed_task_id: CampaignTaskId,
        outcome: TaskOutcome,
        successors: list[tuple[CampaignTaskId, str, str | None]],
        objective_states: ObjectiveStateMap,
    ) -> tuple[list[CampaignTaskId], list[CampaignTaskId]]:
        """Resolve which successors should become ready vs. skipped.

        Args:
            completed_task_id: The task that just completed.
            outcome: The outcome of the completed task.
            successors: List of (successor_task_id, predicate_str, objective_ref) tuples.
            objective_states: Current objective state map.

        Returns:
            (ready_task_ids, skipped_task_ids)
        """

        ready: list[CampaignTaskId] = []
        skipped: list[CampaignTaskId] = []

        for succ_id, predicate, objective_ref in successors:
            if self._evaluate_predicate(predicate, outcome, objective_ref, objective_states):
                ready.append(succ_id)
            else:
                skipped.append(succ_id)

        return ready, skipped

    def _evaluate_predicate(
        self,
        predicate: str,
        outcome: TaskOutcome,
        objective_ref: str | None,
        objective_states: ObjectiveStateMap,
    ) -> bool:
        from campaignexecution.domain.value_objects.enums import TaskOutcome

        match predicate:
            case "AlwaysExecute":
                return True
            case "ExecuteOnSuccess":
                return outcome in {TaskOutcome.SUCCESS, TaskOutcome.PARTIAL_SUCCESS}
            case "ExecuteOnFailure":
                return outcome in {TaskOutcome.FAILURE, TaskOutcome.TIMED_OUT}
            case "ExecuteIfObjectiveMet":
                if not objective_ref:
                    return False
                return objective_states.get(objective_ref) == "Achieved"
            case "ExecuteIfObjectiveFailed":
                if not objective_ref:
                    return False
                return objective_states.get(objective_ref) in {"Failed", "Inconclusive"}
            case "ExecuteIfDetectionFired":
                # Detection correlation is handled at evaluation phase (Phase 5)
                # In Phase 3, this is treated as AlwaysExecute as a safe default
                return True
            case "ExecuteIfDetectionSilent":
                return True
            case _:
                # Unknown predicate: execute by default (safe)
                return True
