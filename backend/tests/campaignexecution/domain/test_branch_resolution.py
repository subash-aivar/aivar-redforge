"""Tests for BranchResolutionService — conditional branch predicate evaluation."""

from __future__ import annotations

from uuid import uuid4

import pytest

from campaignexecution.domain.services.branch_resolution_service import BranchResolutionService
from campaignexecution.domain.value_objects.enums import TaskOutcome
from campaignexecution.domain.value_objects.execution_vos import ObjectiveStateMap
from campaignexecution.domain.value_objects.identifiers import CampaignTaskId


@pytest.fixture()
def service() -> BranchResolutionService:
    return BranchResolutionService()


@pytest.fixture()
def completed_task_id() -> CampaignTaskId:
    return CampaignTaskId(uuid4())


@pytest.fixture()
def succ1() -> CampaignTaskId:
    return CampaignTaskId(uuid4())


@pytest.fixture()
def succ2() -> CampaignTaskId:
    return CampaignTaskId(uuid4())


def test_always_execute_always_ready(
    service: BranchResolutionService,
    completed_task_id: CampaignTaskId,
    succ1: CampaignTaskId,
) -> None:
    ready, _skipped = service.resolve(
        completed_task_id,
        TaskOutcome.FAILURE,
        [(succ1, "AlwaysExecute", None)],
        ObjectiveStateMap(),
    )
    assert succ1 in ready
    assert succ1 not in _skipped


def test_execute_on_success_skips_on_failure(
    service: BranchResolutionService,
    completed_task_id: CampaignTaskId,
    succ1: CampaignTaskId,
    succ2: CampaignTaskId,
) -> None:
    ready, _skipped = service.resolve(
        completed_task_id,
        TaskOutcome.FAILURE,
        [
            (succ1, "ExecuteOnSuccess", None),
            (succ2, "ExecuteOnFailure", None),
        ],
        ObjectiveStateMap(),
    )
    assert succ1 in _skipped
    assert succ2 in ready


def test_execute_on_success_with_partial_success(
    service: BranchResolutionService,
    completed_task_id: CampaignTaskId,
    succ1: CampaignTaskId,
) -> None:
    ready, _skipped = service.resolve(
        completed_task_id,
        TaskOutcome.PARTIAL_SUCCESS,
        [(succ1, "ExecuteOnSuccess", None)],
        ObjectiveStateMap(),
    )
    assert succ1 in ready


def test_execute_if_objective_met(
    service: BranchResolutionService,
    completed_task_id: CampaignTaskId,
    succ1: CampaignTaskId,
    succ2: CampaignTaskId,
) -> None:
    obj_id = str(uuid4())
    states = ObjectiveStateMap(states={obj_id: "Achieved"})

    ready, skipped = service.resolve(
        completed_task_id,
        TaskOutcome.SUCCESS,
        [
            (succ1, "ExecuteIfObjectiveMet", obj_id),
            (succ2, "ExecuteIfObjectiveFailed", obj_id),
        ],
        states,
    )
    assert succ1 in ready
    assert succ2 in skipped


def test_execute_if_objective_failed(
    service: BranchResolutionService,
    completed_task_id: CampaignTaskId,
    succ1: CampaignTaskId,
    succ2: CampaignTaskId,
) -> None:
    obj_id = str(uuid4())
    states = ObjectiveStateMap(states={obj_id: "Failed"})

    ready, skipped = service.resolve(
        completed_task_id,
        TaskOutcome.SUCCESS,
        [
            (succ1, "ExecuteIfObjectiveMet", obj_id),
            (succ2, "ExecuteIfObjectiveFailed", obj_id),
        ],
        states,
    )
    assert succ1 in skipped
    assert succ2 in ready


def test_execute_if_objective_met_skips_when_missing_ref(
    service: BranchResolutionService,
    completed_task_id: CampaignTaskId,
    succ1: CampaignTaskId,
) -> None:
    _ready, skipped = service.resolve(
        completed_task_id,
        TaskOutcome.SUCCESS,
        [(succ1, "ExecuteIfObjectiveMet", None)],
        ObjectiveStateMap(),
    )
    assert succ1 in skipped


def test_unknown_predicate_defaults_to_execute(
    service: BranchResolutionService,
    completed_task_id: CampaignTaskId,
    succ1: CampaignTaskId,
) -> None:
    ready, _skipped = service.resolve(
        completed_task_id,
        TaskOutcome.SUCCESS,
        [(succ1, "UnknownFuturePredicate", None)],
        ObjectiveStateMap(),
    )
    assert succ1 in ready


def test_timed_out_outcome_matches_execute_on_failure(
    service: BranchResolutionService,
    completed_task_id: CampaignTaskId,
    succ1: CampaignTaskId,
) -> None:
    ready, _skipped = service.resolve(
        completed_task_id,
        TaskOutcome.TIMED_OUT,
        [(succ1, "ExecuteOnFailure", None)],
        ObjectiveStateMap(),
    )
    assert succ1 in ready
