"""Enumerations for the TaskGraph domain."""

from __future__ import annotations

from enum import StrEnum


class TaskGraphState(StrEnum):
    DRAFT = "Draft"
    VALIDATED = "Validated"
    SIGNED = "Signed"
    ACTIVE = "Active"
    DEPRECATED = "Deprecated"


class TaskType(StrEnum):
    OPERATION_TASK = "OperationTask"
    WAIT_TASK = "WaitTask"
    HUMAN_APPROVAL_TASK = "HumanApprovalTask"
    EVALUATION_CHECKPOINT = "EvaluationCheckpoint"
    ROLLBACK_TASK = "RollbackTask"
    BARRIER_TASK = "BarrierTask"


class TaskCriticality(StrEnum):
    OPTIONAL = "Optional"
    REQUIRED = "Required"
    CRITICAL_PATH = "CriticalPath"


class DependencyPredicate(StrEnum):
    ALWAYS_EXECUTE = "AlwaysExecute"
    EXECUTE_ON_SUCCESS = "ExecuteOnSuccess"
    EXECUTE_ON_FAILURE = "ExecuteOnFailure"
    EXECUTE_IF_OBJECTIVE_MET = "ExecuteIfObjectiveMet"
    EXECUTE_IF_OBJECTIVE_FAILED = "ExecuteIfObjectiveFailed"
    EXECUTE_IF_DETECTION_FIRED = "ExecuteIfDetectionFired"
    EXECUTE_IF_DETECTION_SILENT = "ExecuteIfDetectionSilent"
