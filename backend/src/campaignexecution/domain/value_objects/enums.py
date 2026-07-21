"""campaignexecution domain enums."""

from __future__ import annotations

from enum import StrEnum


class ExecutionState(StrEnum):
    INITIALIZING = "Initializing"
    RUNNING = "Running"
    WAITING_FOR_APPROVAL = "WaitingForApproval"
    PAUSED = "Paused"
    ROLLING_BACK = "RollingBack"
    COMPLETED = "Completed"
    FAILED = "Failed"
    ABORTED = "Aborted"


class TaskExecutionState(StrEnum):
    PENDING = "Pending"
    READY_TO_DISPATCH = "ReadyToDispatch"
    DISPATCHING = "Dispatching"
    RUNNING = "Running"
    COMPLETED = "Completed"
    FAILED = "Failed"
    SKIPPED = "Skipped"
    ROLLED_BACK = "RolledBack"
    TIMED_OUT = "TimedOut"


class TaskOutcome(StrEnum):
    SUCCESS = "Success"
    FAILURE = "Failure"
    PARTIAL_SUCCESS = "PartialSuccess"
    TIMED_OUT = "TimedOut"
    SKIPPED = "Skipped"
    ABORTED = "Aborted"


class MonitorState(StrEnum):
    ACTIVE = "Active"
    ABORTED = "Aborted"
    RELEASED = "Released"
