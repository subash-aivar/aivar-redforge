"""Exceptions for the Security Posture bounded context."""

from __future__ import annotations


class PostureDomainError(Exception):
    """Base for all posture domain exceptions."""


class BaselineNotFoundError(PostureDomainError):
    """No active baseline exists for the given target."""

    def __init__(self, organization_id: str, target_id: str) -> None:
        super().__init__(
            f"No active baseline found for target {target_id!r} "
            f"in organization {organization_id!r}"
        )
        self.organization_id = organization_id
        self.target_id = target_id


class BaselineAlreadyActiveError(PostureDomainError):
    """An active baseline already exists; supersede it first."""

    def __init__(self, baseline_id: str, target_id: str) -> None:
        super().__init__(
            f"Baseline {baseline_id!r} is already active for target {target_id!r}. "
            "Call supersede() before establishing a new one."
        )
        self.baseline_id = baseline_id
        self.target_id = target_id


class BaselineAlreadyTerminalError(PostureDomainError):
    """Attempted to modify a baseline in a terminal state."""

    def __init__(self, baseline_id: str, status: str) -> None:
        super().__init__(
            f"Baseline {baseline_id!r} is in terminal state {status!r} "
            "and cannot be modified."
        )
        self.baseline_id = baseline_id
        self.status = status


class InsufficientHistoryError(PostureDomainError):
    """Not enough snapshots to compute a trend."""

    def __init__(self, target_id: str, required: int, available: int) -> None:
        super().__init__(
            f"Trend computation for target {target_id!r} requires {required} snapshots, "
            f"but only {available} are available in the window."
        )
        self.target_id = target_id
        self.required = required
        self.available = available


class SnapshotNotFoundError(PostureDomainError):
    """Snapshot ID does not exist."""

    def __init__(self, snapshot_id: str) -> None:
        super().__init__(f"ValidationSnapshot {snapshot_id!r} not found.")
        self.snapshot_id = snapshot_id
