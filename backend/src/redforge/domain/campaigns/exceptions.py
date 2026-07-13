"""Domain exceptions for the Campaign bounded context."""

from __future__ import annotations

from redforge.core.exceptions import ConflictError, ValidationError


class InvalidCampaignTransitionError(ConflictError):
    """Raised when a Campaign lifecycle transition is not allowed from the current status."""

    def __init__(self, current: str, attempted: str) -> None:
        super().__init__(
            f"Cannot transition campaign from '{current}' to '{attempted}'"
        )
        self.current = current
        self.attempted = attempted


class CampaignAlreadyTerminalError(ConflictError):
    """Raised when an operation is attempted on a terminal (completed/failed/cancelled) campaign."""

    def __init__(self, campaign_id: str, status: str) -> None:
        super().__init__(
            f"Campaign '{campaign_id}' is already in terminal state '{status}'"
        )


class EmptyCampaignTargetsError(ValidationError):
    """Raised when a Campaign is created with no target IDs."""

    def __init__(self) -> None:
        super().__init__("A Campaign must have at least one target")


class CampaignNotPausedError(ConflictError):
    """Raised when resume() is called on a campaign that is not paused."""

    def __init__(self, campaign_id: str, status: str) -> None:
        super().__init__(
            f"Cannot resume campaign '{campaign_id}': current status is '{status}'"
        )


class CampaignNotRunningError(ConflictError):
    """Raised when pause() is called on a campaign that is not running."""

    def __init__(self, campaign_id: str, status: str) -> None:
        super().__init__(
            f"Cannot pause campaign '{campaign_id}': current status is '{status}'"
        )
