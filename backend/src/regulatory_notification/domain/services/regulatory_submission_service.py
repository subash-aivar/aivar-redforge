from __future__ import annotations

from regulatory_notification.domain.exceptions.domain_exceptions import AutoSubmissionProhibited


class RegulatorySubmissionService:
    """Human-commanded submission only — timers must never call submit."""

    def ensure_human_command(self, command_name: str) -> None:
        if command_name != "SubmitRegulatoryNotification":
            raise AutoSubmissionProhibited("submission requires explicit human command")
