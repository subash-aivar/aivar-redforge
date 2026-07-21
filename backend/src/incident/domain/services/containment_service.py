"""ContainmentService — thin facade over authorization + action lifecycle."""

from __future__ import annotations

from incident.domain.services.containment_authorization_service import (
    ContainmentAuthorizationService,
)


class ContainmentService:
    def __init__(self) -> None:
        self.authz = ContainmentAuthorizationService()
