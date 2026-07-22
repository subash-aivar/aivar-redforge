"""Design-time approval orchestration helpers."""

from __future__ import annotations

from playbook.domain.services.playbook_authorization_service import PlaybookAuthorizationService
from playbook.domain.value_objects.enums import ActionImpactLevel


class PlaybookApprovalService:
    def __init__(self) -> None:
        self._authz = PlaybookAuthorizationService()

    def quorum_for(self, level: ActionImpactLevel) -> int:
        return self._authz.approval_requirements(level)[1]
