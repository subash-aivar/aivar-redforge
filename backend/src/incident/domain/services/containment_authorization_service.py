"""Static containment authorization matrix (frozen — not configurable)."""

from __future__ import annotations

from incident.domain.exceptions.domain_exceptions import AuthorizationDenied
from incident.domain.value_objects.enums import (
    ContainmentActionType,
    ContainmentAuthorizationLevel,
    IncidentRole,
)

_MATRIX: dict[ContainmentActionType, ContainmentAuthorizationLevel] = {
    ContainmentActionType.ALERT_ESCALATION: ContainmentAuthorizationLevel.ANALYST,
    ContainmentActionType.TRAFFIC_LOGGING: ContainmentAuthorizationLevel.ANALYST,
    ContainmentActionType.PROCESS_TERMINATION: ContainmentAuthorizationLevel.ANALYST,
    ContainmentActionType.SERVICE_SUSPENSION: ContainmentAuthorizationLevel.COMMANDER,
    ContainmentActionType.CREDENTIAL_REVOKE: ContainmentAuthorizationLevel.COMMANDER,
    ContainmentActionType.ACCOUNT_DISABLE: ContainmentAuthorizationLevel.COMMANDER,
    ContainmentActionType.TRAFFIC_BLOCK: ContainmentAuthorizationLevel.COMMANDER,
    ContainmentActionType.NETWORK_ISOLATION: ContainmentAuthorizationLevel.CISO,
    ContainmentActionType.MASS_CREDENTIAL_REVOKE: ContainmentAuthorizationLevel.CISO,
    ContainmentActionType.MANUAL: ContainmentAuthorizationLevel.COMMANDER,
}

_ROLE_LEVEL = {
    IncidentRole.ANALYST.value: ContainmentAuthorizationLevel.ANALYST,
    IncidentRole.COMMANDER.value: ContainmentAuthorizationLevel.COMMANDER,
    IncidentRole.CISO.value: ContainmentAuthorizationLevel.CISO,
}

_LEVEL_RANK = {
    ContainmentAuthorizationLevel.ANALYST: 1,
    ContainmentAuthorizationLevel.COMMANDER: 2,
    ContainmentAuthorizationLevel.CISO: 3,
}


class ContainmentAuthorizationService:
    def required_authorization_level(
        self, action_type: ContainmentActionType
    ) -> ContainmentAuthorizationLevel:
        return _MATRIX[action_type]

    def assert_authorized(self, action_type: ContainmentActionType, roles: tuple[str, ...]) -> None:
        needed = self.required_authorization_level(action_type)
        best = max(
            (_LEVEL_RANK.get(_ROLE_LEVEL[r], 0) for r in roles if r in _ROLE_LEVEL),
            default=0,
        )
        if best < _LEVEL_RANK[needed]:
            raise AuthorizationDenied(f"{action_type.value} requires {needed.value}; roles={roles}")
