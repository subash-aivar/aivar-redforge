from __future__ import annotations

from automated_action.domain.exceptions.domain_exceptions import (
    SeparationOfDutiesViolation,
)
from automated_action.domain.value_objects.enums import ActionImpactLevel

_RUNTIME: dict[ActionImpactLevel, str | None] = {
    ActionImpactLevel.LOW: None,
    ActionImpactLevel.MEDIUM: None,
    ActionImpactLevel.HIGH: "soc:commander",
    ActionImpactLevel.CRITICAL: "incident:ciso",
}


class AutomationAuthorizationService:
    def runtime_role(self, level: ActionImpactLevel) -> str | None:
        return _RUNTIME[level]

    def assert_runtime_authorized(
        self,
        impact_level: ActionImpactLevel,
        authorizer_roles: tuple[str, ...],
        authorizer_id: str,
        trigger_operator_id: str,
    ) -> None:
        required = self.runtime_role(impact_level)
        if required is None:
            return
        if authorizer_id == trigger_operator_id:
            raise SeparationOfDutiesViolation(
                "Runtime authorizer must differ from the operator who triggered execution"
            )
        if required not in authorizer_roles:
            raise SeparationOfDutiesViolation(f"requires role {required}")
