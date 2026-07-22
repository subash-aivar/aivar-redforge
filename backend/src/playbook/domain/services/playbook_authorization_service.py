"""Dual-authorization matrix — ADR-M35-001 / C1."""

from __future__ import annotations

from playbook.domain.exceptions.domain_exceptions import (
    PlaybookAuthorizationDenied,
    SeparationOfDutiesViolation,
)
from playbook.domain.value_objects.enums import ActionImpactLevel

_APPROVAL_MATRIX: dict[ActionImpactLevel, tuple[str, int]] = {
    ActionImpactLevel.LOW: ("soc:analyst", 1),
    ActionImpactLevel.MEDIUM: ("soc:commander", 1),
    ActionImpactLevel.HIGH: ("soc:commander", 2),
    ActionImpactLevel.CRITICAL: ("incident:ciso", 2),
}

_RUNTIME_MATRIX: dict[ActionImpactLevel, str | None] = {
    ActionImpactLevel.LOW: None,
    ActionImpactLevel.MEDIUM: None,
    ActionImpactLevel.HIGH: "soc:commander",
    ActionImpactLevel.CRITICAL: "incident:ciso",
}

_ROLE_RANK = {
    "playbook:analyst": 1,
    "soc:analyst": 2,
    "playbook:engineer": 3,
    "automation:operator": 3,
    "soc:commander": 4,
    "incident:ciso": 5,
    "integration:admin": 3,
}


class PlaybookAuthorizationService:
    def approval_requirements(self, max_impact_level: ActionImpactLevel) -> tuple[str, int]:
        return _APPROVAL_MATRIX[max_impact_level]

    def assert_approval_authorized(
        self,
        max_impact_level: ActionImpactLevel,
        approver_roles: tuple[str, ...],
        *,
        existing_approver_count: int = 0,
    ) -> None:
        min_role, quorum = _APPROVAL_MATRIX[max_impact_level]
        if max_impact_level == ActionImpactLevel.CRITICAL:
            # Dual: one soc:commander + one incident:ciso across the quorum
            if existing_approver_count == 0:
                if "soc:commander" not in approver_roles and "incident:ciso" not in approver_roles:
                    raise PlaybookAuthorizationDenied(
                        "Impact CRITICAL requires role soc:commander or incident:ciso"
                    )
            else:
                if "incident:ciso" not in approver_roles and "soc:commander" not in approver_roles:
                    raise PlaybookAuthorizationDenied(
                        "Impact CRITICAL requires complementary approver roles"
                    )
            return
        if min_role not in approver_roles:
            raise PlaybookAuthorizationDenied(
                f"Impact {max_impact_level.value} requires role {min_role}"
            )
        del quorum

    def runtime_authorization_required(self, impact_level: ActionImpactLevel) -> str | None:
        return _RUNTIME_MATRIX[impact_level]

    def assert_runtime_authorized(
        self,
        impact_level: ActionImpactLevel,
        authorizer_roles: tuple[str, ...],
        authorizer_id: str,
        trigger_operator_id: str,
    ) -> None:
        required_role = self.runtime_authorization_required(impact_level)
        if required_role is None:
            return
        if authorizer_id == trigger_operator_id:
            raise SeparationOfDutiesViolation(
                "Runtime authorizer must differ from the operator who triggered execution"
            )
        if required_role not in authorizer_roles:
            raise PlaybookAuthorizationDenied(
                f"Runtime authorization for {impact_level.value} requires role {required_role}"
            )

    def has_role(self, roles: tuple[str, ...], required: str) -> bool:
        return required in roles or _ROLE_RANK.get(
            max(roles, key=lambda r: _ROLE_RANK.get(r, 0), default=""), 0
        ) >= _ROLE_RANK.get(required, 99)
