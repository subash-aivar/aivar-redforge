from __future__ import annotations

from ai_supply_chain.application.exceptions import ApplicationForbiddenError
from ai_supply_chain.domain.value_objects.enums import AIPostureRole

_ROLE_RANK = {
    AIPostureRole.READER.value: 1,
    AIPostureRole.AUDITOR.value: 1,
    AIPostureRole.ANALYST.value: 2,
    AIPostureRole.ENGINEER.value: 3,
    AIPostureRole.APPROVER.value: 4,
    AIPostureRole.ADMIN.value: 5,
}


def require_at_least(actor_roles: tuple[str, ...], minimum: AIPostureRole) -> None:
    needed = _ROLE_RANK[minimum.value]
    best = max((_ROLE_RANK.get(r, 0) for r in actor_roles), default=0)
    auditor_only_blocked = (
        minimum != AIPostureRole.READER
        and AIPostureRole.AUDITOR.value in actor_roles
        and not any(
            _ROLE_RANK.get(r, 0) >= needed and r != AIPostureRole.AUDITOR.value for r in actor_roles
        )
    )
    if auditor_only_blocked or best < needed:
        raise ApplicationForbiddenError(minimum.value)
