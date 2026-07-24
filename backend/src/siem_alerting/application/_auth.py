"""Role authorization — canonical siem_alerting:* roles."""

from __future__ import annotations

from siem_alerting.application.exceptions import ApplicationForbiddenError
from siem_alerting.domain.value_objects.enums import AlertEngineRole

_ROLE_RANK = {
    AlertEngineRole.VIEWER.value: 1,
    AlertEngineRole.EXECUTOR.value: 2,
    AlertEngineRole.ADMIN.value: 3,
}


def require_at_least(actor_roles: tuple[str, ...], minimum: AlertEngineRole) -> None:
    needed = _ROLE_RANK[minimum.value]
    best = max((_ROLE_RANK.get(r, 0) for r in actor_roles), default=0)
    if best < needed:
        raise ApplicationForbiddenError(minimum.value)
