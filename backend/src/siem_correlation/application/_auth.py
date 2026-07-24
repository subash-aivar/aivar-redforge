"""Role authorization — canonical siem_correlation:* roles."""

from __future__ import annotations

from siem_correlation.application.exceptions import ApplicationForbiddenError
from siem_correlation.domain.value_objects.enums import CorrelationRole

_ROLE_RANK = {
    CorrelationRole.VIEWER.value: 1,
    CorrelationRole.EXECUTOR.value: 2,
    CorrelationRole.ADMIN.value: 3,
}


def require_at_least(actor_roles: tuple[str, ...], minimum: CorrelationRole) -> None:
    needed = _ROLE_RANK[minimum.value]
    best = max((_ROLE_RANK.get(r, 0) for r in actor_roles), default=0)
    if best < needed:
        raise ApplicationForbiddenError(minimum.value)
