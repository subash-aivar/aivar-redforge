from __future__ import annotations

from incident.application.exceptions import ApplicationForbiddenError
from incident.domain.value_objects.enums import IncidentRole

_RANK = {
    IncidentRole.VIEWER.value: 1,
    IncidentRole.ANALYST.value: 2,
    IncidentRole.COMMANDER.value: 3,
    IncidentRole.CISO.value: 4,
}


def require_at_least(roles: tuple[str, ...], minimum: IncidentRole) -> None:
    needed = _RANK[minimum.value]
    best = max((_RANK.get(r, 0) for r in roles), default=0)
    if best < needed:
        raise ApplicationForbiddenError(minimum.value)
