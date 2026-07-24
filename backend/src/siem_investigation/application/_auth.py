"""Role authorization — canonical siem_investigation:* roles."""

from __future__ import annotations

from siem_investigation.application.exceptions import ApplicationForbiddenError
from siem_investigation.domain.value_objects.enums import InvestigationEngineRole

_ROLE_RANK = {
    InvestigationEngineRole.VIEWER.value: 1,
    InvestigationEngineRole.EXECUTOR.value: 2,
    InvestigationEngineRole.ADMIN.value: 3,
}


def require_at_least(actor_roles: tuple[str, ...], minimum: InvestigationEngineRole) -> None:
    needed = _ROLE_RANK[minimum.value]
    best = max((_ROLE_RANK.get(r, 0) for r in actor_roles), default=0)
    if best < needed:
        raise ApplicationForbiddenError(minimum.value)
