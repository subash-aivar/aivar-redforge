"""Role authorization — canonical siem_search:* roles."""

from __future__ import annotations

from siem_search.application.exceptions import ApplicationForbiddenError
from siem_search.domain.value_objects.enums import SearchRole

_ROLE_RANK = {
    SearchRole.VIEWER.value: 1,
    SearchRole.ADMIN.value: 2,
}


def require_at_least(actor_roles: tuple[str, ...], minimum: SearchRole) -> None:
    needed = _ROLE_RANK[minimum.value]
    best = max((_ROLE_RANK.get(r, 0) for r in actor_roles), default=0)
    if best < needed:
        raise ApplicationForbiddenError(minimum.value)
