"""Role authorization — canonical siem_storage:* roles."""

from __future__ import annotations

from siem_storage.application.exceptions import ApplicationForbiddenError
from siem_storage.domain.value_objects.enums import StorageRole

_ROLE_RANK = {
    StorageRole.VIEWER.value: 1,
    StorageRole.PLANNER.value: 2,
    StorageRole.ADMIN.value: 3,
}


def require_at_least(actor_roles: tuple[str, ...], minimum: StorageRole) -> None:
    needed = _ROLE_RANK[minimum.value]
    best = max((_ROLE_RANK.get(r, 0) for r in actor_roles), default=0)
    if best < needed:
        raise ApplicationForbiddenError(minimum.value)
