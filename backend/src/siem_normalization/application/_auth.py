"""Role authorization — canonical siem_normalization:* roles."""

from __future__ import annotations

from siem_normalization.application.exceptions import ApplicationForbiddenError
from siem_normalization.domain.value_objects.enums import NormalizationRole

_ROLE_RANK = {
    NormalizationRole.VIEWER.value: 1,
    NormalizationRole.EXECUTOR.value: 2,
    NormalizationRole.ADMIN.value: 3,
}


def require_at_least(actor_roles: tuple[str, ...], minimum: NormalizationRole) -> None:
    needed = _ROLE_RANK[minimum.value]
    best = max((_ROLE_RANK.get(r, 0) for r in actor_roles), default=0)
    if best < needed:
        raise ApplicationForbiddenError(minimum.value)
