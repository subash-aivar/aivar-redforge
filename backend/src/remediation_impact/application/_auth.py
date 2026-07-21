"""Authorization helpers — Finalization + Review I06 simulation_reader."""

from __future__ import annotations

from remediation_impact.application.exceptions import ApplicationForbiddenError
from remediation_impact.domain.value_objects.enums import RemediationImpactRole

_ROLE_RANK = {
    RemediationImpactRole.VIEWER.value: 1,
    RemediationImpactRole.ANALYST.value: 2,
    RemediationImpactRole.ENGINEER.value: 3,
    RemediationImpactRole.ADMIN.value: 4,
}


def require_at_least(actor_roles: tuple[str, ...], minimum: RemediationImpactRole) -> None:
    needed = _ROLE_RANK[minimum.value]
    best = max((_ROLE_RANK.get(r, 0) for r in actor_roles), default=0)
    if best < needed:
        raise ApplicationForbiddenError(minimum.value)


def require_simulation_read(actor_roles: tuple[str, ...]) -> None:
    """Plan reads require simulation_reader OR analyst+."""
    if RemediationImpactRole.SIMULATION_READER.value in actor_roles:
        return
    require_at_least(actor_roles, RemediationImpactRole.ANALYST)
