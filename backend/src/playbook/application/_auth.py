from __future__ import annotations

from playbook.application.exceptions import ApplicationForbiddenError

_RANK = {
    "playbook:analyst": 1,
    "soc:analyst": 2,
    "playbook:engineer": 3,
    "automation:operator": 3,
    "integration:admin": 3,
    "soc:commander": 4,
    "incident:ciso": 5,
}


def require_any(roles: tuple[str, ...], *allowed: str) -> None:
    if not any(r in roles for r in allowed):
        # allow higher ranks for commander/ciso paths
        best = max((_RANK.get(r, 0) for r in roles), default=0)
        needed = min((_RANK.get(a, 99) for a in allowed), default=99)
        if best < needed:
            raise ApplicationForbiddenError(",".join(allowed))


def require_role(roles: tuple[str, ...], role: str) -> None:
    require_any(roles, role)
