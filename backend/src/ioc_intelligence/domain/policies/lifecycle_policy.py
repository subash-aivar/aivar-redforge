"""IocLifecyclePolicy — the legal `IocLifecycle` transition table
(M51.2 Phase A).

Generalizes `redforge.domain.threat_intel.fusion_entity.FusedIndicator`'s
already-proven `_ALLOWED_TRANSITIONS` table exactly (same shape, own
type): `ACTIVE -> {SUPERSEDED, EXPIRED, REVOKED}`, `SUPERSEDED ->
{REVOKED}`, `EXPIRED -> {ACTIVE}` (refresh re-activates), `REVOKED ->
{}` (terminal). Lifecycle is operational relevance — separate from
`EpistemicState` (how strongly the claim is trusted); see
`EpistemicStatePolicy` for that axis."""

from __future__ import annotations

from ioc_intelligence.domain.exceptions.domain_exceptions import InvalidLifecycleTransitionError
from ioc_intelligence.domain.value_objects.enums import IocLifecycle

_ALLOWED_TRANSITIONS: dict[IocLifecycle, frozenset[IocLifecycle]] = {
    IocLifecycle.ACTIVE: frozenset(
        {
            IocLifecycle.SUPERSEDED,
            IocLifecycle.EXPIRED,
            IocLifecycle.REVOKED,
        }
    ),
    IocLifecycle.SUPERSEDED: frozenset({IocLifecycle.REVOKED}),
    IocLifecycle.EXPIRED: frozenset(
        {
            IocLifecycle.ACTIVE,  # refresh re-activates
            IocLifecycle.REVOKED,
        }
    ),
    IocLifecycle.REVOKED: frozenset(),
}


class IocLifecyclePolicy:
    @staticmethod
    def assert_legal_transition(current: IocLifecycle, target: IocLifecycle) -> None:
        if target not in _ALLOWED_TRANSITIONS[current]:
            raise InvalidLifecycleTransitionError(current.value, target.value)
