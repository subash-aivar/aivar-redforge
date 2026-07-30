"""ORM <-> domain mapping helpers shared across attack_surface_management
repositories (M49C), mirroring `risk_engine.infrastructure.persistence.
mappers`'s "small shared helpers in one module, everything else
colocated with its owning repository" convention. Unlike risk_engine's
two aggregates (which share an identical flattened
`RiskSignalReference` shape), `Asset` and `NetworkRange` have no
overlapping child-row shape, so the only genuinely shared helper here
is `new_uuid` — every `_row_to_*`/`_to_domain` mapping function lives
next to the repository that owns it, per that same precedent."""

from __future__ import annotations

from uuid import UUID, uuid4


def new_uuid() -> UUID:
    return uuid4()
