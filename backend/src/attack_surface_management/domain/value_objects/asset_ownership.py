"""AssetOwnership value object (M49A) — the accountable team/contact
for an asset. Deliberately a plain opaque-string pair, not a rich
Team/User entity: this milestone must not model (and must not
duplicate) any identity/organization bounded context's own entities —
it only needs enough to answer "who owns this asset"."""

from __future__ import annotations

from dataclasses import dataclass

from attack_surface_management.domain.exceptions.domain_exceptions import (
    InvalidAssetOwnershipError,
)


@dataclass(frozen=True, slots=True)
class AssetOwnership:
    owning_team: str
    contact: str | None = None

    def __post_init__(self) -> None:
        if not self.owning_team.strip():
            raise InvalidAssetOwnershipError("owning_team must be non-empty")
