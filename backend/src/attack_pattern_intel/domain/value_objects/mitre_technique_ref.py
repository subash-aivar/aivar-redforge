"""MitreTechniqueRef — opaque reference to canonical MITRE technique
identity owned by `redforge.domain.threat_intel` (M22).

attack_pattern_intel never duplicates technique/tactic catalog data;
this VO carries only the `technique_id` string (format-validated) plus
an optional `sub_technique_id`. Existence against the real catalog is
verified by the application layer via `IMitreTechniqueIdentityPort`
BEFORE an `AttackPattern` is constructed — this VO performs syntactic
validation only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from attack_pattern_intel.domain.exceptions.domain_exceptions import InvalidTechniqueIdError

_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}$")
_SUB_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}\.\d{3}$")


@dataclass(frozen=True, slots=True)
class MitreTechniqueRef:
    """`technique_id` is always the base `T####` id. `sub_technique_id`,
    when present, is the full `T####.###` form (redundant with
    `technique_id`'s prefix by construction — kept explicit so callers
    never have to re-derive the parent id)."""

    technique_id: str
    sub_technique_id: str | None = None

    def __post_init__(self) -> None:
        if not _TECHNIQUE_ID_RE.match(self.technique_id):
            raise InvalidTechniqueIdError(self.technique_id)
        if self.sub_technique_id is not None:
            if not _SUB_TECHNIQUE_ID_RE.match(self.sub_technique_id):
                raise InvalidTechniqueIdError(self.sub_technique_id)
            if not self.sub_technique_id.startswith(f"{self.technique_id}."):
                raise InvalidTechniqueIdError(self.sub_technique_id)

    @property
    def is_sub_technique(self) -> bool:
        return self.sub_technique_id is not None

    @property
    def effective_id(self) -> str:
        """The most-specific id: sub-technique if present, else the
        base technique id."""
        return self.sub_technique_id or self.technique_id

    def __str__(self) -> str:
        return self.effective_id
