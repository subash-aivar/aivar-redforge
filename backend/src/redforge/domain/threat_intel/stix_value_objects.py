"""Value objects for STIX 2.1 parsing — M22 Phase 3 (STIX/TAXII
Integration).

`StixId` validates the exact STIX 2.1 object identifier grammar
(`<type>--<UUID>`, e.g. `attack-pattern--0042a9f5-f053-4769-b3ef-9ad018dfe1a6`)
so a malformed identifier is rejected at construction, never carried
silently into the ACL mapper or a persisted `stix_id` column. Mirrors
the exact frozen-dataclass-with-`__post_init__` convention every other
value object in this bounded context uses (`TechniqueId`, `TacticId`,
`CveId` — M22 Phase 1; `FeedKey` — M22 Phase 2).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from redforge.domain.threat_intel.stix_exceptions import InvalidStixIdError

_STIX_ID_RE = re.compile(
    r"^[a-z][a-z0-9-]{2,49}--"
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


@dataclass(frozen=True, slots=True)
class StixId:
    """A validated STIX 2.1 object identifier."""

    value: str

    def __post_init__(self) -> None:
        if not _STIX_ID_RE.match(self.value):
            raise InvalidStixIdError(self.value)

    @property
    def stix_type(self) -> str:
        """The STIX object type prefix (e.g. `attack-pattern`)."""
        return self.value.split("--", 1)[0]

    def __str__(self) -> str:
        return self.value
