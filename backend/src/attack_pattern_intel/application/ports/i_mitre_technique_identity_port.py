"""IMitreTechniqueIdentityPort — the ACL contract over canonical MITRE
technique identity, owned by `redforge.domain.threat_intel` (M22,
DO-NOT-MODIFY).

`attack_pattern_intel` never queries `threat_intel`'s domain classes
directly, and never duplicates the technique/tactic catalog. This
port is the single, read-only, narrow seam between the two contexts.
A concrete infrastructure adapter implements it by querying the
existing `attack_techniques`/`attack_tactics` tables read-only
(SQLAlchemy Core, or the existing infra-level model classes — never
the domain aggregate types).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class MitreTechniqueSnapshot:
    """A one-time, read-only snapshot of legacy descriptive fields at
    the moment an `AttackPattern` is created. `attack_pattern_intel`
    owns its own `platforms`/`tactic_mappings` VOs going forward — this
    snapshot is never re-synced or treated as a live mirror."""

    technique_id: str
    name: str
    tactic_ids: tuple[str, ...]
    platforms: tuple[str, ...]
    is_sub_technique: bool
    is_deprecated: bool
    is_revoked: bool


class IMitreTechniqueIdentityPort(ABC):
    @abstractmethod
    async def exists(self, technique_id: str) -> bool:
        """True iff `technique_id` (base or sub-technique form) is a
        known technique in the canonical `threat_intel` catalog."""
        ...

    @abstractmethod
    async def get_snapshot(self, technique_id: str) -> MitreTechniqueSnapshot | None:
        """Read-only descriptive snapshot, or `None` if unknown."""
        ...
