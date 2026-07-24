"""CQRS commands for siem_normalization's Event Normalization Framework
(M42 Phase 4). A `NormalizeEventCommand` carries an opaque, provider-
native `raw_payload` — this framework never interprets its shape
itself, only routes it to whichever `IEventNormalizer` the registry
resolves for `provider` (M43D §2/§3).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping

    from redforge.shared.identifiers import EntityId


@dataclass(frozen=True, slots=True)
class NormalizeEventCommand:
    tenant_id: EntityId
    provider: str
    raw_payload: Mapping[str, object]
    declared_schema_version_raw: str
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class NormalizeBatchCommand:
    tenant_id: EntityId
    events: tuple[NormalizeEventCommand, ...] = field(default_factory=tuple)
    actor_roles: tuple[str, ...] = ()
