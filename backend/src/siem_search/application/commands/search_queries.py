"""Immutable CQRS query objects for siem_search's Search Engine
(M42 Phase 10 / M44E).

One parameterized `SearchQuery` (keyed by `SearchEntityType`) rather
than five duplicated classes (`SearchEventsQuery`, `SearchAlertsQuery`,
...): validation and execution are identical across entity types —
only the registry key differs — and five near-identical dataclasses
would be exactly the "duplicated validation" every prior SIEM engine
milestone's review was checked against. Construct one per target, e.g.
`SearchQuery(entity_type=SearchEntityType.ALERTS, ...)`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Mapping

    from redforge.shared.identifiers import EntityId
    from siem_search.domain.value_objects.enums import SearchEntityType, SearchQueryShape
    from siem_search.domain.value_objects.sort_field import SortField
    from siem_search.domain.value_objects.time_range import TimeRange


@dataclass(frozen=True, slots=True)
class SearchQuery:
    tenant_id: EntityId
    entity_type: SearchEntityType
    time_range: TimeRange
    shape: SearchQueryShape
    schema_version_raw: str
    filters: Mapping[str, object] = field(default_factory=dict)
    sort: tuple[SortField, ...] = ()
    page_size: int = 50
    offset: int = 0
    actor_roles: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class SearchBatchQuery:
    tenant_id: EntityId
    queries: tuple[SearchQuery, ...] = field(default_factory=tuple)
    actor_roles: tuple[str, ...] = ()
