"""ISearchProvider — the one open extension point for actually
executing a search (M37 §17). No concrete implementation lives in this
milestone (no Elasticsearch/OpenSearch backend).

Provider owns execution only — never query validation (that stays
`SearchApplicationService`'s job) and never analytics/aggregation
beyond what a single `SearchQueryShape.AGGREGATION` query itself asked
for (M44E's explicit "does not calculate analytics" boundary).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

    from redforge.shared.identifiers import EntityId
    from siem_search.application.dtos.search_hit import SearchResultPage
    from siem_search.domain.value_objects.enums import SearchEntityType, SearchQueryShape
    from siem_search.domain.value_objects.sort_field import SortField
    from siem_search.domain.value_objects.time_range import TimeRange
    from siem_shared.domain.value_objects.schema_version import SchemaVersion


class ISearchProvider(Protocol):
    """`entity_type` + `schema_version` together are the registry key
    (M44E §4), mirroring `IDetectionEvaluator`/`ICorrelationEvaluator`/
    `IAlertEvaluator`/`IInvestigationEvaluator`'s identical shape
    (M44A-M44D)."""

    @property
    def entity_type(self) -> SearchEntityType: ...

    @property
    def schema_version(self) -> SchemaVersion: ...

    def search(
        self,
        tenant_id: EntityId,
        time_range: TimeRange,
        shape: SearchQueryShape,
        filters: Mapping[str, object],
        sort: Sequence[SortField],
        page_size: int,
        offset: int,
    ) -> SearchResultPage:
        """Execute one bounded, paginated search. Implementations
        should raise on a query shape/filter combination they cannot
        execute — the framework translates that into a `FAILED`
        outcome, it does not swallow it."""
        ...
