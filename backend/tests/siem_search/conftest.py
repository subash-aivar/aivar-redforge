from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from redforge.shared.identifiers import EntityId
from siem_search.application.commands.search_queries import SearchQuery
from siem_search.application.dtos.search_hit import SearchHit, SearchResultPage
from siem_search.domain.value_objects.enums import SearchEntityType, SearchQueryShape, SearchRole
from siem_search.domain.value_objects.time_range import TimeRange
from siem_shared.domain.value_objects.schema_version import SchemaVersion

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping, Sequence

    from siem_search.domain.value_objects.sort_field import SortField

VIEWER_ROLES = (SearchRole.VIEWER.value,)
SCHEMA_V1_0 = SchemaVersion(1, 0)
NOW = datetime.now(UTC)
DEFAULT_TIME_RANGE = TimeRange(start=NOW - timedelta(hours=1), end=NOW)


class FakeSearchProvider:
    def __init__(
        self,
        entity_type: SearchEntityType,
        schema_version: SchemaVersion = SCHEMA_V1_0,
        handler: Callable[..., SearchResultPage] | None = None,
    ) -> None:
        self._entity_type = entity_type
        self._schema_version = schema_version
        self._handler = handler

    @property
    def entity_type(self) -> SearchEntityType:
        return self._entity_type

    @property
    def schema_version(self) -> SchemaVersion:
        return self._schema_version

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
        if self._handler is None:
            raise AssertionError("FakeSearchProvider.search called with no handler set")
        return self._handler(tenant_id, time_range, shape, filters, sort, page_size, offset)


def fixed_page(hits: tuple[SearchHit, ...] = (), total_hits: int | None = None):
    def _handler(tenant_id, time_range, shape, filters, sort, page_size, offset):
        return SearchResultPage(
            hits=hits,
            total_hits=total_hits if total_hits is not None else len(hits),
            page_size=page_size,
            offset=offset,
            has_more=False,
        )

    return _handler


def make_hit(entity_type: str = "events", entity_id: str = "e-1", score: float = 1.0) -> SearchHit:
    return SearchHit(entity_type=entity_type, entity_id=entity_id, score=score)


def make_query(**overrides: object) -> SearchQuery:
    defaults: dict[str, object] = {
        "tenant_id": EntityId.generate(),
        "entity_type": SearchEntityType.EVENTS,
        "time_range": DEFAULT_TIME_RANGE,
        "shape": SearchQueryShape.STRUCTURED,
        "schema_version_raw": "1.0",
        "actor_roles": VIEWER_ROLES,
    }
    defaults.update(overrides)
    return SearchQuery(**defaults)  # type: ignore[arg-type]
