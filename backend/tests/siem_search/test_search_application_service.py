from __future__ import annotations

import dataclasses

import pytest

from siem_search.application.commands.search_queries import SearchBatchQuery
from siem_search.application.dtos.search_outcome import SearchStatus
from siem_search.application.exceptions import ApplicationForbiddenError, EmptyBatchSearchError
from siem_search.application.registry.in_memory_search_provider_registry import (
    InMemorySearchProviderRegistry,
)
from siem_search.application.services.search_application_service import SearchApplicationService
from siem_search.domain.value_objects.enums import SearchEntityType, SortDirection
from siem_search.domain.value_objects.sort_field import SortField
from siem_shared.domain.value_objects.schema_version import SchemaVersion

from .conftest import FakeSearchProvider, fixed_page, make_hit, make_query


def _service(registry=None):
    return SearchApplicationService(provider_registry=registry or InMemorySearchProviderRegistry())


def _registry_with(entity_type, handler=None, hits=()):
    registry = InMemorySearchProviderRegistry()
    registry.register(
        FakeSearchProvider(entity_type, handler=handler or fixed_page(hits=hits, total_hits=len(hits)))
    )
    return registry


# ---------------------------------------------------------------------------
# per-entity-type search
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "entity_type",
    [
        SearchEntityType.EVENTS,
        SearchEntityType.ALERTS,
        SearchEntityType.INVESTIGATIONS,
        SearchEntityType.DETECTIONS,
        SearchEntityType.CORRELATION_SESSIONS,
    ],
)
def test_search_each_entity_type(entity_type):
    hit = make_hit(entity_type=entity_type.value)
    registry = _registry_with(entity_type, hits=(hit,))
    service = _service(registry)

    outcome = service.search(make_query(entity_type=entity_type))

    assert outcome.status == SearchStatus.SUCCEEDED
    assert outcome.page.hits == (hit,)


def test_search_without_role_raises_forbidden():
    service = _service()
    with pytest.raises(ApplicationForbiddenError):
        service.search(make_query(actor_roles=()))


# ---------------------------------------------------------------------------
# pagination
# ---------------------------------------------------------------------------


def test_pagination_is_passed_through_to_provider():
    captured = {}

    def _handler(tenant_id, time_range, shape, filters, sort, page_size, offset):
        from siem_search.application.dtos.search_hit import SearchResultPage

        captured["page_size"] = page_size
        captured["offset"] = offset
        return SearchResultPage(hits=(), total_hits=0, page_size=page_size, offset=offset, has_more=False)

    registry = _registry_with(SearchEntityType.EVENTS, handler=_handler)
    service = _service(registry)

    service.search(make_query(page_size=25, offset=50))

    assert captured == {"page_size": 25, "offset": 50}


def test_invalid_page_size_is_rejected():
    service = _service(_registry_with(SearchEntityType.EVENTS))
    outcome = service.search(make_query(page_size=0))

    assert outcome.status == SearchStatus.REJECTED
    assert outcome.failures[0].error_type == "InvalidPaginationError"


def test_oversized_page_size_is_rejected():
    service = _service(_registry_with(SearchEntityType.EVENTS))
    outcome = service.search(make_query(page_size=5000))

    assert outcome.status == SearchStatus.REJECTED


def test_negative_offset_is_rejected():
    service = _service(_registry_with(SearchEntityType.EVENTS))
    outcome = service.search(make_query(offset=-1))

    assert outcome.status == SearchStatus.REJECTED


# ---------------------------------------------------------------------------
# sorting
# ---------------------------------------------------------------------------


def test_sort_is_passed_through_to_provider():
    captured = {}

    def _handler(tenant_id, time_range, shape, filters, sort, page_size, offset):
        from siem_search.application.dtos.search_hit import SearchResultPage

        captured["sort"] = tuple(sort)
        return SearchResultPage(hits=(), total_hits=0, page_size=page_size, offset=offset, has_more=False)

    registry = _registry_with(SearchEntityType.EVENTS, handler=_handler)
    service = _service(registry)
    sort = (SortField(field_name="occurred_at", direction=SortDirection.DESC),)

    service.search(make_query(sort=sort))

    assert captured["sort"] == sort


def test_duplicate_sort_field_is_rejected():
    service = _service(_registry_with(SearchEntityType.EVENTS))
    sort = (SortField(field_name="occurred_at"), SortField(field_name="occurred_at"))
    outcome = service.search(make_query(sort=sort))

    assert outcome.status == SearchStatus.REJECTED
    assert outcome.failures[0].error_type == "InvalidSortError"


# ---------------------------------------------------------------------------
# filters
# ---------------------------------------------------------------------------


def test_invalid_filter_key_is_rejected():
    service = _service(_registry_with(SearchEntityType.EVENTS))
    outcome = service.search(make_query(filters={"": "x"}))

    assert outcome.status == SearchStatus.REJECTED
    assert outcome.failures[0].error_type == "InvalidFilterError"


# ---------------------------------------------------------------------------
# unsupported provider / schema compatibility
# ---------------------------------------------------------------------------


def test_unsupported_provider():
    service = _service()  # empty registry
    outcome = service.search(make_query())

    assert outcome.status == SearchStatus.UNSUPPORTED_PROVIDER


def test_malformed_schema_version_is_rejected():
    service = _service(_registry_with(SearchEntityType.EVENTS))
    outcome = service.search(make_query(schema_version_raw="garbage"))

    assert outcome.status == SearchStatus.REJECTED


def test_incompatible_schema_major_version_is_unsupported():
    registry = InMemorySearchProviderRegistry()
    registry.register(FakeSearchProvider(SearchEntityType.EVENTS, schema_version=SchemaVersion(2, 0)))
    service = _service(registry)

    outcome = service.search(make_query(schema_version_raw="1.0"))

    assert outcome.status == SearchStatus.UNSUPPORTED_PROVIDER


# ---------------------------------------------------------------------------
# provider exceptions
# ---------------------------------------------------------------------------


def test_provider_exception_produces_failed_outcome():
    def _explode(tenant_id, time_range, shape, filters, sort, page_size, offset):
        raise RuntimeError("backend unavailable")

    registry = _registry_with(SearchEntityType.EVENTS, handler=_explode)
    service = _service(registry)

    outcome = service.search(make_query())

    assert outcome.status == SearchStatus.FAILED
    assert outcome.failures[0].error_type == "RuntimeError"


# ---------------------------------------------------------------------------
# batch search
# ---------------------------------------------------------------------------


def test_batch_search_all_succeed():
    registry = _registry_with(SearchEntityType.EVENTS, hits=(make_hit(),))
    service = _service(registry)
    queries = tuple(make_query() for _ in range(3))

    result = service.search_batch(SearchBatchQuery(tenant_id=queries[0].tenant_id, queries=queries, actor_roles=("siem_search:viewer",)))

    assert result.status == SearchStatus.SUCCEEDED
    assert result.succeeded_count == 3


def test_batch_search_partial_failure():
    registry = _registry_with(SearchEntityType.EVENTS)
    service = _service(registry)
    queries = (
        make_query(entity_type=SearchEntityType.EVENTS),
        make_query(entity_type=SearchEntityType.ALERTS),  # unregistered
    )

    result = service.search_batch(
        SearchBatchQuery(tenant_id=queries[0].tenant_id, queries=queries, actor_roles=("siem_search:viewer",))
    )

    assert result.status == SearchStatus.PARTIALLY_SUCCEEDED
    assert result.succeeded_count == 1


def test_batch_search_empty_raises():
    service = _service()
    with pytest.raises(EmptyBatchSearchError):
        service.search_batch(
            SearchBatchQuery(
                tenant_id=make_query().tenant_id, queries=(), actor_roles=("siem_search:viewer",)
            )
        )


def test_batch_search_without_role_raises_forbidden():
    service = _service()
    with pytest.raises(ApplicationForbiddenError):
        service.search_batch(
            SearchBatchQuery(
                tenant_id=make_query().tenant_id, queries=(make_query(),), actor_roles=()
            )
        )


# ---------------------------------------------------------------------------
# immutability
# ---------------------------------------------------------------------------


def test_search_outcome_is_frozen():
    registry = _registry_with(SearchEntityType.EVENTS)
    service = _service(registry)
    outcome = service.search(make_query())
    with pytest.raises(dataclasses.FrozenInstanceError):
        outcome.status = SearchStatus.REJECTED  # type: ignore[misc]
