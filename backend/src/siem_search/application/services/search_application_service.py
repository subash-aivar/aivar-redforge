"""SearchApplicationService — the Search Engine's single application-
layer entrypoint (M42 Phase 10 / M44E).

Orchestrates, in order: authorization, query validation (pagination/
filters/sort/schema version — `query_validation.py`), provider
selection (`ISearchProviderRegistry`), and execution
(`ISearchProvider`). This service is read-only by construction: it
holds no state between calls, has no outbound "writer" port at all
(there is nothing to persist — search never mutates anything), and
never computes analytics/aggregation itself, only what a single
`ISearchProvider.search()` call returns.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from siem_search.application import _auth
from siem_search.application.dtos.search_outcome import (
    BatchSearchResult,
    SearchFailure,
    SearchOutcome,
    SearchStatus,
)
from siem_search.application.exceptions import (
    ApplicationValidationError,
    EmptyBatchSearchError,
    ProviderSelectionError,
)
from siem_search.application.services import query_validation
from siem_search.domain.exceptions.domain_exceptions import SiemSearchDomainError
from siem_search.domain.value_objects.enums import SearchRole
from siem_shared.domain.exceptions.domain_exceptions import SiemSharedDomainError
from siem_shared.domain.value_objects.schema_version import SchemaVersion

if TYPE_CHECKING:
    from siem_search.application.commands.search_queries import SearchBatchQuery, SearchQuery
    from siem_search.application.ports.i_search_provider_registry import ISearchProviderRegistry

_VALIDATION_ERRORS = (ApplicationValidationError, SiemSearchDomainError, SiemSharedDomainError)


def _to_failure(stage: str, exc: Exception) -> SearchFailure:
    return SearchFailure(stage=stage, error_type=type(exc).__name__, message=str(exc))


class SearchApplicationService:
    def __init__(self, provider_registry: ISearchProviderRegistry) -> None:
        self._registry = provider_registry

    def search(self, query: SearchQuery) -> SearchOutcome:
        _auth.require_at_least(query.actor_roles, SearchRole.VIEWER)
        return self._execute(query)

    def search_batch(self, cmd: SearchBatchQuery) -> BatchSearchResult:
        _auth.require_at_least(cmd.actor_roles, SearchRole.VIEWER)
        if not cmd.queries:
            raise EmptyBatchSearchError()

        outcomes = tuple(self._execute(query) for query in cmd.queries)
        succeeded = sum(1 for o in outcomes if o.status == SearchStatus.SUCCEEDED)

        if succeeded == len(outcomes):
            overall = SearchStatus.SUCCEEDED
        elif succeeded == 0:
            overall = SearchStatus.FAILED
        else:
            overall = SearchStatus.PARTIALLY_SUCCEEDED

        return BatchSearchResult(status=overall, outcomes=outcomes)

    def _execute(self, query: SearchQuery) -> SearchOutcome:
        try:
            query_validation.validate_pagination(query.page_size, query.offset)
            query_validation.validate_filters(query.filters)
            query_validation.validate_sort(query.sort)
            schema_version = SchemaVersion.parse(query.schema_version_raw)
        except _VALIDATION_ERRORS as exc:
            return SearchOutcome(
                status=SearchStatus.REJECTED, failures=(_to_failure("validation", exc),)
            )

        try:
            provider = self._registry.resolve(query.entity_type, schema_version)
        except ProviderSelectionError as exc:
            return SearchOutcome(
                status=SearchStatus.UNSUPPORTED_PROVIDER,
                failures=(_to_failure("provider_selection", exc),),
            )

        try:
            page = provider.search(
                tenant_id=query.tenant_id,
                time_range=query.time_range,
                shape=query.shape,
                filters=query.filters,
                sort=query.sort,
                page_size=query.page_size,
                offset=query.offset,
            )
        except Exception as exc:
            # An untrusted provider's execution failure must never
            # crash the pipeline (same discipline as M44A-M44D) — caught
            # broadly and deliberately.
            return SearchOutcome(
                status=SearchStatus.FAILED, failures=(_to_failure("execution", exc),)
            )

        return SearchOutcome(status=SearchStatus.SUCCEEDED, page=page)
