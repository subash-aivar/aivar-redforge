from __future__ import annotations

import pytest

from siem_search.application.dtos.search_hit import SearchResultPage
from siem_search.application.dtos.search_outcome import (
    BatchSearchResult,
    SearchFailure,
    SearchOutcome,
    SearchStatus,
)


def _page() -> SearchResultPage:
    return SearchResultPage(hits=(), total_hits=0, page_size=10, offset=0, has_more=False)


def test_succeeded_requires_page() -> None:
    with pytest.raises(ValueError, match="page"):
        SearchOutcome(status=SearchStatus.SUCCEEDED, page=None)


def test_rejected_forbids_page() -> None:
    with pytest.raises(ValueError, match="page"):
        SearchOutcome(status=SearchStatus.REJECTED, page=_page())


def test_valid_succeeded_outcome() -> None:
    page = _page()
    outcome = SearchOutcome(status=SearchStatus.SUCCEEDED, page=page)
    assert outcome.page is page


def test_batch_result_counts() -> None:
    succeeded = SearchOutcome(status=SearchStatus.SUCCEEDED, page=_page())
    failed = SearchOutcome(
        status=SearchStatus.FAILED,
        failures=(SearchFailure(stage="execution", error_type="X", message="y"),),
    )
    batch = BatchSearchResult(status=SearchStatus.PARTIALLY_SUCCEEDED, outcomes=(succeeded, failed))

    assert batch.succeeded_count == 1
    assert batch.failed_count == 1


def test_batch_result_defaults_to_empty() -> None:
    batch = BatchSearchResult(status=SearchStatus.FAILED)
    assert batch.outcomes == ()
    assert batch.succeeded_count == 0
