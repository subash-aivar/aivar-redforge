from __future__ import annotations

import dataclasses

import pytest

from siem_search.application.dtos.search_hit import SearchHit, SearchResultPage


def test_hit_construction() -> None:
    hit = SearchHit(entity_type="events", entity_id="e-1", score=0.9)
    assert hit.entity_id == "e-1"


def test_hit_rejects_blank_entity_id() -> None:
    with pytest.raises(ValueError, match="entity_id"):
        SearchHit(entity_type="events", entity_id="  ", score=0.9)


def test_hit_rejects_negative_score() -> None:
    with pytest.raises(ValueError, match="score"):
        SearchHit(entity_type="events", entity_id="e-1", score=-0.1)


def test_hit_is_frozen() -> None:
    hit = SearchHit(entity_type="events", entity_id="e-1", score=0.9)
    with pytest.raises(dataclasses.FrozenInstanceError):
        hit.score = 0.1  # type: ignore[misc]


def test_page_construction() -> None:
    hit = SearchHit(entity_type="events", entity_id="e-1", score=0.9)
    page = SearchResultPage(hits=(hit,), total_hits=1, page_size=10, offset=0, has_more=False)
    assert page.hits == (hit,)


def test_page_rejects_total_hits_smaller_than_hits_length() -> None:
    hit = SearchHit(entity_type="events", entity_id="e-1", score=0.9)
    with pytest.raises(ValueError, match="total_hits"):
        SearchResultPage(hits=(hit,), total_hits=0, page_size=10, offset=0, has_more=False)


def test_page_rejects_non_positive_page_size() -> None:
    with pytest.raises(ValueError, match="page_size"):
        SearchResultPage(hits=(), total_hits=0, page_size=0, offset=0, has_more=False)


def test_page_rejects_negative_offset() -> None:
    with pytest.raises(ValueError, match="offset"):
        SearchResultPage(hits=(), total_hits=0, page_size=10, offset=-1, has_more=False)


def test_page_is_frozen() -> None:
    page = SearchResultPage(hits=(), total_hits=0, page_size=10, offset=0, has_more=False)
    with pytest.raises(dataclasses.FrozenInstanceError):
        page.offset = 5  # type: ignore[misc]
