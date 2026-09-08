"""Application queries for intelligence_relationships (M51.4 Phase C1)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from intelligence_relationships.application.exceptions import ApplicationValidationError

if TYPE_CHECKING:
    from intelligence_relationships.domain.value_objects.identifiers import TenantId

DEFAULT_LIST_LIMIT = 50
MAX_LIST_LIMIT = 200


@dataclass(frozen=True, slots=True)
class GetRelationshipQuery:
    tenant_id: TenantId | None
    relationship_id: str


@dataclass(frozen=True, slots=True)
class ListRelationshipsQuery:
    tenant_id: TenantId | None
    relationship_type: str | None = None
    lifecycle_status: str | None = None
    epistemic_state: str | None = None
    source_entity_id: str | None = None
    target_entity_id: str | None = None
    limit: int = DEFAULT_LIST_LIMIT
    offset: int = 0

    def __post_init__(self) -> None:
        if not (1 <= self.limit <= MAX_LIST_LIMIT):
            raise ApplicationValidationError(
                f"limit must be in [1, {MAX_LIST_LIMIT}], got {self.limit!r}"
            )
        if self.offset < 0:
            raise ApplicationValidationError(f"offset must be >= 0, got {self.offset!r}")
