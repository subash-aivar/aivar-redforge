"""Application queries for ioc_intelligence (M51.2 Phase A2; extended
Slice 2.1 with real server-side search/filter/sort — see
`ListIocsQuery`)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from ioc_intelligence.application.exceptions import ApplicationValidationError

if TYPE_CHECKING:
    from ioc_intelligence.domain.value_objects.identifiers import TenantId


@dataclass(frozen=True, slots=True)
class GetIocQuery:
    tenant_id: TenantId | None
    ioc_id: str
    actor_roles: tuple[str, ...] = ()


DEFAULT_LIST_LIMIT = 50
MAX_LIST_LIMIT = 200

# Free-text search is matched against the normalized canonical value only
# (never against unrelated columns) and is bounded in length to keep an
# ILIKE '%...%' scan cheap and to reject pathological input outright.
MAX_SEARCH_LENGTH = 256


class IocSortField(StrEnum):
    """Closed, whitelisted set of sortable columns — the only fields a
    caller may sort by. `PgIocRepository` maps each value to a real,
    trusted SQLAlchemy column; a raw client-supplied column name is
    never interpolated into a query (prevents SQL injection by
    construction, and keeps `ORDER BY` bounded to columns that are
    actually indexed or cheap to sort)."""

    CREATED_AT = "created_at"
    UPDATED_AT = "updated_at"
    VALID_UNTIL = "valid_until"
    IOC_TYPE = "ioc_type"
    LIFECYCLE = "lifecycle"
    EPISTEMIC_STATE = "epistemic_state"


class SortDirection(StrEnum):
    ASC = "asc"
    DESC = "desc"


class ValidityFilter(StrEnum):
    """Time-based validity (`valid_until` vs. now) — deliberately
    independent of `lifecycle`: an IOC can still carry `lifecycle=ACTIVE`
    after its `valid_until` has passed but before the expiry sweep has
    caught up to it. `VALID` means `valid_until IS NULL OR valid_until
    > now()`; `LAPSED` means `valid_until IS NOT NULL AND valid_until <=
    now()`, regardless of the record's current `lifecycle` value."""

    VALID = "valid"
    LAPSED = "lapsed"


@dataclass(frozen=True, slots=True)
class ListIocsQuery:
    tenant_id: TenantId | None
    lifecycle: str | None = None
    epistemic_state: str | None = None
    ioc_type: str | None = None
    search: str | None = None
    confidence: str | None = None
    source_system: str | None = None
    validity: str | None = None
    sort_by: str = IocSortField.CREATED_AT.value
    sort_dir: str = SortDirection.DESC.value
    limit: int = DEFAULT_LIST_LIMIT
    offset: int = 0
    actor_roles: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not (1 <= self.limit <= MAX_LIST_LIMIT):
            raise ApplicationValidationError(
                f"limit must be in [1, {MAX_LIST_LIMIT}], got {self.limit!r}"
            )
        if self.offset < 0:
            raise ApplicationValidationError(f"offset must be >= 0, got {self.offset!r}")
        if self.search is not None and len(self.search) > MAX_SEARCH_LENGTH:
            raise ApplicationValidationError(
                f"search must be at most {MAX_SEARCH_LENGTH} characters, "
                f"got {len(self.search)}"
            )
