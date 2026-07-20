"""Value objects for the RedTeamOperator aggregate."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING
from uuid import UUID

from red_team_operator.domain.exceptions.domain_exceptions import InvalidArgument
from red_team_operator.domain.value_objects.enums import ApprovalScope

if TYPE_CHECKING:
    from collections.abc import Iterator


@dataclass(frozen=True, slots=True)
class OperatorCertifications:
    """Certified technique categories for the operator."""

    categories: tuple[str, ...]

    def __post_init__(self) -> None:
        seen: set[str] = set()
        normalized: list[str] = []
        for raw in self.categories:
            cat = raw.strip()
            if not cat:
                raise InvalidArgument("OperatorCertifications", "category must not be empty")
            key = cat.lower()
            if key in seen:
                raise InvalidArgument("OperatorCertifications", f"duplicate category: {cat}")
            seen.add(key)
            normalized.append(cat)
        object.__setattr__(self, "categories", tuple(normalized))

    @classmethod
    def empty(cls) -> OperatorCertifications:
        return cls(())

    @classmethod
    def of(cls, *categories: str) -> OperatorCertifications:
        return cls(tuple(categories))

    def __iter__(self) -> Iterator[str]:
        return iter(self.categories)

    def __len__(self) -> int:
        return len(self.categories)

    def __contains__(self, item: object) -> bool:
        if not isinstance(item, str):
            return False
        return any(c.lower() == item.strip().lower() for c in self.categories)


@dataclass(frozen=True, slots=True)
class ApprovalAuthority:
    """Approval scopes this operator is authorized to grant."""

    scopes: tuple[ApprovalScope, ...]

    def __post_init__(self) -> None:
        seen: set[ApprovalScope] = set()
        for scope in self.scopes:
            if scope in seen:
                raise InvalidArgument("ApprovalAuthority", f"duplicate scope: {scope.value}")
            seen.add(scope)

    @classmethod
    def empty(cls) -> ApprovalAuthority:
        return cls(())

    @classmethod
    def of(cls, *scopes: ApprovalScope) -> ApprovalAuthority:
        return cls(tuple(scopes))

    def includes(self, scope: ApprovalScope) -> bool:
        return scope in self.scopes

    def with_granted(self, scope: ApprovalScope) -> ApprovalAuthority:
        if scope in self.scopes:
            return self
        return ApprovalAuthority((*self.scopes, scope))

    def with_revoked(self, scope: ApprovalScope) -> ApprovalAuthority:
        if scope not in self.scopes:
            return self
        return ApprovalAuthority(tuple(s for s in self.scopes if s != scope))

    def __iter__(self) -> Iterator[ApprovalScope]:
        return iter(self.scopes)

    def __len__(self) -> int:
        return len(self.scopes)

    def __contains__(self, item: object) -> bool:
        return isinstance(item, ApprovalScope) and item in self.scopes


@dataclass(frozen=True, slots=True)
class ActiveEngagementRefs:
    """Engagements this operator is currently authorized for."""

    engagement_ids: tuple[UUID, ...]

    def __post_init__(self) -> None:
        seen: set[UUID] = set()
        for eid in self.engagement_ids:
            if eid.int == 0:
                raise InvalidArgument("ActiveEngagementRefs", "engagement id must not be nil")
            if eid in seen:
                raise InvalidArgument("ActiveEngagementRefs", f"duplicate engagement: {eid}")
            seen.add(eid)

    @classmethod
    def empty(cls) -> ActiveEngagementRefs:
        return cls(())

    @classmethod
    def of(cls, *engagement_ids: UUID) -> ActiveEngagementRefs:
        return cls(tuple(engagement_ids))

    def includes(self, engagement_id: UUID) -> bool:
        return engagement_id in self.engagement_ids

    def with_added(self, engagement_id: UUID) -> ActiveEngagementRefs:
        if engagement_id in self.engagement_ids:
            return self
        return ActiveEngagementRefs((*self.engagement_ids, engagement_id))

    def with_removed(self, engagement_id: UUID) -> ActiveEngagementRefs:
        if engagement_id not in self.engagement_ids:
            return self
        return ActiveEngagementRefs(
            tuple(eid for eid in self.engagement_ids if eid != engagement_id)
        )

    def __iter__(self) -> Iterator[UUID]:
        return iter(self.engagement_ids)

    def __len__(self) -> int:
        return len(self.engagement_ids)

    def __contains__(self, item: object) -> bool:
        return isinstance(item, UUID) and item in self.engagement_ids
