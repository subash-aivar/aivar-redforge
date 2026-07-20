"""Value objects for DetectionException aggregate."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from detection.domain.exceptions.domain_exceptions import InvalidArgument
from detection.domain.value_objects.enums import ExceptionScopeKind

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True, slots=True)
class ExceptionJustification:
    text: str
    classification: str = "operational"

    def __post_init__(self) -> None:
        cleaned = self.text.strip()
        if not cleaned:
            raise InvalidArgument("ExceptionJustification.text", "required")
        object.__setattr__(self, "text", cleaned[:8192])
        object.__setattr__(
            self, "classification", (self.classification or "operational").strip()[:64]
        )


@dataclass(frozen=True, slots=True)
class ExceptionApprover:
    identity: str

    def __post_init__(self) -> None:
        if not self.identity.strip():
            raise InvalidArgument("ExceptionApprover.identity", "required")
        object.__setattr__(self, "identity", self.identity.strip()[:256])


@dataclass(frozen=True, slots=True)
class ExceptionValidUntil:
    expires_at: datetime

    def is_expired(self, now: datetime) -> bool:
        return now >= self.expires_at


@dataclass(frozen=True, slots=True)
class ExceptionScope:
    """Finding-level or rule-level exception scope."""

    kind: ExceptionScopeKind
    finding_id: str | None = None
    rule_id: str | None = None
    asset_filter: str | None = None
    condition: str | None = None

    def __post_init__(self) -> None:
        if self.kind == ExceptionScopeKind.FINDING:
            if not (self.finding_id and self.finding_id.strip()):
                raise InvalidArgument(
                    "ExceptionScope.finding_id", "required for Finding scope"
                )
        elif self.kind == ExceptionScopeKind.RULE:
            if not (self.rule_id and self.rule_id.strip()):
                raise InvalidArgument(
                    "ExceptionScope.rule_id", "required for Rule scope"
                )
        else:
            raise InvalidArgument("ExceptionScope.kind", "unsupported")


@dataclass(frozen=True, slots=True)
class AffectedRuleRefs:
    rule_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        cleaned = tuple(r.strip() for r in self.rule_ids if r.strip())
        if not cleaned:
            raise InvalidArgument("AffectedRuleRefs", "at least one rule required")
        object.__setattr__(self, "rule_ids", cleaned)

    def contains(self, rule_id: str) -> bool:
        return rule_id.strip() in self.rule_ids


@dataclass(frozen=True, slots=True)
class AssetScopeFilter:
    asset_ids: tuple[str, ...] = ()
    asset_types: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "asset_ids",
            tuple(a.strip() for a in self.asset_ids if a.strip()),
        )
        object.__setattr__(
            self,
            "asset_types",
            tuple(t.strip() for t in self.asset_types if t.strip()),
        )

    def is_unrestricted(self) -> bool:
        return not self.asset_ids and not self.asset_types
