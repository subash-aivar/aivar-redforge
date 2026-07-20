"""Value objects for DetectionPack aggregate."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from detection.domain.exceptions.domain_exceptions import InvalidArgument
from detection.domain.value_objects.keys import RuleSemVer

if TYPE_CHECKING:
    from datetime import datetime


_PACK_KEY_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}\.[a-z][a-z0-9_]{0,63}$")


@dataclass(frozen=True, slots=True)
class PackKey:
    """Stable pack identifier: `{namespace}.{pack_name}`."""

    value: str

    def __post_init__(self) -> None:
        cleaned = self.value.strip().lower()
        if not _PACK_KEY_RE.match(cleaned):
            raise InvalidArgument(
                "PackKey",
                "must match {namespace}.{pack_name} (lowercase alnum/underscore)",
            )
        object.__setattr__(self, "value", cleaned)

    def __str__(self) -> str:
        return self.value


# Semantic version for packs — RuleSemVer naming avoided; reuse same validation.
PackSemVer = RuleSemVer


@dataclass(frozen=True, slots=True)
class PackMaintainer:
    identity: str
    display_name: str | None = None

    def __post_init__(self) -> None:
        if not self.identity.strip():
            raise InvalidArgument("PackMaintainer.identity", "required")
        object.__setattr__(self, "identity", self.identity.strip()[:256])
        if self.display_name is not None:
            object.__setattr__(self, "display_name", self.display_name.strip()[:256] or None)


@dataclass(frozen=True, slots=True)
class ComplianceFrameworkRef:
    framework_id: str
    framework_name: str | None = None

    def __post_init__(self) -> None:
        if not self.framework_id.strip():
            raise InvalidArgument("ComplianceFrameworkRef.framework_id", "required")
        object.__setattr__(self, "framework_id", self.framework_id.strip()[:128])


@dataclass(frozen=True, slots=True)
class PackSubscriptionScope:
    """Tenants currently subscribed to this pack."""

    tenant_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        cleaned = tuple(sorted({t.strip() for t in self.tenant_ids if t.strip()}))
        object.__setattr__(self, "tenant_ids", cleaned)

    def contains(self, tenant_id: str) -> bool:
        return tenant_id.strip() in self.tenant_ids

    def with_subscribed(self, tenant_id: str) -> PackSubscriptionScope:
        tid = tenant_id.strip()
        if not tid:
            raise InvalidArgument("tenant_id", "required")
        if tid in self.tenant_ids:
            return self
        return PackSubscriptionScope(tenant_ids=(*self.tenant_ids, tid))

    def with_unsubscribed(self, tenant_id: str) -> PackSubscriptionScope:
        tid = tenant_id.strip()
        return PackSubscriptionScope(
            tenant_ids=tuple(t for t in self.tenant_ids if t != tid)
        )


@dataclass(frozen=True, slots=True)
class CoverageMatrixEntry:
    technique_id: str
    rule_count: int
    rule_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.technique_id.strip():
            raise InvalidArgument("CoverageMatrixEntry.technique_id", "required")
        if self.rule_count < 0:
            raise InvalidArgument("CoverageMatrixEntry.rule_count", "must be >= 0")


@dataclass(frozen=True, slots=True)
class CoverageMatrix:
    """ATT&CK technique coverage summary for a pack (computed, not raw storage)."""

    entries: tuple[CoverageMatrixEntry, ...] = ()
    computed_at: datetime | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "entries", tuple(self.entries))

    @classmethod
    def empty(cls) -> CoverageMatrix:
        return cls()

    @classmethod
    def from_technique_map(
        cls,
        technique_to_rules: dict[str, list[str]],
        *,
        computed_at: datetime | None = None,
    ) -> CoverageMatrix:
        entries = tuple(
            CoverageMatrixEntry(
                technique_id=tech,
                rule_count=len(rules),
                rule_ids=tuple(rules),
            )
            for tech, rules in sorted(technique_to_rules.items())
            if tech.strip()
        )
        return cls(entries=entries, computed_at=computed_at)

    def to_dict(self) -> dict[str, Any]:
        return {
            "entries": [
                {
                    "technique_id": e.technique_id,
                    "rule_count": e.rule_count,
                    "rule_ids": list(e.rule_ids),
                }
                for e in self.entries
            ],
            "computed_at": self.computed_at.isoformat() if self.computed_at else None,
        }


@dataclass(frozen=True, slots=True)
class PackMetadata:
    description: str = ""
    tags: tuple[str, ...] = ()
    extra: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "description", (self.description or "")[:4096])
        object.__setattr__(
            self,
            "tags",
            tuple(t.strip()[:64] for t in self.tags if t.strip())[:32],
        )
        object.__setattr__(self, "extra", dict(self.extra))
