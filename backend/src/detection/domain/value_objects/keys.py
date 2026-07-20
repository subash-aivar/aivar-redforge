"""Rule keys, tags, and external references."""

from __future__ import annotations

import re
from dataclasses import dataclass

from detection.domain.exceptions.domain_exceptions import InvalidArgument

_RULE_KEY_RE = re.compile(r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_\-]*$")
_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


@dataclass(frozen=True, slots=True)
class RuleKey:
    """Human-readable stable identifier: ``{author_namespace}.{rule_name}``."""

    value: str

    def __post_init__(self) -> None:
        if not self.value or not _RULE_KEY_RE.match(self.value):
            raise InvalidArgument(
                "RuleKey",
                "must match {namespace}.{rule_name} (lowercase, underscore/hyphen)",
            )

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class RuleSemVer:
    """Semantic version value object (freeze: RuleVersion as value)."""

    major: int
    minor: int
    patch: int

    def __post_init__(self) -> None:
        if self.major < 0 or self.minor < 0 or self.patch < 0:
            raise InvalidArgument("RuleVersion", "version components must be >= 0")

    @classmethod
    def parse(cls, text: str) -> RuleSemVer:
        parts = text.strip().split(".")
        if len(parts) != 3 or not all(p.isdigit() for p in parts):
            raise InvalidArgument("RuleVersion", "must be major.minor.patch")
        return cls(int(parts[0]), int(parts[1]), int(parts[2]))

    def bump_patch(self) -> RuleSemVer:
        return RuleSemVer(self.major, self.minor, self.patch + 1)

    def bump_minor(self) -> RuleSemVer:
        return RuleSemVer(self.major, self.minor + 1, 0)

    def bump_major(self) -> RuleSemVer:
        return RuleSemVer(self.major + 1, 0, 0)

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"


# Alias used in freeze ubiquitous language.
RuleVersion = RuleSemVer


@dataclass(frozen=True, slots=True)
class RuleTag:
    value: str

    def __post_init__(self) -> None:
        cleaned = self.value.strip()
        if not cleaned or len(cleaned) > 64:
            raise InvalidArgument("RuleTag", "must be 1-64 characters")
        object.__setattr__(self, "value", cleaned.lower())

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class ExternalRuleRef:
    system: str
    external_id: str

    def __post_init__(self) -> None:
        if not self.system.strip() or not self.external_id.strip():
            raise InvalidArgument("ExternalRuleRef", "system and external_id required")


@dataclass(frozen=True, slots=True)
class AuthorRef:
    identity: str

    def __post_init__(self) -> None:
        if not self.identity.strip():
            raise InvalidArgument("AuthorRef", "identity required")


@dataclass(frozen=True, slots=True)
class ReviewerRef:
    identity: str

    def __post_init__(self) -> None:
        if not self.identity.strip():
            raise InvalidArgument("ReviewerRef", "identity required")


@dataclass(frozen=True, slots=True)
class TelemetrySourceRef:
    source_id: str
    source_type: str | None = None

    def __post_init__(self) -> None:
        if not self.source_id.strip():
            raise InvalidArgument("TelemetrySourceRef", "source_id required")


@dataclass(frozen=True, slots=True)
class AssetScopeFilter:
    asset_types: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if any(not t.strip() for t in self.asset_types):
            raise InvalidArgument("AssetScopeFilter", "asset_types must be non-empty strings")
        if any(not t.strip() for t in self.tags):
            raise InvalidArgument("AssetScopeFilter", "tags must be non-empty strings")


@dataclass(frozen=True, slots=True)
class ThrottlePolicy:
    window_seconds: int
    max_count: int

    def __post_init__(self) -> None:
        if self.window_seconds <= 0:
            raise InvalidArgument("ThrottlePolicy", "window_seconds must be > 0")
        if self.max_count <= 0:
            raise InvalidArgument("ThrottlePolicy", "max_count must be > 0")


@dataclass(frozen=True, slots=True)
class FalsePositiveProfile:
    fp_rate: float
    total_findings: int
    fp_count: int
    last_calculated_at: str | None = None

    def __post_init__(self) -> None:
        if not 0.0 <= self.fp_rate <= 1.0:
            raise InvalidArgument("FalsePositiveProfile", "fp_rate must be in [0,1]")
        if self.total_findings < 0 or self.fp_count < 0:
            raise InvalidArgument("FalsePositiveProfile", "counts must be >= 0")
        if self.fp_count > self.total_findings:
            raise InvalidArgument("FalsePositiveProfile", "fp_count cannot exceed total")


@dataclass(frozen=True, slots=True)
class MitreTechniqueId:
    value: str

    def __post_init__(self) -> None:
        if not _TECHNIQUE_RE.match(self.value):
            raise InvalidArgument("MitreTechniqueId", "must match T#### or T####.###")


__all__ = [
    "AssetScopeFilter",
    "AuthorRef",
    "ExternalRuleRef",
    "FalsePositiveProfile",
    "MitreTechniqueId",
    "ReviewerRef",
    "RuleKey",
    "RuleSemVer",
    "RuleTag",
    "RuleVersion",
    "TelemetrySourceRef",
    "ThrottlePolicy",
]
