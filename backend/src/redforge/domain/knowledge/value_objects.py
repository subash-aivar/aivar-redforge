"""Value objects for the Knowledge bounded context.

Knowledge items are reusable AI security building blocks — attack
definitions, validation packs, compliance rules, provider profiles.
"""

from dataclasses import dataclass
from enum import StrEnum, unique


@unique
class KnowledgeCategory(StrEnum):
    """Classification of knowledge items by purpose."""

    ATTACK = "attack"
    VALIDATION_PACK = "validation_pack"
    COMPLIANCE_PACK = "compliance_pack"
    DETECTION_RULE = "detection_rule"
    RECOMMENDATION = "recommendation"
    PROVIDER_PROFILE = "provider_profile"
    SECURITY_SKILL = "security_skill"


@unique
class KnowledgeStatus(StrEnum):
    """Lifecycle status of a knowledge item.

    - DRAFT: Under development, not usable in validations.
    - PUBLISHED: Available for use in validation runs.
    - ARCHIVED: Retired, no longer usable but preserved for history.
    - SUPERSEDED: Replaced by a newer version.
    """

    DRAFT = "draft"
    PUBLISHED = "published"
    ARCHIVED = "archived"
    SUPERSEDED = "superseded"


@unique
class KnowledgeSource(StrEnum):
    """Origin of a knowledge item."""

    BUILTIN = "builtin"
    COMMUNITY = "community"
    ENTERPRISE = "enterprise"
    CUSTOM = "custom"


@dataclass(frozen=True, slots=True)
class KnowledgeVersion:
    """Semantic version for a knowledge item.

    Knowledge evolves. Versions track that evolution and enable
    superseding without data loss.
    """

    major: int
    minor: int
    patch: int

    def __post_init__(self) -> None:
        if self.major < 0 or self.minor < 0 or self.patch < 0:
            raise ValueError("Version components must be non-negative")

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"

    @classmethod
    def from_string(cls, value: str) -> "KnowledgeVersion":
        """Parse a version string like '1.2.3'."""
        parts = value.split(".")
        if len(parts) != 3:
            raise ValueError(f"Invalid version format: '{value}' (expected X.Y.Z)")
        try:
            return cls(major=int(parts[0]), minor=int(parts[1]), patch=int(parts[2]))
        except ValueError as exc:
            raise ValueError(f"Invalid version format: '{value}'") from exc

    def next_patch(self) -> "KnowledgeVersion":
        return KnowledgeVersion(self.major, self.minor, self.patch + 1)

    def next_minor(self) -> "KnowledgeVersion":
        return KnowledgeVersion(self.major, self.minor + 1, 0)

    def next_major(self) -> "KnowledgeVersion":
        return KnowledgeVersion(self.major + 1, 0, 0)


@dataclass(frozen=True, slots=True)
class KnowledgeReference:
    """A reference link attached to a knowledge item.

    Links to external resources: documentation, research papers,
    OWASP pages, MITRE ATLAS techniques, etc.
    """

    url: str
    title: str
    reference_type: str = "documentation"

    def __post_init__(self) -> None:
        if not self.url:
            raise ValueError("url must not be empty")
        if not self.title:
            raise ValueError("title must not be empty")
