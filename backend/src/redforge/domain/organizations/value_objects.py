"""Value objects for the Organization bounded context.

Value objects are immutable, equality-based-on-value, and self-validating.
They encapsulate business rules about what constitutes valid organization
attributes and cannot exist in an invalid state.
"""

from __future__ import annotations

import re
from enum import StrEnum, unique


@unique
class OrganizationStatus(StrEnum):
    """Lifecycle status of an Organization.

    - ACTIVE: Organization is operational and can perform validations.
    - INACTIVE: Organization has been deactivated; access is suspended.
    - SUSPENDED: Organization is suspended due to policy violation or billing.
    """

    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"


@unique
class OrganizationPlan(StrEnum):
    """Subscription plan determining feature access and resource limits.

    - FREE: Limited access for evaluation.
    - STARTER: Small team usage with basic features.
    - PROFESSIONAL: Full feature access for growing teams.
    - ENTERPRISE: Custom limits, SLA, dedicated support.
    """

    FREE = "free"
    STARTER = "starter"
    PROFESSIONAL = "professional"
    ENTERPRISE = "enterprise"


class OrganizationName:
    """Validated organization display name.

    Business rules:
    - Must be between 2 and 100 characters.
    - Must not be empty or whitespace-only.
    - Leading/trailing whitespace is stripped.
    """

    __slots__ = ("_value",)

    MIN_LENGTH = 2
    MAX_LENGTH = 100

    def __init__(self, value: str) -> None:
        cleaned = value.strip()
        if len(cleaned) < self.MIN_LENGTH:
            raise ValueError(
                f"Organization name must be at least {self.MIN_LENGTH} characters, "
                f"got {len(cleaned)}"
            )
        if len(cleaned) > self.MAX_LENGTH:
            raise ValueError(
                f"Organization name must be at most {self.MAX_LENGTH} characters, "
                f"got {len(cleaned)}"
            )
        self._value = cleaned

    @property
    def value(self) -> str:
        return self._value

    def __str__(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return f"OrganizationName({self._value!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, OrganizationName):
            return NotImplemented
        return self._value == other._value

    def __hash__(self) -> int:
        return hash(self._value)


class OrganizationSlug:
    """URL-safe unique identifier for an Organization.

    Business rules:
    - Must be between 2 and 63 characters (DNS-compatible).
    - Lowercase alphanumeric and hyphens only.
    - Must start and end with an alphanumeric character.
    - No consecutive hyphens.
    """

    __slots__ = ("_value",)

    MIN_LENGTH = 2
    MAX_LENGTH = 63
    _PATTERN = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")
    _CONSECUTIVE_HYPHENS = re.compile(r"--")

    def __init__(self, value: str) -> None:
        if len(value) < self.MIN_LENGTH:
            raise ValueError(
                f"Organization slug must be at least {self.MIN_LENGTH} characters, "
                f"got {len(value)}"
            )
        if len(value) > self.MAX_LENGTH:
            raise ValueError(
                f"Organization slug must be at most {self.MAX_LENGTH} characters, "
                f"got {len(value)}"
            )
        if not self._PATTERN.match(value):
            raise ValueError(
                f"Organization slug must contain only lowercase alphanumeric "
                f"characters and hyphens, and must start/end with alphanumeric: '{value}'"
            )
        if self._CONSECUTIVE_HYPHENS.search(value):
            raise ValueError(
                f"Organization slug must not contain consecutive hyphens: '{value}'"
            )
        self._value = value

    @classmethod
    def from_name(cls, name: str) -> OrganizationSlug:
        """Generate a slug from an organization name.

        Transforms the name to a valid slug by:
        - Lowercasing
        - Replacing spaces and underscores with hyphens
        - Removing invalid characters
        - Collapsing consecutive hyphens
        - Trimming leading/trailing hyphens
        """
        slug = name.lower().strip()
        slug = re.sub(r"[\s_]+", "-", slug)
        slug = re.sub(r"[^a-z0-9-]", "", slug)
        slug = re.sub(r"-{2,}", "-", slug)
        slug = slug.strip("-")
        return cls(slug)

    @property
    def value(self) -> str:
        return self._value

    def __str__(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return f"OrganizationSlug({self._value!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, OrganizationSlug):
            return NotImplemented
        return self._value == other._value

    def __hash__(self) -> int:
        return hash(self._value)
