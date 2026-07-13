"""Value objects for the AI Target bounded context.

These represent the validated, immutable attributes of an AI system
under continuous security validation. Each enforces its own business rules.
"""

from __future__ import annotations

import re
from enum import StrEnum, unique
from typing import Self


@unique
class TargetType(StrEnum):
    """Classification of the AI system being validated.

    Determines which attack modules and validation strategies apply.
    """

    LLM_APPLICATION = "llm_application"
    AI_AGENT = "ai_agent"
    RAG_SYSTEM = "rag_system"
    MCP_SERVER = "mcp_server"
    AI_API = "ai_api"
    AI_WORKFLOW = "ai_workflow"
    AUTONOMOUS_AGENT = "autonomous_agent"


@unique
class TargetStatus(StrEnum):
    """Lifecycle status of an AI Target.

    - ACTIVE: Target is available for validation runs.
    - INACTIVE: Target is temporarily disabled (no validations will execute).
    - ARCHIVED: Target is permanently retired (read-only, historical).
    """

    ACTIVE = "active"
    INACTIVE = "inactive"
    ARCHIVED = "archived"


@unique
class Provider(StrEnum):
    """AI provider powering the target system.

    Used for provider-specific attack strategies and API compatibility.
    """

    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GOOGLE = "google"
    AZURE_OPENAI = "azure_openai"
    AWS_BEDROCK = "aws_bedrock"
    META = "meta"
    MISTRAL = "mistral"
    COHERE = "cohere"
    CUSTOM = "custom"


class TargetName:
    """Validated display name for an AI Target.

    Business rules:
    - Between 2 and 150 characters.
    - Leading/trailing whitespace stripped.
    """

    __slots__ = ("_value",)

    MIN_LENGTH = 2
    MAX_LENGTH = 150

    def __init__(self, value: str) -> None:
        cleaned = value.strip()
        if len(cleaned) < self.MIN_LENGTH:
            raise ValueError(
                f"Target name must be at least {self.MIN_LENGTH} characters, "
                f"got {len(cleaned)}"
            )
        if len(cleaned) > self.MAX_LENGTH:
            raise ValueError(
                f"Target name must be at most {self.MAX_LENGTH} characters, "
                f"got {len(cleaned)}"
            )
        self._value = cleaned

    @property
    def value(self) -> str:
        return self._value

    def __str__(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return f"TargetName({self._value!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, TargetName):
            return NotImplemented
        return self._value == other._value

    def __hash__(self) -> int:
        return hash(self._value)


class EndpointUrl:
    """Validated URL where the AI target is reachable.

    Business rules:
    - Must start with http:// or https://.
    - Maximum 2048 characters.
    - No whitespace.
    """

    __slots__ = ("_value",)

    MAX_LENGTH = 2048
    _PATTERN = re.compile(r"^https?://\S+$")

    def __init__(self, value: str) -> None:
        stripped = value.strip()
        if len(stripped) > self.MAX_LENGTH:
            raise ValueError(
                f"Endpoint URL must be at most {self.MAX_LENGTH} characters"
            )
        if not self._PATTERN.match(stripped):
            raise ValueError(
                f"Endpoint URL must be a valid HTTP/HTTPS URL: '{stripped}'"
            )
        self._value = stripped

    @property
    def value(self) -> str:
        return self._value

    def __str__(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return f"EndpointUrl({self._value!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, EndpointUrl):
            return NotImplemented
        return self._value == other._value

    def __hash__(self) -> int:
        return hash(self._value)


class Tag:
    """Validated tag for categorizing and filtering AI Targets.

    Business rules:
    - Lowercase alphanumeric, hyphens, and colons only.
    - Between 1 and 50 characters.
    - Supports namespaced tags (e.g., "env:production", "team:security").
    """

    __slots__ = ("_value",)

    MIN_LENGTH = 1
    MAX_LENGTH = 50
    _PATTERN = re.compile(r"^[a-z0-9][a-z0-9:_-]*$")

    def __init__(self, value: str) -> None:
        normalized = value.strip().lower()
        if len(normalized) < self.MIN_LENGTH:
            raise ValueError("Tag must not be empty")
        if len(normalized) > self.MAX_LENGTH:
            raise ValueError(
                f"Tag must be at most {self.MAX_LENGTH} characters, got {len(normalized)}"
            )
        if not self._PATTERN.match(normalized):
            raise ValueError(
                f"Tag must contain only lowercase alphanumeric, hyphens, "
                f"underscores, and colons: '{value}'"
            )
        self._value = normalized

    @property
    def value(self) -> str:
        return self._value

    def __str__(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return f"Tag({self._value!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Tag):
            return NotImplemented
        return self._value == other._value

    def __hash__(self) -> int:
        return hash(self._value)


class ValidationPolicyReference:
    """Reference to a validation policy attached to an AI Target.

    This is a pointer (by ID) to a policy defined elsewhere.
    The AI Target does not own the policy — it references it.
    """

    __slots__ = ("_policy_id",)

    def __init__(self, policy_id: str) -> None:
        if not policy_id or len(policy_id) < 2:
            raise ValueError("Validation policy reference must be a valid identifier")
        self._policy_id = policy_id

    @property
    def policy_id(self) -> str:
        return self._policy_id

    def __str__(self) -> str:
        return self._policy_id

    def __repr__(self) -> str:
        return f"ValidationPolicyReference({self._policy_id!r})"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, ValidationPolicyReference):
            return NotImplemented
        return self._policy_id == other._policy_id

    def __hash__(self) -> int:
        return hash(self._policy_id)


class TargetMetadata:
    """Immutable key-value metadata associated with an AI Target.

    Used for configuration, labels, and extensible attributes that
    don't warrant their own value object. Keys and values are strings.

    Business rules:
    - Keys must be non-empty, max 100 characters.
    - Values must be max 1000 characters.
    - Maximum 50 entries.
    """

    __slots__ = ("_data",)

    MAX_ENTRIES = 50
    MAX_KEY_LENGTH = 100
    MAX_VALUE_LENGTH = 1000

    def __init__(self, data: dict[str, str] | None = None) -> None:
        entries = data or {}
        if len(entries) > self.MAX_ENTRIES:
            raise ValueError(
                f"Metadata cannot exceed {self.MAX_ENTRIES} entries, got {len(entries)}"
            )
        for key, value in entries.items():
            if not key or len(key) > self.MAX_KEY_LENGTH:
                raise ValueError(
                    f"Metadata key must be 1-{self.MAX_KEY_LENGTH} characters: '{key}'"
                )
            if len(value) > self.MAX_VALUE_LENGTH:
                raise ValueError(
                    f"Metadata value for '{key}' exceeds {self.MAX_VALUE_LENGTH} characters"
                )
        self._data: dict[str, str] = dict(entries)

    @property
    def data(self) -> dict[str, str]:
        """Return a copy to preserve immutability."""
        return dict(self._data)

    def with_entry(self, key: str, value: str) -> Self:
        """Return new metadata with an added or updated entry."""
        new_data = dict(self._data)
        new_data[key] = value
        return self.__class__(new_data)

    def without_entry(self, key: str) -> Self:
        """Return new metadata with an entry removed."""
        new_data = dict(self._data)
        new_data.pop(key, None)
        return self.__class__(new_data)

    def get(self, key: str, default: str | None = None) -> str | None:
        """Get a metadata value by key."""
        return self._data.get(key, default)

    def __len__(self) -> int:
        return len(self._data)

    def __repr__(self) -> str:
        return f"TargetMetadata({len(self._data)} entries)"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, TargetMetadata):
            return NotImplemented
        return self._data == other._data

    def __hash__(self) -> int:
        return hash(tuple(sorted(self._data.items())))
