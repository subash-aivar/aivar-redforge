"""Domain exceptions for tool_intel.

Independent of `redforge.domain.threat_intel`, `ioc_intelligence`,
`threat_actor_intel`, `attack_pattern_intel`, `malware_intel`,
`campaign_intel` and `intelligence_relationships` — tool_intel is its
own bounded context and must not import domain objects from any of
them.
"""

from __future__ import annotations


class ToolDomainError(Exception):
    """Base domain error for tool_intel."""


class TenantMismatchError(ToolDomainError):
    def __init__(self, expected: object, actual: object) -> None:
        super().__init__(f"Tenant mismatch: expected {expected}, got {actual}")


class EmptyIdentifierError(ToolDomainError):
    def __init__(self, identifier_name: str) -> None:
        super().__init__(f"{identifier_name} must be a non-empty string")


class InvalidCanonicalNameError(ToolDomainError):
    def __init__(self, raw_value: str) -> None:
        self.raw_value = raw_value
        super().__init__(
            f"Invalid tool canonical_name {raw_value!r} — must normalize to a non-empty identifier"
        )


class InvalidLifecycleTransitionError(ToolDomainError):
    """Raised for an illegal RECORD-lifecycle transition
    (`ToolLifecycleStatus`)."""

    def __init__(self, from_state: str, to_state: str) -> None:
        self.from_state = from_state
        self.to_state = to_state
        super().__init__(f"Invalid lifecycle transition {from_state} -> {to_state}")


class MissingSupersededByError(ToolDomainError):
    def __init__(self) -> None:
        super().__init__("supersede() requires a superseded_by ToolId")


class DuplicateToolError(ToolDomainError):
    """Raised by the identity policy when a `canonical_name` already
    exists within the same scope (tenant_id or global)."""

    def __init__(self, canonical_name: str) -> None:
        self.canonical_name = canonical_name
        super().__init__(f"A Tool named {canonical_name!r} already exists in this scope")


class MissingSourceAttributionError(ToolDomainError):
    def __init__(self, action: str) -> None:
        super().__init__(f"{action} requires a SourceAttribution as evidence")
