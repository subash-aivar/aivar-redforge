"""Domain exceptions for campaign_intel.

Independent of `redforge.domain.threat_intel`, `ioc_intelligence`,
`threat_actor_intel`, `attack_pattern_intel`, `malware_intel` and
`intelligence_relationships` — campaign_intel is its own bounded
context and must not import domain objects from any of them.
"""

from __future__ import annotations


class CampaignDomainError(Exception):
    """Base domain error for campaign_intel."""


class TenantMismatchError(CampaignDomainError):
    def __init__(self, expected: object, actual: object) -> None:
        super().__init__(f"Tenant mismatch: expected {expected}, got {actual}")


class EmptyIdentifierError(CampaignDomainError):
    def __init__(self, identifier_name: str) -> None:
        super().__init__(f"{identifier_name} must be a non-empty string")


class InvalidCanonicalNameError(CampaignDomainError):
    def __init__(self, raw_value: str) -> None:
        self.raw_value = raw_value
        super().__init__(
            f"Invalid campaign canonical_name {raw_value!r} — must normalize to a "
            "non-empty identifier"
        )


class InvalidRegionError(CampaignDomainError):
    def __init__(self, raw_value: str) -> None:
        self.raw_value = raw_value
        super().__init__(
            f"Invalid campaign region {raw_value!r} — must normalize to a non-empty "
            "code of letters, digits or hyphens"
        )


class InvalidTimelineError(CampaignDomainError):
    def __init__(self, reason: str) -> None:
        super().__init__(f"Invalid campaign timeline: {reason}")


class InvalidLifecycleTransitionError(CampaignDomainError):
    """Raised for an illegal RECORD-lifecycle transition
    (`CampaignLifecycleStatus`) — never for the real-world campaign's own
    `CampaignStatus`."""

    def __init__(self, from_state: str, to_state: str) -> None:
        self.from_state = from_state
        self.to_state = to_state
        super().__init__(f"Invalid lifecycle transition {from_state} -> {to_state}")


class InvalidStatusTransitionError(CampaignDomainError):
    """Raised for an illegal real-world campaign `CampaignStatus`
    transition — a completely independent axis from the record
    lifecycle."""

    def __init__(self, from_state: str, to_state: str) -> None:
        self.from_state = from_state
        self.to_state = to_state
        super().__init__(f"Invalid status transition {from_state} -> {to_state}")


class MissingSupersededByError(CampaignDomainError):
    def __init__(self) -> None:
        super().__init__("supersede() requires a superseded_by CampaignId")


class DuplicateCampaignError(CampaignDomainError):
    """Raised by the identity policy when a `canonical_name` already
    exists within the same scope (tenant_id or global)."""

    def __init__(self, canonical_name: str) -> None:
        self.canonical_name = canonical_name
        super().__init__(f"A Campaign named {canonical_name!r} already exists in this scope")


class MissingSourceAttributionError(CampaignDomainError):
    def __init__(self, action: str) -> None:
        super().__init__(f"{action} requires a SourceAttribution as evidence")
