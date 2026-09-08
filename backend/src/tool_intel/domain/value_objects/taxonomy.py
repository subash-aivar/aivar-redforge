"""Tool taxonomy value objects — alias and family. Both are
RedForge-native and defined locally: no cross-import of another bounded
context's domain module."""

from __future__ import annotations

from dataclasses import dataclass

from tool_intel.domain.exceptions.domain_exceptions import EmptyIdentifierError


@dataclass(frozen=True, slots=True)
class ToolAlias:
    """An alternate name this tool is tracked under by another vendor or
    feed. Never an identity — identity is `canonical_name`."""

    value: str

    def __post_init__(self) -> None:
        if not self.value.strip():
            raise EmptyIdentifierError("alias value")

    def __str__(self) -> str:
        return self.value


@dataclass(frozen=True, slots=True)
class ToolFamily:
    """A grouping label for related tools — e.g. the "Cobalt Strike"
    family covering its various loaders and beacons.

    Deliberately a free string, not a closed enum: tool families are
    coined by vendors continuously and do not close. `family_name` is
    optional at the aggregate level (`family: ToolFamily | None`), but
    when a family IS asserted it must be non-empty."""

    family_name: str

    def __post_init__(self) -> None:
        if not self.family_name.strip():
            raise EmptyIdentifierError("family_name")

    def __str__(self) -> str:
        return self.family_name
