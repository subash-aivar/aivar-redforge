"""Event versioning and schema migration support — Sprint 25.

Provides:
- EventUpcaster protocol: transforms an old-schema event to a newer schema.
- VersionResolver: selects the correct upcaster chain for a given EventVersion.
- UpcasterChain: applies a sequence of upcasters in order.
- DefaultVersionResolver: identity resolver (no upcasters registered).

Design rules:
- No imports from infrastructure layer.
- Upcasters are pure functions over EventEnvelope.
- Upcaster chains are immutable once built.
- The resolver is injected, never instantiated inside the engine.
"""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import Sequence

from redforge.domain.platform.events import EventEnvelope
from redforge.domain.platform.value_objects import EventVersion

# ── Upcaster protocol ──────────────────────────────────────────────────────


@runtime_checkable
class EventUpcaster(Protocol):
    """Transforms a single EventEnvelope from one schema version to another.

    Upcasters MUST be idempotent — applying the same upcaster twice to an
    already-migrated event must return the event unchanged.

    The `source_version` and `target_version` declare the transformation
    boundary. The VersionResolver uses these to build chains.
    """

    source_version: EventVersion
    target_version: EventVersion

    def upcast(self, envelope: EventEnvelope) -> EventEnvelope:
        """Return a new envelope with the payload migrated to target_version.

        The returned envelope must have `metadata.schema_version == target_version`.
        """
        ...


# ── Upcaster chain ────────────────────────────────────────────────────────


class UpcasterChain:
    """Applies a sequence of upcasters in order.

    Chain: 1.0 → 1.1 → 2.0 → 2.1
    If an event is already at version 2.0, only the 2.0 → 2.1 upcaster fires.
    """

    def __init__(self, upcasters: Sequence[EventUpcaster]) -> None:
        self._upcasters = list(upcasters)

    def apply(self, envelope: EventEnvelope) -> EventEnvelope:
        """Apply all applicable upcasters to the envelope in chain order."""
        current = envelope
        for upcaster in self._upcasters:
            if (current.schema_version.is_compatible_with(upcaster.source_version)
                    and current.schema_version == upcaster.source_version):
                current = upcaster.upcast(current)
        return current

    @property
    def length(self) -> int:
        return len(self._upcasters)


# ── VersionResolver protocol ───────────────────────────────────────────────


@runtime_checkable
class VersionResolver(Protocol):
    """Resolves the upcaster chain for a given event type.

    The engine calls resolve() on every envelope it reads from storage.
    If the envelope is already at the current schema version, the chain
    must return the envelope unchanged (idempotent).
    """

    def resolve(self, event_type: str) -> UpcasterChain:
        """Return the upcaster chain for the given event_type."""
        ...

    def current_version(self, event_type: str) -> EventVersion:
        """Return the current (latest) schema version for an event type."""
        ...


# ── Default resolver (identity) ────────────────────────────────────────────


class DefaultVersionResolver:
    """Identity resolver — all events pass through unchanged.

    Used in production until upcasters are registered. Drop-in replacement
    when the first schema migration is required: register upcasters and swap.
    """

    def __init__(self) -> None:
        self._chains: dict[str, UpcasterChain] = {}
        self._current_versions: dict[str, EventVersion] = {}

    def register(
        self,
        event_type: str,
        upcaster: EventUpcaster,
    ) -> None:
        """Register an upcaster for an event type.

        Upcasters are appended in registration order — register them in
        chronological version order (oldest → newest).
        """
        existing = list(self._chains.get(event_type, UpcasterChain([])).
                        _upcasters)
        existing.append(upcaster)
        self._chains[event_type] = UpcasterChain(existing)
        self._current_versions[event_type] = upcaster.target_version

    def resolve(self, event_type: str) -> UpcasterChain:
        return self._chains.get(event_type, UpcasterChain([]))

    def current_version(self, event_type: str) -> EventVersion:
        return self._current_versions.get(event_type, EventVersion.v1())


# ── Concrete upcaster base ─────────────────────────────────────────────────


@dataclasses.dataclass(frozen=True, slots=True)
class PayloadFieldRenameUpcaster:
    """Reference upcaster: renames a top-level key in the payload dict.

    Example:
        Rename "user_id" → "actor_id" from version 1.0 → 1.1.

    The payload must be a dict. Non-dict payloads pass through unchanged.
    """

    source_version: EventVersion
    target_version: EventVersion
    old_field: str
    new_field: str

    def upcast(self, envelope: EventEnvelope) -> EventEnvelope:
        if not isinstance(envelope.payload, dict):
            return _bump_version(envelope, self.target_version)
        payload = dict(envelope.payload)
        if self.old_field in payload:
            payload[self.new_field] = payload.pop(self.old_field)
        return _bump_version(
            dataclasses.replace(envelope, payload=payload),
            self.target_version,
        )


def _bump_version(envelope: EventEnvelope, version: EventVersion) -> EventEnvelope:
    """Return envelope with metadata.schema_version set to `version`."""
    new_meta = dataclasses.replace(envelope.metadata, schema_version=version)
    return dataclasses.replace(envelope, metadata=new_meta)
