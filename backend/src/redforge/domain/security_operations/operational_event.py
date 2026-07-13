"""OperationalEvent — the sanitized, client-facing projection of a raw
internal row (M15).

This is the ONE shape ever returned to a browser by the Security
Operations API/stream. It is built exclusively by
`application/security_operations/projection_registry.py`'s projectors —
never by forwarding a raw domain/infra row's own fields directly. Every
field here is a short, bounded, backend-controlled scalar. There is no
field for a stack trace, SQL text, raw HTTP body, header dict,
Authorization value, cookie, bearer token, credential, or private key —
by construction, not by a redaction pass applied afterward.

`cursor` is a composite, lexicographically-sortable string —
`f"{occurred_at_iso}|{source_tag}|{row_key}"` — assigned by
`application/security_operations/stream_service.py` when it merges rows
from the (up to) four durable per-bounded-context tables this milestone
reads from (validation_execution_events, security_drift_events,
continuous_validation_policy_lifecycle_events,
runtime_component_health_transitions). See that module's docstring for
why a composite string was chosen over resurrecting the dormant generic
`platform_events` global_position sequence. ISO-8601 UTC timestamps
sort lexicographically in timestamp order, so this cursor IS the SSE
wire-level `id:`/`Last-Event-ID` value — no separate numeric position
is needed.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from redforge.domain.security_operations.value_objects import (
        OperationalImportance,
        SourceDomain,
    )

# Hard cap on title/summary length — a projector that produces a longer
# string is truncated, never rejected (a defensive bound, not expected
# to trigger since projectors only ever interpolate short, pre-extracted
# identifiers/enum values, never a raw evidence blob).
_MAX_TEXT_LENGTH = 240


def _bounded(text: str) -> str:
    return text[:_MAX_TEXT_LENGTH]


@dataclass(frozen=True, slots=True)
class OperationalEvent:
    """One row of the Security Operations event stream / change feed."""

    cursor: str
    event_id: str
    organization_id: str
    source_domain: SourceDomain
    importance: OperationalImportance
    title: str
    summary: str
    entity_type: str
    entity_id: str
    occurred_at: str
    """ISO-8601 UTC timestamp string."""

    schema_version: int = 1

    def __post_init__(self) -> None:
        object.__setattr__(self, "title", _bounded(self.title))
        object.__setattr__(self, "summary", _bounded(self.summary))

    def with_cursor(self, cursor: str) -> OperationalEvent:
        return replace(self, cursor=cursor)
