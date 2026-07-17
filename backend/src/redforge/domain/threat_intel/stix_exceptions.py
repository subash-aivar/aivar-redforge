"""Domain exceptions for STIX 2.1 parsing/validation — M22 Phase 3
(STIX/TAXII Integration).

All subclass `ValidationError` (HTTP 422 if ever surfaced at an API
boundary), mirroring the exact convention `reference_data_exceptions.py`
(M22 Phase 1) and `feed_exceptions.py` (M22 Phase 2) already establish.
In practice these are raised and caught entirely inside
`StixTaxiiFeedConnector.execute()` (application layer) — they never
reach an HTTP response directly, since a connector failure is recorded
as a failed `FeedSyncRun` by `FeedSyncOrchestrationService`, not
translated to a status code. The `ValidationError` base is still the
correct classification: every one of these means the STIX payload
itself was malformed or unsafe to process, not a transient transport
failure.

The size/count/depth caps these exceptions guard are the direct fix for
the Hardening Review's P0 finding ("Malicious STIX bundle can trigger
object graph explosion during parsing") — every cap is enforced at the
raw JSON level, before any STIX object is individually parsed.
"""

from __future__ import annotations

from redforge.core.exceptions import ValidationError


class StixContainerTooLargeError(ValidationError):
    """Raised when a raw STIX bundle/TAXII envelope payload exceeds the
    configured maximum byte size, before it is ever handed to
    `json.loads`."""

    def __init__(self, byte_length: int, max_bytes: int) -> None:
        super().__init__(
            f"STIX container payload of {byte_length} bytes exceeds the "
            f"maximum of {max_bytes} bytes"
        )
        self.byte_length = byte_length
        self.max_bytes = max_bytes


class MalformedStixContainerError(ValidationError):
    """Raised when a raw payload is not valid JSON, or does not have
    the shape of a STIX 2.1 `bundle` object or a TAXII 2.1 objects
    envelope (both are `{"objects": [...]}` at the top level)."""

    def __init__(self, reason: str) -> None:
        super().__init__(f"Malformed STIX/TAXII container: {reason}")


class StixContainerNestingTooDeepError(ValidationError):
    """Raised when the parsed JSON structure nests dict/list values
    deeper than the configured cap — defense against a crafted payload
    designed to exhaust the stack or memory during traversal."""

    def __init__(self, max_depth: int) -> None:
        super().__init__(f"STIX container JSON nesting exceeds the maximum depth of {max_depth}")
        self.max_depth = max_depth


class StixObjectCountExceededError(ValidationError):
    """Raised when a single container's `objects` array holds more
    entries than the configured cap."""

    def __init__(self, count: int, max_objects: int) -> None:
        super().__init__(
            f"STIX container holds {count} objects, exceeding the maximum of {max_objects}"
        )
        self.count = count
        self.max_objects = max_objects


class MalformedStixObjectError(ValidationError):
    """Raised when one individual STIX object of a *supported* type
    (`attack-pattern`, `x-mitre-tactic`, `relationship`, `vulnerability`)
    is missing a required field or has a field of the wrong shape.
    Objects of unsupported types are never an error — they are counted
    as skipped by the caller instead, since a STIX bundle legitimately
    contains many object types this connector does not map (identity,
    marking-definition, intrusion-set, malware, course-of-action, ...).
    """

    def __init__(self, stix_id: str, reason: str) -> None:
        super().__init__(f"Malformed STIX object {stix_id!r}: {reason}")
        self.stix_id = stix_id


class InvalidStixIdError(ValidationError):
    """Raised when a STIX object identifier does not match the STIX 2.1
    `<type>--<UUID>` identifier grammar."""

    def __init__(self, raw: str) -> None:
        super().__init__(f"Invalid STIX object id: {raw!r} — expected '<type>--<uuid>'")
