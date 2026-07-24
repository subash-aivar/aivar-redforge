"""Domain exceptions for siem_shared's Canonical Event Model (M37 §2.1)."""

from __future__ import annotations


class SiemSharedDomainError(Exception):
    """Base domain error for siem_shared."""


class InvalidFingerprintError(SiemSharedDomainError):
    def __init__(self) -> None:
        super().__init__("EventFingerprint value must be a non-empty string")


class InvalidTimestampOrderingError(SiemSharedDomainError):
    def __init__(self) -> None:
        super().__init__("EventTimestamp.ingested_at must not be earlier than occurred_at")


class NaiveTimestampError(SiemSharedDomainError):
    def __init__(self, field_name: str) -> None:
        super().__init__(f"EventTimestamp.{field_name} must be timezone-aware")


class NonSerializableAttributeError(SiemSharedDomainError):
    def __init__(self, path: str, value: object) -> None:
        super().__init__(
            f"EventMetadata.attributes[{path}] is not JSON-serializable-safe: "
            f"{type(value).__name__}"
        )


class EmptyVendorError(SiemSharedDomainError):
    def __init__(self) -> None:
        super().__init__("EventSource.vendor must be a non-empty string")


class MissingConnectorIdError(SiemSharedDomainError):
    def __init__(self) -> None:
        super().__init__(
            "EventSource.source_connector_id is required for connector-shaped sources"
        )


class InvalidSchemaVersionStringError(SiemSharedDomainError):
    def __init__(self, raw: str) -> None:
        super().__init__(f"Invalid SchemaVersion string: {raw!r} (expected 'major.minor')")


class IncompatibleSchemaVersionError(SiemSharedDomainError):
    def __init__(self, expected_major: int, actual_major: int) -> None:
        super().__init__(
            f"Incompatible CEM schema major version: expected {expected_major}, "
            f"got {actual_major}"
        )


class EmptyRawPayloadRefError(SiemSharedDomainError):
    def __init__(self) -> None:
        super().__init__("EventMetadata.raw_payload_ref must be a non-empty string when set")


class NoUpcasterAvailableError(SiemSharedDomainError):
    def __init__(self, from_version: object) -> None:
        super().__init__(f"No registered SchemaUpcaster can upcast from version {from_version}")
