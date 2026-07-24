"""Shared primitive validators for application-layer command/query inputs."""

from __future__ import annotations

from uuid import UUID  # noqa: TC003 — used at runtime (value.int)

from ulid import ULID

from credential_vault.application.exceptions import ApplicationValidationError
from redforge.shared.identifiers import EntityId


def validate_uuid(value: UUID | EntityId, field: str) -> None:
    """Raise ApplicationValidationError if value is the nil UUID."""
    if isinstance(value, (EntityId, ULID)):
        return
    if value.int == 0:
        raise ApplicationValidationError(field, "must be a valid non-nil UUID")


def validate_str(
    value: str,
    field: str,
    max_len: int,
    allow_empty: bool = False,
) -> None:
    """Raise ApplicationValidationError if value is empty or exceeds max_len."""
    if not allow_empty and len(value) == 0:
        raise ApplicationValidationError(field, "must not be empty")
    if len(value) > max_len:
        raise ApplicationValidationError(field, f"must be at most {max_len} characters")


def validate_limit(value: int) -> int:
    """Validate and clamp limit to the inclusive range 1-1000."""
    if value < 1:
        raise ApplicationValidationError("limit", "must be 1-1000")
    return max(1, min(value, 1000))


def validate_offset(value: int) -> int:
    """Validate that offset is non-negative and return it unchanged."""
    if value < 0:
        raise ApplicationValidationError("offset", "must be >= 0")
    return value
