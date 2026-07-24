"""Shared primitive validators for application-layer inputs."""

from __future__ import annotations

from uuid import UUID

from ulid import ULID

from engagement.application.exceptions import ApplicationValidationError
from redforge.shared.identifiers import EntityId


def validate_uuid(value: UUID | EntityId, field: str) -> None:
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
    if not allow_empty and len(value) == 0:
        raise ApplicationValidationError(field, "must not be empty")
    if len(value) > max_len:
        raise ApplicationValidationError(field, f"must be at most {max_len} characters")
