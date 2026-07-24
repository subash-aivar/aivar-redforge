"""Shared primitive validators for application-layer inputs."""

from __future__ import annotations

from uuid import UUID

from ulid import ULID

from campaign.application.exceptions import ApplicationValidationError
from redforge.shared.identifiers import EntityId


def validate_uuid(value: UUID | EntityId, field: str) -> None:
    if isinstance(value, (EntityId, ULID)):
        return
    if value.int == 0:
        raise ApplicationValidationError(f"'{field}' must be a valid non-nil UUID")


def validate_str(
    value: str,
    field: str,
    max_len: int,
    allow_empty: bool = False,
) -> None:
    if not allow_empty and not value.strip():
        raise ApplicationValidationError(f"'{field}' must not be empty")
    if len(value) > max_len:
        raise ApplicationValidationError(f"'{field}' must be at most {max_len} characters")
