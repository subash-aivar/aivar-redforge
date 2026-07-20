"""Shared primitive validators for application-layer command/query inputs."""

from __future__ import annotations

from uuid import UUID

from execution.application.exceptions import ApplicationValidationError


def validate_uuid(value: UUID, field: str) -> None:
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


def validate_limit(value: int) -> int:
    if value < 1:
        raise ApplicationValidationError("limit", "must be 1-1000")
    return max(1, min(value, 1000))


def validate_offset(value: int) -> int:
    if value < 0:
        raise ApplicationValidationError("offset", "must be >= 0")
    return value
