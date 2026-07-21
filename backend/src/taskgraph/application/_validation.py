"""Shared primitive validators for TaskGraph application-layer inputs."""

from __future__ import annotations

from typing import TYPE_CHECKING

from taskgraph.application.exceptions import ApplicationValidationError

if TYPE_CHECKING:
    from uuid import UUID


def validate_uuid(value: UUID, field: str) -> None:
    if value.int == 0:
        raise ApplicationValidationError(field, "must be a valid non-nil UUID")


def validate_str(
    value: str,
    field: str,
    max_len: int,
    allow_empty: bool = False,
) -> None:
    if not allow_empty and not value.strip():
        raise ApplicationValidationError(field, "must not be empty")
    if len(value) > max_len:
        raise ApplicationValidationError(field, f"must be at most {max_len} characters")
