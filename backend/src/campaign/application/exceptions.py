"""Campaign application exceptions."""

from __future__ import annotations


class ApplicationValidationError(Exception):
    """Raised when an application command fails input validation."""


class ApplicationNotFoundError(Exception):
    """Raised when a requested aggregate cannot be found."""


class ApplicationConflictError(Exception):
    """Raised when an operation conflicts with current state (e.g. optimistic lock)."""
