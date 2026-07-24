"""Minimal shared command-shape validation for ai_security (M47A),
mirroring `vulnerability_engine`'s `command_validation.py` pattern."""

from __future__ import annotations

from ai_security.application.exceptions import InvalidDisplayNameError


def validate_name(name: str) -> None:
    if not name or not name.strip():
        raise InvalidDisplayNameError("must be a non-empty string")
