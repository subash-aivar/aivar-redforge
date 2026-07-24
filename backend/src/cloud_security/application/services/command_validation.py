"""Command-validation stages for cloud_security's application services
(M45A). Every stage is a pure function that either returns
successfully or raises one of `cloud_security.application.exceptions`'s
typed errors — never a bare `ValueError`."""

from __future__ import annotations

from cloud_security.application.exceptions import InvalidDisplayNameError


def validate_display_name(display_name: str) -> None:
    if not display_name.strip():
        raise InvalidDisplayNameError("display_name must be a non-empty string")
