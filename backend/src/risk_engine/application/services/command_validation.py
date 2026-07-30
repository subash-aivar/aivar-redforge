"""Minimal shared command-shape validation for risk_engine (M48C),
mirroring `vulnerability_engine`'s `command_validation.py` pattern.
Only request-shape checks that the domain layer itself does not
already perform live here — everything else (e.g. score bounds,
non-empty contributions) is delegated to domain value-object/aggregate
validation, never duplicated."""

from __future__ import annotations

from risk_engine.application.exceptions import (
    EmptySignalsError,
    InvalidSubjectReferenceError,
)


def validate_subject_reference(subject_reference: str) -> None:
    if not subject_reference or not subject_reference.strip():
        raise InvalidSubjectReferenceError("must be a non-empty string")


def validate_signals_non_empty(signals: object) -> None:
    if not signals:
        raise EmptySignalsError()
