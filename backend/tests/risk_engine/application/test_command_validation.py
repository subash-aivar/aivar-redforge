from __future__ import annotations

import pytest

from risk_engine.application.exceptions import EmptySignalsError, InvalidSubjectReferenceError
from risk_engine.application.services.command_validation import (
    validate_signals_non_empty,
    validate_subject_reference,
)


def test_validate_subject_reference_accepts_non_empty() -> None:
    validate_subject_reference("asset-1")


@pytest.mark.parametrize("value", ["", "   "])
def test_validate_subject_reference_rejects_blank(value: str) -> None:
    with pytest.raises(InvalidSubjectReferenceError):
        validate_subject_reference(value)


def test_validate_signals_non_empty_accepts_non_empty_tuple() -> None:
    validate_signals_non_empty((1,))


def test_validate_signals_non_empty_rejects_empty() -> None:
    with pytest.raises(EmptySignalsError):
        validate_signals_non_empty(())
