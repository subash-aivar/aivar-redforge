"""EventOutcome — whether the source-reported action succeeded (M37 §2.1)."""

from __future__ import annotations

from enum import StrEnum


class EventOutcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    UNKNOWN = "unknown"
