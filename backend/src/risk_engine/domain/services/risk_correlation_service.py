"""RiskCorrelationService — determines whether two `RiskSignalReference`s
are correlatable (i.e. plausibly about the same subject) within a time
window. Stateless, pure, no I/O.

Judgment call: correlation is keyed on `subject_reference` equality
(when both signals carry one), not on `source_id` equality — two
signals from different source contexts about the same asset/target
are the interesting correlation case, and they would almost never
share a `source_id` (each context mints its own local identifiers).
When either signal lacks a `subject_reference`, they are considered
not correlatable — there is nothing to key the correlation on. This
must stay consistent with `IsCorrelatableSignalSpecification`, which
delegates here."""

from __future__ import annotations

from datetime import timedelta

from risk_engine.domain.value_objects.risk_signal import RiskSignalReference


class RiskCorrelationService:
    @staticmethod
    def are_correlatable(
        a: RiskSignalReference, b: RiskSignalReference, *, window: timedelta
    ) -> bool:
        if a.subject_reference is None or b.subject_reference is None:
            return False
        if a.subject_reference != b.subject_reference:
            return False
        return abs(a.observed_at - b.observed_at) <= window
