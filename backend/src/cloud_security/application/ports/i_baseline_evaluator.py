"""IBaselineEvaluator — the low-level rule-evaluation extension point
(M45F): given one `CloudAsset`, produce zero or more `BaselineFinding`s.
No concrete implementation exists in this milestone — no CIS/NIST/ISO/
HIPAA/PCI rule content is defined here or anywhere in this bounded
context. A concrete `IBaselineProvider` implementation would delegate
to one or more of these internally; this milestone's application
service never calls an `IBaselineEvaluator` directly, only the
`IBaselineProvider` it's wrapped in."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Sequence

    from cloud_security.domain.aggregates.cloud_asset import CloudAsset
    from cloud_security.domain.value_objects.baseline_finding import BaselineFinding


class IBaselineEvaluator(Protocol):
    def evaluate(self, asset: CloudAsset) -> Sequence[BaselineFinding]:
        """Return every finding produced by evaluating `asset` against
        this evaluator's rule(s). Implementations should raise on an
        asset shape they cannot evaluate — the caller translates that
        into a per-asset failure, it does not swallow it."""
        ...
