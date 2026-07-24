"""IDetectionEvaluatorRegistry — registration/lookup contract (M44A §4).

`InMemoryDetectionEvaluatorRegistry` (M44A §4) is this milestone's one
concrete implementation.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from siem_detection.application.ports.i_detection_evaluator import IDetectionEvaluator
    from siem_shared.domain.value_objects.schema_version import SchemaVersion


class IDetectionEvaluatorRegistry(Protocol):
    def register(self, evaluator: IDetectionEvaluator) -> None:
        """Raises `DuplicateEvaluatorRegistrationError` if an evaluator
        for the same (rule_id, schema_version) is already registered."""
        ...

    def resolve(self, rule_id: str, requested_version: SchemaVersion) -> IDetectionEvaluator:
        """Deterministic selection: raises `UnsupportedEvaluatorError` if
        `rule_id` has no registrations, `UnsupportedEvaluatorVersionError`
        if none are compatible with `requested_version`,
        `AmbiguousEvaluatorSelectionError` if more than one is."""
        ...

    def is_registered(self, rule_id: str, schema_version: SchemaVersion) -> bool: ...
