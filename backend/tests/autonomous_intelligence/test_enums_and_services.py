from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from autonomous_intelligence.domain.aggregates.autonomous_operations_policy import (
    AutonomousOperationsPolicy,
)
from autonomous_intelligence.domain.aggregates.optimization_model import OptimizationModel
from autonomous_intelligence.domain.aggregates.suggestion_outcome import SuggestionOutcome
from autonomous_intelligence.domain.exceptions.domain_exceptions import DomainInvariantViolation
from autonomous_intelligence.domain.services.feedback_ingestion_service import (
    FeedbackIngestionService,
)
from autonomous_intelligence.domain.value_objects.enums import (
    ModelStatus,
    OutcomeType,
    SuggestionStatus,
    SuggestionTargetType,
)
from autonomous_intelligence.domain.value_objects.identifiers import TenantId


@pytest.mark.parametrize("value", list(SuggestionStatus))
def test_suggestion_status(value: SuggestionStatus) -> None:
    assert isinstance(value.value, str)


@pytest.mark.parametrize("value", list(SuggestionTargetType))
def test_target_types(value: SuggestionTargetType) -> None:
    assert value.value == value.name.lower() or "_" in value.value


@pytest.mark.parametrize("value", list(ModelStatus))
def test_model_status(value: ModelStatus) -> None:
    assert value.value == value.name.lower()


@pytest.mark.parametrize("value", list(OutcomeType))
def test_outcome_types(value: OutcomeType) -> None:
    assert isinstance(value.value, str)


def test_policy_confidence_floor() -> None:
    p = AutonomousOperationsPolicy.default(TenantId(uuid4()))
    with pytest.raises(DomainInvariantViolation):
        p.set_min_confidence(SuggestionTargetType.DETECTION_RULE_TUNING, 0.1)


def test_outcome_measurement_and_feedback() -> None:
    tenant = TenantId(uuid4())
    outcome = SuggestionOutcome.create_pending(
        uuid4(), tenant, SuggestionTargetType.DETECTION_RULE_TUNING, 30, 0.4
    )
    outcome.record_measurement(0.3, datetime.now(UTC))
    assert outcome.delta == pytest.approx(-0.1)
    model = OptimizationModel.start_training(
        tenant, SuggestionTargetType.DETECTION_RULE_TUNING, "m", 1
    )
    FeedbackIngestionService().ingest(model, outcome)
    assert model.feedback_sample_count == 1
