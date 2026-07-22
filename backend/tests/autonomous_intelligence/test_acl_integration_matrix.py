from __future__ import annotations

from uuid import uuid4

import pytest

from autonomous_intelligence.infrastructure.acl.m28_performance_translator import (
    DetectionRulePerformanceReportedPayload,
    M28PerformanceTranslator,
)
from autonomous_intelligence.infrastructure.acl.m32_exposure_translator import (
    ExposureScoreUpdatedPayload,
    M32ExposureTranslator,
)
from autonomous_intelligence.infrastructure.acl.m33_anomaly_translator import (
    AnomalySignalDetectedPayload,
    M33AnomalyTranslator,
)
from autonomous_intelligence.infrastructure.acl.m33_ml_signal_translator import (
    M33MlSignalTranslator,
    MLModelTrainingCompletedPayload,
)
from autonomous_intelligence.infrastructure.acl.m34_lesson_translator import (
    IncidentLessonsLearnedPayload,
    M34LessonTranslator,
)
from campaign.infrastructure.acl.m36_scenario_proposal_subscriber import (
    M36ProposalSubscriber as CampSub,
)
from detection.infrastructure.acl.m36_rule_tuning_proposal_subscriber import (
    M36ProposalSubscriber as DetSub,
)
from playbook.infrastructure.acl.m36_playbook_synthesis_subscriber import (
    M36ProposalSubscriber as PbSub,
)
from posture_forecasting.infrastructure.acl.m32_exposure_translator import (
    ExposureScoreUpdatedPayload as PFPayload,
)
from posture_forecasting.infrastructure.acl.m32_exposure_translator import (
    M32ExposureTranslator as PFTranslator,
)
from threat_hunt.infrastructure.acl.m33_anomaly_translator import (
    AnomalySignalDetectedPayload as HuntPayload,
)
from threat_hunt.infrastructure.acl.m33_anomaly_translator import (
    M33AnomalyTranslator as HuntTranslator,
)


@pytest.mark.parametrize("fp_rate", [0.0, 0.1, 0.25, 0.5, 0.75, 0.9, 1.0])
def test_m28_translator(fp_rate: float) -> None:
    sig = M28PerformanceTranslator().translate(
        DetectionRulePerformanceReportedPayload("t", "r1", "HIGH", {"fp": fp_rate})
    )
    assert sig is not None


@pytest.mark.parametrize("score", [0.0, 10.0, 25.0, 50.0, 75.0, 90.0, 100.0])
def test_m32_translator(score: float) -> None:
    sig = M32ExposureTranslator().translate(
        ExposureScoreUpdatedPayload("t", "exp-1", "MEDIUM", {"score": score})
    )
    assert sig is not None


@pytest.mark.parametrize("strength", [0.1, 0.3, 0.5, 0.7, 0.9, 1.0])
def test_m33_anomaly_translator(strength: float) -> None:
    sig = M33AnomalyTranslator().translate(
        AnomalySignalDetectedPayload("t", "s1", "HIGH", {"strength": strength})
    )
    assert sig is not None


@pytest.mark.parametrize("status", ["succeeded", "failed", "partial"])
def test_m33_ml_translator(status: str) -> None:
    sig = M33MlSignalTranslator().translate(
        MLModelTrainingCompletedPayload("t", "m1", status, {"precision": 0.8})
    )
    assert sig is not None


@pytest.mark.parametrize(
    "pattern", ["credential_access", "lateral", "exfil", "persistence", "discovery"]
)
def test_m34_lesson_translator(pattern: str) -> None:
    sig = M34LessonTranslator().translate(
        IncidentLessonsLearnedPayload("t", "inc1", "INFO", {"pattern": pattern})
    )
    assert sig is not None


@pytest.mark.parametrize("score", [1.0, 20.0, 40.0, 60.0, 80.0, 99.0])
def test_posture_inbound_acl(score: float) -> None:
    assert PFTranslator().translate(PFPayload("t", score, 0, 1, 0.5)) is not None


@pytest.mark.parametrize("strength", [0.2, 0.4, 0.6, 0.8, 1.0])
def test_hunt_inbound_acl(strength: float) -> None:
    assert HuntTranslator().translate(HuntPayload("t", "s", strength, "T1003")) is not None


@pytest.mark.parametrize("payload_key", ["a", "b", "c", "d", "e", "f", "g", "h"])
def test_outbound_detection_subscriber(payload_key: str) -> None:
    item = DetSub().handle(str(uuid4()), str(uuid4()), {payload_key: 1})
    assert item.status == "pending"


@pytest.mark.parametrize("payload_key", ["a", "b", "c", "d", "e", "f", "g", "h"])
def test_outbound_campaign_subscriber(payload_key: str) -> None:
    item = CampSub().handle(str(uuid4()), str(uuid4()), {payload_key: 1})
    assert item.status == "pending"


@pytest.mark.parametrize("payload_key", ["a", "b", "c", "d", "e", "f", "g", "h"])
def test_outbound_playbook_subscriber(payload_key: str) -> None:
    item = PbSub().handle(str(uuid4()), str(uuid4()), {payload_key: 1})
    assert item.status == "pending"


def test_acl_translation_error_swallowed() -> None:
    class Boom:
        pass

    for translator in (
        M28PerformanceTranslator(),
        M32ExposureTranslator(),
        M33AnomalyTranslator(),
        M33MlSignalTranslator(),
        M34LessonTranslator(),
    ):
        assert translator.translate(Boom()) is None  # type: ignore[arg-type]
