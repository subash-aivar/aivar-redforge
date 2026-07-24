from __future__ import annotations

from datetime import UTC, datetime

import pytest

from cloud_security.domain.exceptions.domain_exceptions import EmptyRuleIdentifierError
from cloud_security.domain.value_objects.baseline_finding import BaselineFinding
from cloud_security.domain.value_objects.enums import (
    CloudSeverity,
    FindingCategory,
    FindingStatus,
)
from cloud_security.domain.value_objects.identifiers import AssetId, FindingId, RuleId

NOW = datetime.now(UTC)


def _finding(**overrides) -> BaselineFinding:
    defaults = {
        "finding_id": FindingId.generate(),
        "asset_id": AssetId.generate(),
        "severity": CloudSeverity.HIGH,
        "category": FindingCategory.NETWORKING,
        "rule_id": RuleId("cs-001"),
        "rule_name": "Unrestricted ingress",
        "description": "Security group allows 0.0.0.0/0 on port 22",
        "recommendation": "Restrict ingress to known CIDR ranges",
        "evidence_reference": "evidence://sg-123/ingress-rules",
        "status": FindingStatus.OPEN,
        "detected_at": NOW,
    }
    defaults.update(overrides)
    return BaselineFinding(**defaults)


def test_valid_finding_constructs() -> None:
    finding = _finding()
    assert finding.severity == CloudSeverity.HIGH
    assert finding.status == FindingStatus.OPEN


@pytest.mark.parametrize("field_name", ["rule_name", "description", "recommendation"])
def test_rejects_empty_required_text_fields(field_name: str) -> None:
    with pytest.raises(EmptyRuleIdentifierError):
        _finding(**{field_name: "   "})


def test_rule_id_rejects_empty_value() -> None:
    from cloud_security.domain.exceptions.domain_exceptions import EmptyIdentifierError

    with pytest.raises(EmptyIdentifierError):
        RuleId("")
