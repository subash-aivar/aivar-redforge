"""BaselineFinding — one immutable evaluation result against a single
`CloudAsset` (M45F).

Carries a severity, category, and rule reference only — never a
compliance-framework control mapping (no CIS/NIST/ISO/HIPAA/PCI id),
never a risk score, never a remediation action. `evidence_reference`
is an opaque pointer (e.g. to a snapshot of the attribute that
triggered the finding) — this domain layer never stores or interprets
the evidence itself."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from cloud_security.domain.exceptions.domain_exceptions import EmptyRuleIdentifierError

if TYPE_CHECKING:
    from datetime import datetime

    from cloud_security.domain.value_objects.enums import (
        CloudSeverity,
        FindingCategory,
        FindingStatus,
    )
    from cloud_security.domain.value_objects.identifiers import AssetId, FindingId, RuleId


@dataclass(frozen=True, slots=True)
class BaselineFinding:
    finding_id: FindingId
    asset_id: AssetId
    severity: CloudSeverity
    category: FindingCategory
    rule_id: RuleId
    rule_name: str
    description: str
    recommendation: str
    evidence_reference: str
    status: FindingStatus
    detected_at: datetime

    def __post_init__(self) -> None:
        if not self.rule_name.strip():
            raise EmptyRuleIdentifierError("rule_name")
        if not self.description.strip():
            raise EmptyRuleIdentifierError("description")
        if not self.recommendation.strip():
            raise EmptyRuleIdentifierError("recommendation")
