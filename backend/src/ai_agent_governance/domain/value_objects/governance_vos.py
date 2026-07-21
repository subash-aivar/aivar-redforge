from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from ai_agent_governance.domain.value_objects.enums import (
    AuthorizedActionCategory,
    DataSensitivityClassification,
)
from ai_agent_governance.domain.value_objects.identifiers import (
    AgentOperationalEnvelopeId,
    AISystemAssetId,
)


@dataclass(frozen=True, slots=True)
class AISystemAssetRef:
    asset_id: AISystemAssetId


@dataclass(frozen=True, slots=True)
class AgentOperationalEnvelopeRef:
    envelope_id: AgentOperationalEnvelopeId
    envelope_version: int


@dataclass(frozen=True, slots=True)
class RateCeiling:
    category: AuthorizedActionCategory
    max_actions: int
    window: timedelta


@dataclass(frozen=True, slots=True)
class AuthorizedResourceScope:
    resource_pattern: str
    max_data_sensitivity: DataSensitivityClassification


@dataclass(frozen=True, slots=True)
class ObservedAction:
    action_category: AuthorizedActionCategory
    resource: str
    data_sensitivity: DataSensitivityClassification
    human_approval_present: bool
    occurred_at: datetime
    idempotency_key: str
    metadata: dict[str, str]


@dataclass(frozen=True, slots=True)
class EnvelopeApprovedBy:
    approver_id: str
    approved_at: datetime
