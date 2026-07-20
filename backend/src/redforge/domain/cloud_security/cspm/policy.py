"""CSPMPolicy aggregate — versioned reusable security control definition."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from redforge.domain.cloud_security.cspm.entities import RemediationReference
from redforge.domain.cloud_security.cspm.exceptions import InvalidCSPMArgumentError
from redforge.domain.cloud_security.cspm.value_objects import (
    ComplianceRef,
    CSPMPolicyId,
    CSPMRuleId,
    FindingSeverity,
    PolicyVersion,
    RuleMetadata,
)


@dataclass
class CSPMPolicy:
    id: CSPMPolicyId
    rule_id: CSPMRuleId
    title: str
    description: str
    severity: FindingSeverity
    version: PolicyVersion
    provider_types: tuple[str, ...]
    asset_types: tuple[str, ...]
    metadata: RuleMetadata
    remediation: RemediationReference
    compliance_mapping: list[ComplianceRef]
    rule: dict[str, Any]
    inherits_from: str | None
    enabled: bool
    evaluation_strategy: str
    created_at: datetime
    updated_at: datetime
    row_version: int = 1

    @classmethod
    def from_definition(
        cls,
        *,
        policy_id: str,
        rule_id: str,
        title: str,
        description: str,
        severity: str,
        version: str,
        provider_types: list[str],
        asset_types: list[str],
        metadata: RuleMetadata,
        remediation: RemediationReference,
        compliance_mapping: list[ComplianceRef],
        rule: dict[str, Any],
        inherits_from: str | None = None,
        enabled: bool = True,
        evaluation_strategy: str = "boolean",
        now: datetime | None = None,
    ) -> CSPMPolicy:
        if not title.strip():
            raise InvalidCSPMArgumentError("title", "required")
        if not rule:
            raise InvalidCSPMArgumentError("rule", "required")
        ts = now or datetime.now(UTC)
        return cls(
            id=CSPMPolicyId(policy_id.strip()),
            rule_id=CSPMRuleId(rule_id.strip() or policy_id.strip()),
            title=title.strip()[:512],
            description=description.strip()[:4000],
            severity=FindingSeverity(severity.upper()),
            version=PolicyVersion.parse(version),
            provider_types=tuple(p.upper() for p in provider_types),
            asset_types=tuple(a.upper() for a in asset_types),
            metadata=metadata,
            remediation=remediation,
            compliance_mapping=list(compliance_mapping),
            rule=dict(rule),
            inherits_from=inherits_from,
            enabled=enabled,
            evaluation_strategy=evaluation_strategy,
            created_at=ts,
            updated_at=ts,
            row_version=1,
        )

    def applies_to(self, *, provider_type: str, asset_type: str) -> bool:
        if not self.enabled:
            return False
        providers = self.provider_types
        assets = self.asset_types
        provider_ok = not providers or provider_type.upper() in providers or "*" in providers
        asset_ok = not assets or asset_type.upper() in assets or "*" in assets
        return provider_ok and asset_ok

    def disable(self, *, now: datetime | None = None) -> None:
        ts = now or datetime.now(UTC)
        self.enabled = False
        self.updated_at = ts
        self.row_version += 1

    def enable(self, *, now: datetime | None = None) -> None:
        ts = now or datetime.now(UTC)
        self.enabled = True
        self.updated_at = ts
        self.row_version += 1
