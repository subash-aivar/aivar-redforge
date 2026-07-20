"""CSPMFinding aggregate — posture violation lifecycle."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from redforge.domain.cloud_security.cspm.entities import (
    FindingEvidence,
    FindingHistory,
    RemediationReference,
)
from redforge.domain.cloud_security.cspm.events import (
    CSPMDomainEvent,
    CSPMFindingCreated,
    CSPMFindingReopened,
    CSPMFindingResolved,
    CSPMFindingUpdated,
)
from redforge.domain.cloud_security.cspm.exceptions import (
    InvalidCSPMArgumentError,
    InvalidFindingTransitionError,
)
from redforge.domain.cloud_security.cspm.value_objects import (
    ComplianceRef,
    CSPMFindingId,
    CSPMPolicyId,
    CSPMRuleId,
    FindingConfidence,
    FindingSeverity,
    FindingStatus,
)
from redforge.domain.cloud_security.value_objects import CloudAssetId, OrganizationId

_ALLOWED_TRANSITIONS: dict[FindingStatus, frozenset[FindingStatus]] = {
    FindingStatus.OPEN: frozenset(
        {
            FindingStatus.CONFIRMED,
            FindingStatus.SUPPRESSED,
            FindingStatus.ACCEPTED_RISK,
            FindingStatus.RESOLVED,
            FindingStatus.EXPIRED,
        }
    ),
    FindingStatus.CONFIRMED: frozenset(
        {
            FindingStatus.SUPPRESSED,
            FindingStatus.ACCEPTED_RISK,
            FindingStatus.RESOLVED,
            FindingStatus.EXPIRED,
        }
    ),
    FindingStatus.SUPPRESSED: frozenset(
        {FindingStatus.OPEN, FindingStatus.REOPENED, FindingStatus.EXPIRED}
    ),
    FindingStatus.ACCEPTED_RISK: frozenset(
        {FindingStatus.OPEN, FindingStatus.REOPENED, FindingStatus.RESOLVED}
    ),
    FindingStatus.RESOLVED: frozenset({FindingStatus.REOPENED}),
    FindingStatus.REOPENED: frozenset(
        {
            FindingStatus.CONFIRMED,
            FindingStatus.SUPPRESSED,
            FindingStatus.ACCEPTED_RISK,
            FindingStatus.RESOLVED,
            FindingStatus.EXPIRED,
        }
    ),
    FindingStatus.EXPIRED: frozenset({FindingStatus.REOPENED, FindingStatus.OPEN}),
}


@dataclass
class CSPMFinding:
    id: CSPMFindingId
    cloud_asset_id: CloudAssetId
    organization_id: OrganizationId
    policy_id: CSPMPolicyId
    rule_id: CSPMRuleId
    severity: FindingSeverity
    confidence: FindingConfidence
    title: str
    description: str
    remediation: RemediationReference
    compliance_mapping: list[ComplianceRef]
    status: FindingStatus
    evidence: list[FindingEvidence]
    history: list[FindingHistory]
    first_seen_at: datetime
    last_seen_at: datetime
    detected_at: datetime
    resolved_at: datetime | None
    reopened_at: datetime | None
    suppressed_until: datetime | None
    accepted_by: str | None
    accepted_reason: str | None
    config_hash: str
    fingerprint: str
    created_at: datetime
    updated_at: datetime
    version: int = 1
    _pending_events: list[CSPMDomainEvent] = field(default_factory=list, repr=False)

    @staticmethod
    def build_fingerprint(policy_id: str, rule_id: str, cloud_asset_id: str) -> str:
        return f"{policy_id}:{rule_id}:{cloud_asset_id}"

    @classmethod
    def open(
        cls,
        *,
        cloud_asset_id: CloudAssetId,
        organization_id: OrganizationId,
        policy_id: CSPMPolicyId,
        rule_id: CSPMRuleId,
        severity: FindingSeverity,
        title: str,
        description: str,
        remediation: RemediationReference,
        compliance_mapping: list[ComplianceRef],
        evidence: list[FindingEvidence],
        config_hash: str,
        confidence: FindingConfidence = FindingConfidence.HIGH,
        now: datetime | None = None,
        finding_id: CSPMFindingId | None = None,
    ) -> CSPMFinding:
        if not title.strip():
            raise InvalidCSPMArgumentError("title", "required")
        ts = now or datetime.now(UTC)
        fid = finding_id or CSPMFindingId.generate()
        fingerprint = cls.build_fingerprint(str(policy_id), str(rule_id), str(cloud_asset_id))
        aggregate = cls(
            id=fid,
            cloud_asset_id=cloud_asset_id,
            organization_id=organization_id,
            policy_id=policy_id,
            rule_id=rule_id,
            severity=severity,
            confidence=confidence,
            title=title.strip()[:512],
            description=description.strip()[:4000],
            remediation=remediation,
            compliance_mapping=list(compliance_mapping),
            status=FindingStatus.OPEN,
            evidence=list(evidence),
            history=[
                FindingHistory.record(
                    from_status=None,
                    to_status=FindingStatus.OPEN,
                    changed_at=ts,
                    changed_by="system",
                    reason="created",
                )
            ],
            first_seen_at=ts,
            last_seen_at=ts,
            detected_at=ts,
            resolved_at=None,
            reopened_at=None,
            suppressed_until=None,
            accepted_by=None,
            accepted_reason=None,
            config_hash=config_hash,
            fingerprint=fingerprint,
            created_at=ts,
            updated_at=ts,
            version=1,
        )
        aggregate._pending_events.append(
            CSPMFindingCreated(
                finding_id=str(fid),
                organization_id=str(organization_id),
                cloud_asset_id=str(cloud_asset_id),
                policy_id=str(policy_id),
                severity=severity.value,
                occurred_at=ts,
            )
        )
        return aggregate

    def touch_seen(
        self,
        *,
        evidence: list[FindingEvidence],
        config_hash: str,
        now: datetime | None = None,
    ) -> None:
        ts = now or datetime.now(UTC)
        self.last_seen_at = ts
        self.evidence = list(evidence)
        self.config_hash = config_hash
        self.updated_at = ts
        self.version += 1

    def _transition(
        self,
        to_status: FindingStatus,
        *,
        changed_by: str,
        reason: str,
        now: datetime | None = None,
    ) -> None:
        allowed = _ALLOWED_TRANSITIONS.get(self.status, frozenset())
        if to_status not in allowed:
            raise InvalidFindingTransitionError(str(self.id), self.status.value, to_status.value)
        ts = now or datetime.now(UTC)
        previous = self.status
        self.history.append(
            FindingHistory.record(
                from_status=previous,
                to_status=to_status,
                changed_at=ts,
                changed_by=changed_by,
                reason=reason,
            )
        )
        self.status = to_status
        self.updated_at = ts
        self.version += 1
        self._pending_events.append(
            CSPMFindingUpdated(
                finding_id=str(self.id),
                organization_id=str(self.organization_id),
                status=to_status.value,
                occurred_at=ts,
            )
        )

    def confirm(self, *, changed_by: str, reason: str = "", now: datetime | None = None) -> None:
        self._transition(FindingStatus.CONFIRMED, changed_by=changed_by, reason=reason, now=now)

    def suppress(
        self,
        *,
        changed_by: str,
        reason: str,
        until: datetime | None = None,
        now: datetime | None = None,
    ) -> None:
        self._transition(FindingStatus.SUPPRESSED, changed_by=changed_by, reason=reason, now=now)
        self.suppressed_until = until

    def accept_risk(
        self, *, accepted_by: str, reason: str, now: datetime | None = None
    ) -> None:
        if not accepted_by.strip():
            raise InvalidCSPMArgumentError("accepted_by", "required")
        if not reason.strip():
            raise InvalidCSPMArgumentError("accepted_reason", "required")
        self._transition(
            FindingStatus.ACCEPTED_RISK, changed_by=accepted_by, reason=reason, now=now
        )
        self.accepted_by = accepted_by.strip()
        self.accepted_reason = reason.strip()[:2000]

    def resolve(
        self, *, changed_by: str, reason: str = "resolved", now: datetime | None = None
    ) -> None:
        ts = now or datetime.now(UTC)
        self._transition(FindingStatus.RESOLVED, changed_by=changed_by, reason=reason, now=ts)
        self.resolved_at = ts
        self._pending_events.append(
            CSPMFindingResolved(
                finding_id=str(self.id),
                organization_id=str(self.organization_id),
                occurred_at=ts,
            )
        )

    def reopen(
        self, *, changed_by: str, reason: str = "reopened", now: datetime | None = None
    ) -> None:
        ts = now or datetime.now(UTC)
        self._transition(FindingStatus.REOPENED, changed_by=changed_by, reason=reason, now=ts)
        self.reopened_at = ts
        self.resolved_at = None
        self._pending_events.append(
            CSPMFindingReopened(
                finding_id=str(self.id),
                organization_id=str(self.organization_id),
                occurred_at=ts,
            )
        )

    def expire(self, *, changed_by: str = "system", now: datetime | None = None) -> None:
        self._transition(FindingStatus.EXPIRED, changed_by=changed_by, reason="expired", now=now)

    def pop_events(self) -> list[CSPMDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events
