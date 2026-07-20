"""Entities for CSPM findings, evaluations, and remediation."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID, uuid4

from redforge.domain.cloud_security.cspm.value_objects import FindingStatus


@dataclass(frozen=True, slots=True)
class FindingEvidence:
    evidence_id: str
    path: str
    expected: str
    actual: str
    message: str

    def __post_init__(self) -> None:
        if not self.evidence_id or len(self.evidence_id) > 64:
            raise ValueError("FindingEvidence.evidence_id invalid")
        if len(self.path) > 512 or len(self.message) > 2000:
            raise ValueError("FindingEvidence field length exceeded")

    @classmethod
    def create(
        cls, *, path: str, expected: str, actual: str, message: str
    ) -> FindingEvidence:
        return cls(
            evidence_id=str(uuid4()),
            path=path[:512],
            expected=expected[:1024],
            actual=actual[:1024],
            message=message[:2000],
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "evidence_id": self.evidence_id,
            "path": self.path,
            "expected": self.expected,
            "actual": self.actual,
            "message": self.message,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> FindingEvidence:
        return cls(
            evidence_id=str(data["evidence_id"]),
            path=str(data["path"]),
            expected=str(data["expected"]),
            actual=str(data["actual"]),
            message=str(data["message"]),
        )


@dataclass(frozen=True, slots=True)
class FindingHistory:
    history_id: str
    from_status: FindingStatus | None
    to_status: FindingStatus
    changed_at: datetime
    changed_by: str
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {
            "history_id": self.history_id,
            "from_status": self.from_status.value if self.from_status else None,
            "to_status": self.to_status.value,
            "changed_at": self.changed_at.isoformat(),
            "changed_by": self.changed_by,
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> FindingHistory:
        from_raw = data.get("from_status")
        return cls(
            history_id=str(data["history_id"]),
            from_status=FindingStatus(str(from_raw)) if from_raw else None,
            to_status=FindingStatus(str(data["to_status"])),
            changed_at=datetime.fromisoformat(str(data["changed_at"])),
            changed_by=str(data["changed_by"]),
            reason=str(data.get("reason", "")),
        )

    @classmethod
    def record(
        cls,
        *,
        from_status: FindingStatus | None,
        to_status: FindingStatus,
        changed_at: datetime,
        changed_by: str,
        reason: str,
    ) -> FindingHistory:
        return cls(
            history_id=str(uuid4()),
            from_status=from_status,
            to_status=to_status,
            changed_at=changed_at,
            changed_by=changed_by,
            reason=reason[:2000],
        )


@dataclass(frozen=True, slots=True)
class RemediationReference:
    description: str
    business_impact: str = ""
    technical_impact: str = ""
    manual_steps: tuple[str, ...] = ()
    automated_metadata: dict[str, str] | None = None
    reference_urls: tuple[str, ...] = ()
    terraform_guidance: str = ""
    cloudformation_guidance: str = ""
    arm_guidance: str = ""
    gcp_deployment_guidance: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "description": self.description,
            "business_impact": self.business_impact,
            "technical_impact": self.technical_impact,
            "manual_steps": list(self.manual_steps),
            "automated_metadata": dict(self.automated_metadata or {}),
            "reference_urls": list(self.reference_urls),
            "terraform_guidance": self.terraform_guidance,
            "cloudformation_guidance": self.cloudformation_guidance,
            "arm_guidance": self.arm_guidance,
            "gcp_deployment_guidance": self.gcp_deployment_guidance,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object] | None) -> RemediationReference:
        if not data:
            return cls(description="")

        def _str_tuple(key: str) -> tuple[str, ...]:
            raw = data.get(key) or []
            if not isinstance(raw, (list, tuple)):
                return ()
            return tuple(str(x) for x in raw)

        auto = data.get("automated_metadata") or {}
        automated: dict[str, str] = {}
        if isinstance(auto, dict):
            automated = {str(k): str(v) for k, v in auto.items()}

        return cls(
            description=str(data.get("description", "")),
            business_impact=str(data.get("business_impact", "")),
            technical_impact=str(data.get("technical_impact", "")),
            manual_steps=_str_tuple("manual_steps"),
            automated_metadata=automated,
            reference_urls=_str_tuple("reference_urls"),
            terraform_guidance=str(data.get("terraform_guidance", "")),
            cloudformation_guidance=str(data.get("cloudformation_guidance", "")),
            arm_guidance=str(data.get("arm_guidance", "")),
            gcp_deployment_guidance=str(data.get("gcp_deployment_guidance", "")),
        )


@dataclass(frozen=True, slots=True)
class EvaluationResult:
    policy_id: str
    rule_id: str
    cloud_asset_id: str
    passed: bool
    severity: str
    title: str
    message: str
    evidence: tuple[FindingEvidence, ...] = ()
    duration_ms: int = 0

    def to_dict(self) -> dict[str, object]:
        return {
            "policy_id": self.policy_id,
            "rule_id": self.rule_id,
            "cloud_asset_id": self.cloud_asset_id,
            "passed": self.passed,
            "severity": self.severity,
            "title": self.title,
            "message": self.message,
            "evidence": [e.to_dict() for e in self.evidence],
            "duration_ms": self.duration_ms,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> EvaluationResult:
        evidence_raw = data.get("evidence") or []
        evidence: list[FindingEvidence] = []
        if isinstance(evidence_raw, list):
            for item in evidence_raw:
                if isinstance(item, dict):
                    evidence.append(FindingEvidence.from_dict(item))
        return cls(
            policy_id=str(data["policy_id"]),
            rule_id=str(data["rule_id"]),
            cloud_asset_id=str(data["cloud_asset_id"]),
            passed=bool(data["passed"]),
            severity=str(data["severity"]),
            title=str(data["title"]),
            message=str(data["message"]),
            evidence=tuple(evidence),
            duration_ms=_as_int(data.get("duration_ms"), default=0),
        )


def _as_int(value: object, *, default: int = 0) -> int:
    if value is None:
        return default
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str) and value.strip():
        return int(value)
    return default


@dataclass
class CSPMDriftBaseline:
    """Configuration drift baseline for a cloud asset (foundation only)."""

    id: UUID
    organization_id: str
    cloud_asset_id: UUID
    drift_kind: str
    baseline_hash: str
    baseline_snapshot: dict[str, object]
    captured_at: datetime
    updated_at: datetime

    @classmethod
    def create(
        cls,
        *,
        organization_id: str,
        cloud_asset_id: UUID,
        drift_kind: str,
        baseline_hash: str,
        baseline_snapshot: dict[str, object],
        now: datetime | None = None,
        baseline_id: UUID | None = None,
    ) -> CSPMDriftBaseline:
        from datetime import UTC

        ts = now or datetime.now(UTC)
        return cls(
            id=baseline_id or uuid4(),
            organization_id=organization_id,
            cloud_asset_id=cloud_asset_id,
            drift_kind=drift_kind,
            baseline_hash=baseline_hash,
            baseline_snapshot=dict(baseline_snapshot),
            captured_at=ts,
            updated_at=ts,
        )

    def update_baseline(
        self,
        *,
        baseline_hash: str,
        baseline_snapshot: dict[str, object],
        now: datetime | None = None,
    ) -> None:
        from datetime import UTC

        ts = now or datetime.now(UTC)
        self.baseline_hash = baseline_hash
        self.baseline_snapshot = dict(baseline_snapshot)
        self.updated_at = ts
