"""IntelligenceSuggestion aggregate — human-in-the-loop lifecycle."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from autonomous_intelligence.domain.events.intelligence_events import (
    SuggestionApplied,
    SuggestionApproved,
    SuggestionCreated,
    SuggestionExpired,
    SuggestionProposedForApplication,
    SuggestionRejected,
    SuggestionWithdrawn,
)
from autonomous_intelligence.domain.exceptions.domain_exceptions import (
    AuthorizationDenied,
    InvalidSuggestionTransition,
    TenantMismatch,
)
from autonomous_intelligence.domain.value_objects.enums import (
    SuggestionPriority,
    SuggestionStatus,
    SuggestionTargetType,
)
from autonomous_intelligence.domain.value_objects.evidence import (
    REVIEW_ROLES,
    SuggestionEvidence,
    SuggestionTargetRef,
)
from autonomous_intelligence.domain.value_objects.identifiers import SuggestionId, TenantId


class IntelligenceSuggestion:
    __slots__ = (
        "_pending_events",
        "approved_by",
        "created_at",
        "evidence",
        "priority",
        "rejected_by",
        "rejection_reason",
        "review_deadline_at",
        "reviewed_at",
        "status",
        "suggestion_id",
        "target_ref",
        "tenant_id",
        "version",
    )

    def __init__(
        self,
        suggestion_id: SuggestionId,
        tenant_id: TenantId,
        target_ref: SuggestionTargetRef,
        evidence: SuggestionEvidence,
        status: SuggestionStatus,
        created_at: datetime,
        review_deadline_at: datetime,
        *,
        priority: SuggestionPriority = SuggestionPriority.MEDIUM,
        approved_by: str | None = None,
        rejected_by: str | None = None,
        rejection_reason: str | None = None,
        reviewed_at: datetime | None = None,
        version: int = 1,
    ) -> None:
        self.suggestion_id = suggestion_id
        self.tenant_id = tenant_id
        self.target_ref = target_ref
        self.evidence = evidence
        self.status = status
        self.created_at = created_at
        self.review_deadline_at = review_deadline_at
        self.priority = priority
        self.approved_by = approved_by
        self.rejected_by = rejected_by
        self.rejection_reason = rejection_reason
        self.reviewed_at = reviewed_at
        self.version = version
        self._pending_events: list[Any] = []

    def pop_events(self) -> list[Any]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: Any) -> None:
        self._pending_events.append(event)

    def _assert_tenant(self, tenant_id: TenantId) -> None:
        if self.tenant_id.value != tenant_id.value:
            raise TenantMismatch("tenant mismatch")

    @classmethod
    def create(
        cls,
        tenant_id: TenantId,
        target_ref: SuggestionTargetRef,
        evidence: SuggestionEvidence,
        *,
        review_ttl_hours: int = 72,
        priority: SuggestionPriority = SuggestionPriority.MEDIUM,
    ) -> IntelligenceSuggestion:
        now = datetime.now(UTC)
        suggestion = cls(
            SuggestionId.generate(),
            tenant_id,
            target_ref,
            evidence,
            SuggestionStatus.PENDING_REVIEW,
            now,
            now + timedelta(hours=review_ttl_hours),
            priority=priority,
        )
        suggestion._emit(
            SuggestionCreated(
                tenant_id=str(tenant_id),
                aggregate_id=str(suggestion.suggestion_id),
                suggestion_id=str(suggestion.suggestion_id),
                target_type=target_ref.target_type.value,
                confidence_score=evidence.confidence_score,
                model_id=evidence.model_id,
            )
        )
        return suggestion

    def approve(self, tenant_id: TenantId, approved_by: str, roles: tuple[str, ...]) -> None:
        self._assert_tenant(tenant_id)
        if self.status != SuggestionStatus.PENDING_REVIEW:
            raise InvalidSuggestionTransition(f"cannot approve from {self.status.value}")
        required = REVIEW_ROLES[self.target_ref.target_type]
        if required not in roles:
            raise AuthorizationDenied(f"requires role {required}")
        now = datetime.now(UTC)
        self.status = SuggestionStatus.APPROVED
        self.approved_by = approved_by
        self.reviewed_at = now
        self.version += 1
        self._emit(
            SuggestionApproved(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.suggestion_id),
                suggestion_id=str(self.suggestion_id),
                approved_by=approved_by,
                target_type=self.target_ref.target_type.value,
            )
        )
        self._emit(
            SuggestionProposedForApplication(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.suggestion_id),
                suggestion_id=str(self.suggestion_id),
                target_type=self.target_ref.target_type.value,
                target_context=self.target_ref.target_context,
                target_id=str(self.target_ref.target_id) if self.target_ref.target_id else None,
                proposal_payload=dict(self.target_ref.proposed_change_payload),
            )
        )

    def reject(
        self, tenant_id: TenantId, rejected_by: str, reason: str, roles: tuple[str, ...]
    ) -> None:
        self._assert_tenant(tenant_id)
        if self.status != SuggestionStatus.PENDING_REVIEW:
            raise InvalidSuggestionTransition(f"cannot reject from {self.status.value}")
        required = REVIEW_ROLES[self.target_ref.target_type]
        if required not in roles:
            raise AuthorizationDenied(f"requires role {required}")
        now = datetime.now(UTC)
        self.status = SuggestionStatus.REJECTED
        self.rejected_by = rejected_by
        self.rejection_reason = reason
        self.reviewed_at = now
        self.version += 1
        self._emit(
            SuggestionRejected(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.suggestion_id),
                suggestion_id=str(self.suggestion_id),
                rejected_by=rejected_by,
                rejection_reason=reason,
            )
        )

    def mark_applied(self, tenant_id: TenantId, target_context_ref: str) -> None:
        self._assert_tenant(tenant_id)
        if self.status != SuggestionStatus.APPROVED:
            raise InvalidSuggestionTransition(f"cannot apply from {self.status.value}")
        now = datetime.now(UTC)
        self.status = SuggestionStatus.APPLIED
        self.version += 1
        self._emit(
            SuggestionApplied(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.suggestion_id),
                suggestion_id=str(self.suggestion_id),
                applied_at=now.isoformat(),
                target_context_ref=target_context_ref,
            )
        )

    def expire(self, tenant_id: TenantId) -> None:
        self._assert_tenant(tenant_id)
        if self.status != SuggestionStatus.PENDING_REVIEW:
            raise InvalidSuggestionTransition(f"cannot expire from {self.status.value}")
        now = datetime.now(UTC)
        self.status = SuggestionStatus.EXPIRED
        self.version += 1
        self._emit(
            SuggestionExpired(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.suggestion_id),
                suggestion_id=str(self.suggestion_id),
                expired_at=now.isoformat(),
            )
        )

    def withdraw(self, tenant_id: TenantId, reason: str) -> None:
        self._assert_tenant(tenant_id)
        if self.status not in {SuggestionStatus.PENDING_REVIEW, SuggestionStatus.APPROVED}:
            raise InvalidSuggestionTransition(f"cannot withdraw from {self.status.value}")
        now = datetime.now(UTC)
        self.status = SuggestionStatus.WITHDRAWN
        self.version += 1
        self._emit(
            SuggestionWithdrawn(
                tenant_id=str(tenant_id),
                aggregate_id=str(self.suggestion_id),
                suggestion_id=str(self.suggestion_id),
                withdrawn_at=now.isoformat(),
                reason=reason,
            )
        )

    @property
    def target_type(self) -> SuggestionTargetType:
        return self.target_ref.target_type
