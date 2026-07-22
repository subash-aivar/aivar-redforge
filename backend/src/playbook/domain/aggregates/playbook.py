"""Playbook aggregate root."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from playbook.domain.events.playbook_events import (
    PlaybookApproved,
    PlaybookCreated,
    PlaybookDeprecated,
)
from playbook.domain.exceptions.domain_exceptions import (
    DomainInvariantViolation,
    InvalidPlaybookTransition,
    TenantMismatch,
)
from playbook.domain.value_objects.definitions import ApprovalRecord
from playbook.domain.value_objects.enums import ActionImpactLevel, PlaybookStatus
from playbook.domain.value_objects.identifiers import PlaybookId, TenantId


class Playbook:
    __slots__ = (
        "_pending_events",
        "approved_by",
        "created_at",
        "created_by",
        "current_version_number",
        "description",
        "max_impact_level",
        "name",
        "playbook_id",
        "status",
        "tenant_id",
        "version",
    )

    def __init__(
        self,
        playbook_id: PlaybookId,
        tenant_id: TenantId,
        name: str,
        description: str,
        status: PlaybookStatus,
        current_version_number: int,
        max_impact_level: ActionImpactLevel,
        created_by: str,
        created_at: datetime,
        *,
        approved_by: list[ApprovalRecord] | None = None,
        version: int = 1,
    ) -> None:
        self.playbook_id = playbook_id
        self.tenant_id = tenant_id
        self.name = name
        self.description = description
        self.status = status
        self.current_version_number = current_version_number
        self.max_impact_level = max_impact_level
        self.created_by = created_by
        self.created_at = created_at
        self.approved_by = list(approved_by or [])
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
        name: str,
        description: str,
        created_by: str,
        *,
        at: datetime | None = None,
    ) -> Playbook:
        now = at or datetime.now(UTC)
        pb = cls(
            PlaybookId.generate(),
            tenant_id,
            name,
            description,
            PlaybookStatus.DRAFT,
            0,
            ActionImpactLevel.LOW,
            created_by,
            now,
        )
        pb._emit(
            PlaybookCreated(
                tenant_id=str(tenant_id),
                aggregate_id=str(pb.playbook_id),
                playbook_id=str(pb.playbook_id),
                name=name,
                created_by=created_by,
                created_at=now.isoformat(),
            )
        )
        return pb

    def set_max_impact(self, level: ActionImpactLevel) -> None:
        self.max_impact_level = level
        self.version += 1

    def set_current_version(self, version_number: int) -> None:
        self.current_version_number = version_number
        self.version += 1

    def submit_for_approval(self, tenant_id: TenantId) -> None:
        self._assert_tenant(tenant_id)
        if self.status not in {PlaybookStatus.DRAFT, PlaybookStatus.UNDER_REVIEW}:
            raise InvalidPlaybookTransition(f"cannot submit from {self.status.value}")
        if self.current_version_number < 1:
            raise DomainInvariantViolation("published version required before review")
        self.status = PlaybookStatus.UNDER_REVIEW
        self.version += 1

    def record_approval(
        self,
        tenant_id: TenantId,
        approver_id: str,
        role: str,
        *,
        quorum_required: int,
        at: datetime | None = None,
    ) -> None:
        self._assert_tenant(tenant_id)
        if self.status != PlaybookStatus.UNDER_REVIEW:
            raise InvalidPlaybookTransition("playbook must be UNDER_REVIEW")
        now = at or datetime.now(UTC)
        if any(a.approved_by == approver_id for a in self.approved_by):
            raise DomainInvariantViolation("duplicate approver")
        self.approved_by.append(ApprovalRecord(approver_id, now, role))
        if len(self.approved_by) >= quorum_required:
            self.status = PlaybookStatus.APPROVED
            self._emit(
                PlaybookApproved(
                    tenant_id=str(self.tenant_id),
                    aggregate_id=str(self.playbook_id),
                    playbook_id=str(self.playbook_id),
                    version_number=self.current_version_number,
                    max_impact_level=self.max_impact_level.value,
                    approved_by=[a.approved_by for a in self.approved_by],
                    approved_at=now.isoformat(),
                )
            )
        self.version += 1

    def deprecate(self, tenant_id: TenantId, deprecated_by: str, reason: str) -> None:
        self._assert_tenant(tenant_id)
        if self.status == PlaybookStatus.DEPRECATED:
            raise InvalidPlaybookTransition("already deprecated")
        now = datetime.now(UTC)
        self.status = PlaybookStatus.DEPRECATED
        self.version += 1
        self._emit(
            PlaybookDeprecated(
                tenant_id=str(self.tenant_id),
                aggregate_id=str(self.playbook_id),
                playbook_id=str(self.playbook_id),
                deprecated_by=deprecated_by,
                deprecated_at=now.isoformat(),
                reason=reason,
            )
        )
