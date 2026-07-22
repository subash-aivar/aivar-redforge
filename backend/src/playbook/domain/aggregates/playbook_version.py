"""PlaybookVersion aggregate — immutable once published."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from playbook.domain.events.playbook_events import PlaybookVersionPublished
from playbook.domain.exceptions.domain_exceptions import VersionImmutableError
from playbook.domain.services.playbook_content_hash_service import PlaybookContentHashService
from playbook.domain.value_objects.definitions import ActionStepDefinition, TriggerCondition
from playbook.domain.value_objects.enums import VersionStatus
from playbook.domain.value_objects.identifiers import PlaybookId, PlaybookVersionId, TenantId


class PlaybookVersion:
    __slots__ = (
        "_pending_events",
        "action_steps",
        "content_hash",
        "playbook_id",
        "published_at",
        "published_by",
        "status",
        "tenant_id",
        "trigger_configs",
        "version_id",
        "version_number",
    )

    def __init__(
        self,
        version_id: PlaybookVersionId,
        tenant_id: TenantId,
        playbook_id: PlaybookId,
        version_number: int,
        status: VersionStatus,
        action_steps: list[ActionStepDefinition],
        trigger_configs: list[TriggerCondition],
        *,
        content_hash: str = "",
        published_by: str | None = None,
        published_at: datetime | None = None,
    ) -> None:
        self.version_id = version_id
        self.tenant_id = tenant_id
        self.playbook_id = playbook_id
        self.version_number = version_number
        self.status = status
        self.content_hash = content_hash
        self.action_steps = list(action_steps)
        self.trigger_configs = list(trigger_configs)
        self.published_by = published_by
        self.published_at = published_at
        self._pending_events: list[Any] = []

    def pop_events(self) -> list[Any]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    @classmethod
    def create_draft(
        cls,
        tenant_id: TenantId,
        playbook_id: PlaybookId,
        version_number: int,
        action_steps: list[ActionStepDefinition],
        trigger_configs: list[TriggerCondition],
    ) -> PlaybookVersion:
        return cls(
            PlaybookVersionId.generate(),
            tenant_id,
            playbook_id,
            version_number,
            VersionStatus.DRAFT,
            action_steps,
            trigger_configs,
        )

    def publish(self, published_by: str, *, at: datetime | None = None) -> None:
        if self.status == VersionStatus.PUBLISHED:
            raise VersionImmutableError("version already published")
        now = at or datetime.now(UTC)
        hasher = PlaybookContentHashService()
        self.content_hash = hasher.compute(self)
        self.status = VersionStatus.PUBLISHED
        self.published_by = published_by
        self.published_at = now
        self._pending_events.append(
            PlaybookVersionPublished(
                tenant_id=str(self.tenant_id),
                aggregate_id=str(self.version_id),
                playbook_id=str(self.playbook_id),
                version_id=str(self.version_id),
                version_number=self.version_number,
                content_hash=self.content_hash,
                published_by=published_by,
                published_at=now.isoformat(),
            )
        )
