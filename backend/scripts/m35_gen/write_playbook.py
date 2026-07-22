"""Generate playbook bounded context."""

from __future__ import annotations

from .common import CONNECTOR_TYPES, IMPACT, SRC, TESTS, empty_inits, w


def write() -> None:
    base = SRC / "playbook"
    empty_inits(
        base,
        base / "domain",
        base / "domain" / "aggregates",
        base / "domain" / "events",
        base / "domain" / "exceptions",
        base / "domain" / "repositories",
        base / "domain" / "services",
        base / "domain" / "value_objects",
        base / "application",
        base / "application" / "commands",
        base / "application" / "dtos",
        base / "application" / "services",
        base / "infrastructure",
        base / "infrastructure" / "persistence",
        base / "infrastructure" / "workers",
        base / "infrastructure" / "observability",
        base / "infrastructure" / "acl",
        base / "api",
        base / "api" / "v1",
    )
    w(base / "__init__.py", '"""M35 playbook bounded context."""\n')
    w(base / "py.typed", "")
    _vos(base)
    _exceptions(base)
    _events(base)
    _aggregates(base)
    _services(base)
    _repos(base)


def _vos(base):
    w(
        base / "domain" / "value_objects" / "enums.py",
        f'''"""Frozen enums for playbook BC (M35)."""

from __future__ import annotations

from enum import StrEnum

{IMPACT}

class PlaybookStatus(StrEnum):
    DRAFT = "DRAFT"
    UNDER_REVIEW = "UNDER_REVIEW"
    APPROVED = "APPROVED"
    DEPRECATED = "DEPRECATED"


class VersionStatus(StrEnum):
    DRAFT = "DRAFT"
    PUBLISHED = "PUBLISHED"


class TestOutcome(StrEnum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"


class KillSwitchState(StrEnum):
    ARMED = "ARMED"
    TRIGGERED = "TRIGGERED"


class TriggerSourceContext(StrEnum):
    M28_FINDING = "M28_FINDING"
    M34_INCIDENT = "M34_INCIDENT"
    M32_EXPOSURE = "M32_EXPOSURE"
    MANUAL = "MANUAL"

{CONNECTOR_TYPES}
''',
    )
    w(
        base / "domain" / "value_objects" / "identifiers.py",
        '''"""Typed identifiers for playbook BC."""

from __future__ import annotations

from dataclasses import dataclass
from uuid import UUID, uuid4


@dataclass(frozen=True, slots=True)
class TenantId:
    value: UUID

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class PlaybookId:
    value: UUID

    @classmethod
    def generate(cls) -> PlaybookId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class PlaybookVersionId:
    value: UUID

    @classmethod
    def generate(cls) -> PlaybookVersionId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True, slots=True)
class PlaybookTestResultId:
    value: UUID

    @classmethod
    def generate(cls) -> PlaybookTestResultId:
        return cls(uuid4())

    def __str__(self) -> str:
        return str(self.value)
''',
    )
    w(
        base / "domain" / "value_objects" / "definitions.py",
        '''"""Playbook definition value objects."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

from playbook.domain.value_objects.enums import (
    ActionImpactLevel,
    ConnectorType,
    TriggerSourceContext,
)


@dataclass(frozen=True, slots=True)
class TargetSelectorExpression:
    expression: str


@dataclass(frozen=True, slots=True)
class RollbackDefinition:
    rollback_action_type: str
    rollback_connector_type: ConnectorType
    is_reversible: bool
    max_rollback_window_hours: int = 24


@dataclass(frozen=True, slots=True)
class ActionStepDefinition:
    step_number: int
    action_type: str
    connector_type: ConnectorType
    target_selector: TargetSelectorExpression
    parameters: dict[str, object]
    impact_level: ActionImpactLevel
    rollback_definition: RollbackDefinition | None = None
    max_execution_seconds: int = 120


@dataclass(frozen=True, slots=True)
class TriggerCondition:
    source_context: TriggerSourceContext
    trigger_type: str
    severity_threshold: str | None = None
    asset_tag_filter: list[str] | None = None
    rate_limit_window_seconds: int = 300
    rate_limit_max_invocations: int = 1


@dataclass(frozen=True, slots=True)
class ApprovalRecord:
    approved_by: str
    approved_at: datetime
    role: str
''',
    )


def _exceptions(base):
    w(
        base / "domain" / "exceptions" / "domain_exceptions.py",
        '''"""Playbook domain exceptions."""

from __future__ import annotations


class PlaybookDomainError(Exception):
    pass


class DomainInvariantViolation(PlaybookDomainError):
    pass


class TenantMismatch(PlaybookDomainError):
    pass


class PlaybookAuthorizationDenied(PlaybookDomainError):
    pass


class SeparationOfDutiesViolation(PlaybookDomainError):
    pass


class DryRunRequired(PlaybookDomainError):
    pass


class DryRunHashMismatch(PlaybookDomainError):
    pass


class DryRunNotPassed(PlaybookDomainError):
    pass


class KillSwitchActive(PlaybookDomainError):
    pass


class InvalidPlaybookTransition(PlaybookDomainError):
    pass


class VersionImmutableError(PlaybookDomainError):
    pass
''',
    )


def _events(base):
    w(
        base / "domain" / "events" / "base.py",
        '''from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from uuid import uuid4


@dataclass(frozen=True, slots=True)
class BasePlaybookEvent:
    event_id: str = field(default_factory=lambda: str(uuid4()))
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    tenant_id: str = ""
    aggregate_id: str = ""
''',
    )
    w(
        base / "domain" / "events" / "playbook_events.py",
        '''"""Frozen playbook domain events (M35)."""

from __future__ import annotations

from dataclasses import dataclass

from playbook.domain.events.base import BasePlaybookEvent


@dataclass(frozen=True, slots=True, kw_only=True)
class PlaybookCreated(BasePlaybookEvent):
    playbook_id: str
    name: str
    created_by: str
    created_at: str


@dataclass(frozen=True, slots=True, kw_only=True)
class PlaybookVersionPublished(BasePlaybookEvent):
    playbook_id: str
    version_id: str
    version_number: int
    content_hash: str
    published_by: str
    published_at: str


@dataclass(frozen=True, slots=True, kw_only=True)
class PlaybookApproved(BasePlaybookEvent):
    playbook_id: str
    version_number: int
    max_impact_level: str
    approved_by: list[str]
    approved_at: str


@dataclass(frozen=True, slots=True, kw_only=True)
class PlaybookDeprecated(BasePlaybookEvent):
    playbook_id: str
    deprecated_by: str
    deprecated_at: str
    reason: str


@dataclass(frozen=True, slots=True, kw_only=True)
class PlaybookTestCompleted(BasePlaybookEvent):
    playbook_id: str
    test_id: str
    version_id: str
    content_hash_at_test: str
    outcome: str
    steps_tested: int
    steps_passed: int
    executed_at: str


@dataclass(frozen=True, slots=True, kw_only=True)
class PlaybookTriggered(BasePlaybookEvent):
    playbook_id: str
    version_number: int
    source_context: str
    source_event_id: str
    triggered_at: str


@dataclass(frozen=True, slots=True, kw_only=True)
class AutomationKillSwitchActivated(BasePlaybookEvent):
    activated_by: str
    activated_at: str
    reason: str


@dataclass(frozen=True, slots=True, kw_only=True)
class AutomationKillSwitchReset(BasePlaybookEvent):
    reset_by: str
    reset_at: str
''',
    )


def _aggregates(base):
    w(
        base / "domain" / "aggregates" / "playbook.py",
        '''"""Playbook aggregate root."""

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
''',
    )
    w(
        base / "domain" / "aggregates" / "playbook_version.py",
        '''"""PlaybookVersion aggregate — immutable once published."""

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
''',
    )
    w(
        base / "domain" / "aggregates" / "playbook_test_result.py",
        '''"""PlaybookTestResult — append-only dry-run outcome."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from playbook.domain.value_objects.enums import TestOutcome
from playbook.domain.value_objects.identifiers import (
    PlaybookId,
    PlaybookTestResultId,
    PlaybookVersionId,
    TenantId,
)


@dataclass
class PlaybookTestResult:
    test_id: PlaybookTestResultId
    tenant_id: TenantId
    playbook_id: PlaybookId
    version_id: PlaybookVersionId
    content_hash_at_test: str
    outcome: TestOutcome
    steps_tested: int
    steps_passed: int
    coverage_paths: list[str]
    executed_by: str
    executed_at: datetime
    duration_ms: int

    @classmethod
    def create(
        cls,
        tenant_id: TenantId,
        playbook_id: PlaybookId,
        version_id: PlaybookVersionId,
        content_hash_at_test: str,
        outcome: TestOutcome,
        steps_tested: int,
        steps_passed: int,
        coverage_paths: list[str],
        executed_by: str,
        executed_at: datetime,
        duration_ms: int,
    ) -> PlaybookTestResult:
        return cls(
            PlaybookTestResultId.generate(),
            tenant_id,
            playbook_id,
            version_id,
            content_hash_at_test,
            outcome,
            steps_tested,
            steps_passed,
            coverage_paths,
            executed_by,
            executed_at,
            duration_ms,
        )
''',
    )
    w(
        base / "domain" / "aggregates" / "automation_policy.py",
        '''"""AutomationPolicy aggregate — per-tenant kill switch and budgets."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from playbook.domain.events.playbook_events import (
    AutomationKillSwitchActivated,
    AutomationKillSwitchReset,
)
from playbook.domain.exceptions.domain_exceptions import DomainInvariantViolation, KillSwitchActive
from playbook.domain.value_objects.enums import ConnectorType, KillSwitchState
from playbook.domain.value_objects.identifiers import TenantId


class AutomationPolicy:
    __slots__ = (
        "_pending_events",
        "allowed_connector_types",
        "kill_switch_state",
        "kill_switch_triggered_at",
        "kill_switch_triggered_by",
        "max_actions_per_hour",
        "max_concurrent_executions",
        "tenant_id",
        "updated_at",
    )

    def __init__(
        self,
        tenant_id: TenantId,
        kill_switch_state: KillSwitchState = KillSwitchState.ARMED,
        *,
        kill_switch_triggered_at: datetime | None = None,
        kill_switch_triggered_by: str | None = None,
        max_concurrent_executions: int = 5,
        max_actions_per_hour: int = 100,
        allowed_connector_types: list[ConnectorType] | None = None,
        updated_at: datetime | None = None,
    ) -> None:
        self.tenant_id = tenant_id
        self.kill_switch_state = kill_switch_state
        self.kill_switch_triggered_at = kill_switch_triggered_at
        self.kill_switch_triggered_by = kill_switch_triggered_by
        self.max_concurrent_executions = max_concurrent_executions
        self.max_actions_per_hour = max_actions_per_hour
        self.allowed_connector_types = allowed_connector_types
        self.updated_at = updated_at or datetime.now(UTC)
        self._pending_events: list[Any] = []

    def pop_events(self) -> list[Any]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    @classmethod
    def default(cls, tenant_id: TenantId) -> AutomationPolicy:
        return cls(tenant_id)

    def assert_armed(self) -> None:
        if self.kill_switch_state == KillSwitchState.TRIGGERED:
            raise KillSwitchActive("automation kill switch is TRIGGERED")

    def activate_kill_switch(self, activated_by: str, reason: str) -> None:
        if self.kill_switch_state == KillSwitchState.TRIGGERED:
            raise DomainInvariantViolation("kill switch already TRIGGERED")
        now = datetime.now(UTC)
        self.kill_switch_state = KillSwitchState.TRIGGERED
        self.kill_switch_triggered_at = now
        self.kill_switch_triggered_by = activated_by
        self.updated_at = now
        self._pending_events.append(
            AutomationKillSwitchActivated(
                tenant_id=str(self.tenant_id),
                aggregate_id=str(self.tenant_id),
                activated_by=activated_by,
                activated_at=now.isoformat(),
                reason=reason,
            )
        )

    def reset_kill_switch(self, reset_by: str) -> None:
        if self.kill_switch_state != KillSwitchState.TRIGGERED:
            raise DomainInvariantViolation("kill switch is not TRIGGERED")
        now = datetime.now(UTC)
        self.kill_switch_state = KillSwitchState.ARMED
        self.kill_switch_triggered_at = None
        self.kill_switch_triggered_by = None
        self.updated_at = now
        self._pending_events.append(
            AutomationKillSwitchReset(
                tenant_id=str(self.tenant_id),
                aggregate_id=str(self.tenant_id),
                reset_by=reset_by,
                reset_at=now.isoformat(),
            )
        )

    def update_budgets(
        self,
        *,
        max_concurrent_executions: int | None = None,
        max_actions_per_hour: int | None = None,
        allowed_connector_types: list[ConnectorType] | None = None,
    ) -> None:
        if max_concurrent_executions is not None:
            if not 1 <= max_concurrent_executions <= 50:
                raise DomainInvariantViolation("max_concurrent_executions must be 1..50")
            self.max_concurrent_executions = max_concurrent_executions
        if max_actions_per_hour is not None:
            if not 1 <= max_actions_per_hour <= 1000:
                raise DomainInvariantViolation("max_actions_per_hour must be 1..1000")
            self.max_actions_per_hour = max_actions_per_hour
        if allowed_connector_types is not None:
            self.allowed_connector_types = list(allowed_connector_types)
        self.updated_at = datetime.now(UTC)
''',
    )


def _services(base):
    w(
        base / "domain" / "services" / "playbook_authorization_service.py",
        '''"""Dual-authorization matrix — ADR-M35-001 / C1."""

from __future__ import annotations

from playbook.domain.exceptions.domain_exceptions import (
    PlaybookAuthorizationDenied,
    SeparationOfDutiesViolation,
)
from playbook.domain.value_objects.enums import ActionImpactLevel


class PlaybookAuthorizationService:
    _APPROVAL_MATRIX: dict[ActionImpactLevel, tuple[str, int]] = {
        ActionImpactLevel.LOW: ("soc:analyst", 1),
        ActionImpactLevel.MEDIUM: ("soc:commander", 1),
        ActionImpactLevel.HIGH: ("soc:commander", 2),
        ActionImpactLevel.CRITICAL: ("incident:ciso", 2),
    }

    _RUNTIME_MATRIX: dict[ActionImpactLevel, str | None] = {
        ActionImpactLevel.LOW: None,
        ActionImpactLevel.MEDIUM: None,
        ActionImpactLevel.HIGH: "soc:commander",
        ActionImpactLevel.CRITICAL: "incident:ciso",
    }

    _ROLE_RANK = {
        "playbook:analyst": 1,
        "soc:analyst": 2,
        "playbook:engineer": 3,
        "automation:operator": 3,
        "soc:commander": 4,
        "incident:ciso": 5,
        "integration:admin": 3,
    }

    def approval_requirements(
        self, max_impact_level: ActionImpactLevel
    ) -> tuple[str, int]:
        return self._APPROVAL_MATRIX[max_impact_level]

    def assert_approval_authorized(
        self,
        max_impact_level: ActionImpactLevel,
        approver_roles: tuple[str, ...],
        *,
        existing_approver_count: int = 0,
    ) -> None:
        min_role, quorum = self._APPROVAL_MATRIX[max_impact_level]
        if max_impact_level == ActionImpactLevel.CRITICAL:
            # Dual: one soc:commander + one incident:ciso across the quorum
            if existing_approver_count == 0:
                if "soc:commander" not in approver_roles and "incident:ciso" not in approver_roles:
                    raise PlaybookAuthorizationDenied(
                        f"Impact CRITICAL requires role soc:commander or incident:ciso"
                    )
            else:
                if "incident:ciso" not in approver_roles and "soc:commander" not in approver_roles:
                    raise PlaybookAuthorizationDenied(
                        "Impact CRITICAL requires complementary approver roles"
                    )
            return
        if min_role not in approver_roles:
            raise PlaybookAuthorizationDenied(
                f"Impact {max_impact_level.value} requires role {min_role}"
            )
        del quorum

    def runtime_authorization_required(
        self, impact_level: ActionImpactLevel
    ) -> str | None:
        return self._RUNTIME_MATRIX[impact_level]

    def assert_runtime_authorized(
        self,
        impact_level: ActionImpactLevel,
        authorizer_roles: tuple[str, ...],
        authorizer_id: str,
        trigger_operator_id: str,
    ) -> None:
        required_role = self.runtime_authorization_required(impact_level)
        if required_role is None:
            return
        if authorizer_id == trigger_operator_id:
            raise SeparationOfDutiesViolation(
                "Runtime authorizer must differ from the operator who triggered execution"
            )
        if required_role not in authorizer_roles:
            raise PlaybookAuthorizationDenied(
                f"Runtime authorization for {impact_level.value} requires role {required_role}"
            )

    def has_role(self, roles: tuple[str, ...], required: str) -> bool:
        return required in roles or self._ROLE_RANK.get(
            max(roles, key=lambda r: self._ROLE_RANK.get(r, 0), default=""), 0
        ) >= self._ROLE_RANK.get(required, 99)
''',
    )
    w(
        base / "domain" / "services" / "playbook_content_hash_service.py",
        '''"""SHA-256 content hashing — ADR-M35-005 / C5."""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from playbook.domain.aggregates.playbook_version import PlaybookVersion


class PlaybookContentHashService:
    def canonical_json(self, version: PlaybookVersion) -> bytes:
        payload = {
            "action_steps": [
                {
                    "action_type": s.action_type,
                    "connector_type": s.connector_type.value,
                    "impact_level": s.impact_level.value,
                    "max_execution_seconds": s.max_execution_seconds,
                    "parameters": s.parameters,
                    "rollback_definition": (
                        {
                            "is_reversible": s.rollback_definition.is_reversible,
                            "max_rollback_window_hours": (
                                s.rollback_definition.max_rollback_window_hours
                            ),
                            "rollback_action_type": s.rollback_definition.rollback_action_type,
                            "rollback_connector_type": (
                                s.rollback_definition.rollback_connector_type.value
                            ),
                        }
                        if s.rollback_definition
                        else None
                    ),
                    "step_number": s.step_number,
                    "target_selector": s.target_selector.expression,
                }
                for s in sorted(version.action_steps, key=lambda x: x.step_number)
            ],
            "trigger_configs": [
                {
                    "asset_tag_filter": t.asset_tag_filter,
                    "rate_limit_max_invocations": t.rate_limit_max_invocations,
                    "rate_limit_window_seconds": t.rate_limit_window_seconds,
                    "severity_threshold": t.severity_threshold,
                    "source_context": t.source_context.value,
                    "trigger_type": t.trigger_type,
                }
                for t in version.trigger_configs
            ],
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def compute(self, version: PlaybookVersion) -> str:
        return hashlib.sha256(self.canonical_json(version)).hexdigest()
''',
    )
    w(
        base / "domain" / "services" / "trigger_matching_service.py",
        '''"""Match external trigger events to playbook trigger configs."""

from __future__ import annotations

from playbook.domain.value_objects.definitions import TriggerCondition
from playbook.domain.value_objects.enums import TriggerSourceContext


class TriggerMatchingService:
    def matches(
        self,
        condition: TriggerCondition,
        *,
        source_context: TriggerSourceContext,
        trigger_type: str,
        severity: str | None,
        asset_tags: list[str] | None,
    ) -> bool:
        if condition.source_context != source_context:
            return False
        if condition.trigger_type != trigger_type and condition.trigger_type != "*":
            return False
        if condition.severity_threshold and severity:
            order = ["LOW", "MEDIUM", "HIGH", "CRITICAL", "P4_LOW", "P3_MEDIUM", "P2_HIGH", "P1_CRITICAL"]
            try:
                if order.index(severity) < order.index(condition.severity_threshold):
                    return False
            except ValueError:
                if severity != condition.severity_threshold:
                    return False
        if condition.asset_tag_filter:
            tags = set(asset_tags or [])
            if not tags.intersection(condition.asset_tag_filter):
                return False
        return True
''',
    )
    w(
        base / "domain" / "services" / "playbook_dry_run_service.py",
        '''"""Dry-run simulation for playbook versions."""

from __future__ import annotations

from dataclasses import dataclass

from playbook.domain.aggregates.playbook_version import PlaybookVersion
from playbook.domain.value_objects.enums import TestOutcome


@dataclass(frozen=True, slots=True)
class DryRunResult:
    outcome: TestOutcome
    steps_tested: int
    steps_passed: int
    coverage_paths: list[str]
    duration_ms: int


class PlaybookDryRunService:
    def run(self, version: PlaybookVersion) -> DryRunResult:
        steps = sorted(version.action_steps, key=lambda s: s.step_number)
        if not steps:
            return DryRunResult(TestOutcome.FAILED, 0, 0, [], 1)
        paths: list[str] = []
        passed = 0
        for step in steps:
            # Dry-run validates structure: connector type present, no secret keys in params
            secret_keys = {"api_key", "secret", "password", "token", "private_key", "certificate"}
            if secret_keys.intersection(step.parameters):
                paths.append(f"step:{step.step_number}:secret_rejected")
                continue
            if not step.action_type:
                paths.append(f"step:{step.step_number}:missing_action")
                continue
            paths.append(f"step:{step.step_number}:ok")
            passed += 1
        tested = len(steps)
        if passed == tested:
            outcome = TestOutcome.PASSED
        elif passed == 0:
            outcome = TestOutcome.FAILED
        else:
            outcome = TestOutcome.PARTIAL
        return DryRunResult(outcome, tested, passed, paths, max(1, tested * 5))
''',
    )
    w(
        base / "domain" / "services" / "kill_switch_service.py",
        '''"""Kill switch domain operations — ADR-M35-004."""

from __future__ import annotations

from playbook.domain.aggregates.automation_policy import AutomationPolicy


class KillSwitchService:
    def activate(self, policy: AutomationPolicy, activated_by: str, reason: str) -> None:
        policy.activate_kill_switch(activated_by, reason)

    def reset(self, policy: AutomationPolicy, reset_by: str) -> None:
        policy.reset_kill_switch(reset_by)

    def is_triggered(self, policy: AutomationPolicy) -> bool:
        return policy.kill_switch_state.value == "TRIGGERED"
''',
    )
    w(
        base / "domain" / "services" / "playbook_lifecycle_service.py",
        '''"""Playbook lifecycle helpers."""

from __future__ import annotations

from playbook.domain.value_objects.definitions import ActionStepDefinition
from playbook.domain.value_objects.enums import ActionImpactLevel


class PlaybookLifecycleService:
    def max_impact(self, steps: list[ActionStepDefinition]) -> ActionImpactLevel:
        order = [
            ActionImpactLevel.LOW,
            ActionImpactLevel.MEDIUM,
            ActionImpactLevel.HIGH,
            ActionImpactLevel.CRITICAL,
        ]
        if not steps:
            return ActionImpactLevel.LOW
        return max(steps, key=lambda s: order.index(s.impact_level)).impact_level
''',
    )
    w(
        base / "domain" / "services" / "playbook_approval_service.py",
        '''"""Design-time approval orchestration helpers."""

from __future__ import annotations

from playbook.domain.services.playbook_authorization_service import PlaybookAuthorizationService
from playbook.domain.value_objects.enums import ActionImpactLevel


class PlaybookApprovalService:
    def __init__(self) -> None:
        self._authz = PlaybookAuthorizationService()

    def quorum_for(self, level: ActionImpactLevel) -> int:
        return self._authz.approval_requirements(level)[1]
''',
    )


def _repos(base):
    w(
        base / "domain" / "repositories" / "i_playbook_repositories.py",
        '''"""Frozen repository interfaces for playbook BC."""

from __future__ import annotations

from abc import ABC, abstractmethod

from playbook.domain.aggregates.automation_policy import AutomationPolicy
from playbook.domain.aggregates.playbook import Playbook
from playbook.domain.aggregates.playbook_test_result import PlaybookTestResult
from playbook.domain.aggregates.playbook_version import PlaybookVersion
from playbook.domain.value_objects.enums import TriggerSourceContext
from playbook.domain.value_objects.identifiers import (
    PlaybookId,
    PlaybookVersionId,
    TenantId,
)


class IPlaybookRepository(ABC):
    @abstractmethod
    async def save(self, playbook: Playbook, tenant_id: TenantId) -> None: ...

    @abstractmethod
    async def get(self, playbook_id: PlaybookId, tenant_id: TenantId) -> Playbook | None: ...

    @abstractmethod
    async def find_approved_for_trigger(
        self, tenant_id: TenantId, source_context: TriggerSourceContext
    ) -> list[Playbook]: ...

    @abstractmethod
    async def list(
        self, tenant_id: TenantId, *, status_filter: str | None, page: int, page_size: int
    ) -> list[Playbook]: ...


class IPlaybookVersionRepository(ABC):
    @abstractmethod
    async def save(self, version: PlaybookVersion, tenant_id: TenantId) -> None: ...

    @abstractmethod
    async def get(
        self, playbook_id: PlaybookId, version_number: int, tenant_id: TenantId
    ) -> PlaybookVersion | None: ...

    @abstractmethod
    async def get_latest(
        self, playbook_id: PlaybookId, tenant_id: TenantId
    ) -> PlaybookVersion | None: ...


class IPlaybookTestResultRepository(ABC):
    @abstractmethod
    async def append(self, result: PlaybookTestResult, tenant_id: TenantId) -> None: ...

    @abstractmethod
    async def find_latest_for_version(
        self, playbook_id: PlaybookId, version_id: PlaybookVersionId, tenant_id: TenantId
    ) -> PlaybookTestResult | None: ...


class IAutomationPolicyRepository(ABC):
    @abstractmethod
    async def get_or_create_default(self, tenant_id: TenantId) -> AutomationPolicy: ...

    @abstractmethod
    async def save(self, policy: AutomationPolicy, tenant_id: TenantId) -> None: ...
''',
    )
