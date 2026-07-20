"""KillSwitchState aggregate root — authoritative kill switch for a scope."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid7

from execution.domain.events.safety_events import (
    KillSwitchReArmed,
    KillSwitchReleased,
    KillSwitchTriggered,
)
from execution.domain.exceptions.domain_exceptions import (
    InvalidArgument,
    InvalidStateTransition,
    PlatformWideReleaseAuthorizationInsufficient,
    SameOperatorReleaseForbidden,
    TenantMismatch,
)
from execution.domain.value_objects.enums import (
    CISO_ROLE,
    OVERSIGHT_ROLES,
    KillSwitchArmedState,
    KillSwitchScope,
)
from execution.domain.value_objects.execution_vos import (
    ReleaseAuthority,
    TriggerAuthority,
    TriggerHash,
    TriggerReason,
)
from execution.domain.value_objects.identifiers import KillSwitchId

if TYPE_CHECKING:
    from datetime import datetime
    from uuid import UUID

    from execution.domain.events.base import BaseDomainEvent
    from execution.domain.value_objects.identifiers import TenantId

_ALLOWED: dict[KillSwitchArmedState, frozenset[KillSwitchArmedState]] = {
    KillSwitchArmedState.ARMED: frozenset({KillSwitchArmedState.TRIGGERED}),
    KillSwitchArmedState.TRIGGERED: frozenset({KillSwitchArmedState.RELEASED}),
    KillSwitchArmedState.RELEASED: frozenset({KillSwitchArmedState.ARMED}),
}

class KillSwitchState:
    """Kill switch state machine: Armed → Triggered → Released → Armed."""

    __slots__ = (
        "_pending_events",
        "_version",
        "armed_state",
        "created_at",
        "kill_switch_id",
        "release_authority",
        "release_countersign_authority",
        "release_timestamp",
        "scope",
        "scope_ref",
        "tenant_id",
        "trigger_authority",
        "trigger_hash",
        "trigger_reason",
        "trigger_timestamp",
        "updated_at",
    )

    def __init__(
        self,
        kill_switch_id: KillSwitchId,
        tenant_id: TenantId,
        scope: KillSwitchScope,
        scope_ref: UUID,
        armed_state: KillSwitchArmedState,
        created_at: datetime,
        updated_at: datetime,
        version: int,
        trigger_authority: TriggerAuthority | None = None,
        trigger_reason: TriggerReason | None = None,
        trigger_timestamp: datetime | None = None,
        trigger_hash: TriggerHash | None = None,
        release_authority: ReleaseAuthority | None = None,
        release_countersign_authority: ReleaseAuthority | None = None,
        release_timestamp: datetime | None = None,
    ) -> None:
        self.kill_switch_id = kill_switch_id
        self.tenant_id = tenant_id
        self.scope = scope
        self.scope_ref = scope_ref
        self.armed_state = armed_state
        self.created_at = created_at
        self.updated_at = updated_at
        self._version = version
        self.trigger_authority = trigger_authority
        self.trigger_reason = trigger_reason
        self.trigger_timestamp = trigger_timestamp
        self.trigger_hash = trigger_hash
        self.release_authority = release_authority
        self.release_countersign_authority = release_countersign_authority
        self.release_timestamp = release_timestamp
        self._pending_events: list[BaseDomainEvent] = []

    @property
    def version(self) -> int:
        return self._version

    @property
    def id(self) -> KillSwitchId:
        return self.kill_switch_id

    def pop_events(self) -> list[BaseDomainEvent]:
        events = list(self._pending_events)
        self._pending_events.clear()
        return events

    def _emit(self, event: BaseDomainEvent) -> None:
        self._pending_events.append(event)

    def _mutate(self, now: datetime) -> None:
        self.updated_at = now
        self._version += 1

    def _assert_tenant(self, tenant_id: TenantId) -> None:
        if tenant_id != self.tenant_id:
            raise TenantMismatch(self.tenant_id, tenant_id)

    def _transition(self, to_state: KillSwitchArmedState) -> None:
        allowed = _ALLOWED.get(self.armed_state, frozenset())
        if to_state not in allowed:
            raise InvalidStateTransition(
                self.armed_state.value,
                to_state.value,
                str(self.kill_switch_id),
            )
        self.armed_state = to_state

    @classmethod
    def create_armed(
        cls,
        tenant_id: TenantId,
        scope: KillSwitchScope,
        scope_ref: UUID,
        now: datetime,
    ) -> KillSwitchState:
        return cls(
            kill_switch_id=KillSwitchId.generate(),
            tenant_id=tenant_id,
            scope=scope,
            scope_ref=scope_ref,
            armed_state=KillSwitchArmedState.ARMED,
            created_at=now,
            updated_at=now,
            version=0,
        )

    def trigger(
        self,
        tenant_id: TenantId,
        authority: TriggerAuthority,
        reason: TriggerReason,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        if not reason.value.strip():
            raise InvalidArgument("reason", "trigger requires a non-empty reason")
        previous = self.armed_state
        self._transition(KillSwitchArmedState.TRIGGERED)
        self.trigger_authority = authority
        self.trigger_reason = reason
        self.trigger_timestamp = now
        self.trigger_hash = TriggerHash.compute(
            self.scope, KillSwitchArmedState.TRIGGERED, authority, now
        )
        self.release_authority = None
        self.release_countersign_authority = None
        self.release_timestamp = None
        self._mutate(now)
        self._emit(
            KillSwitchTriggered(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.kill_switch_id),
                aggregate_type="KillSwitchState",
                scope=self.scope,
                scope_ref=str(self.scope_ref),
                authority_ref=str(authority.operator_id),
                reason=reason.value,
                trigger_hash=self.trigger_hash.value,
                previous_state=previous,
            )
        )

    def release(
        self,
        tenant_id: TenantId,
        releasing: ReleaseAuthority,
        now: datetime,
        *,
        countersigning: ReleaseAuthority | None = None,
    ) -> None:
        self._assert_tenant(tenant_id)
        if self.trigger_authority is not None and (
            releasing.operator_id == self.trigger_authority.operator_id
        ):
            raise SameOperatorReleaseForbidden(str(releasing.operator_id))

        if self.scope == KillSwitchScope.PLATFORM_WIDE:
            self._validate_platform_wide_release(releasing, countersigning)
        elif countersigning is not None:
            raise InvalidArgument(
                "countersigning",
                "countersigning authority is only valid for PlatformWide release",
            )

        previous = self.armed_state
        self._transition(KillSwitchArmedState.RELEASED)
        self.release_authority = releasing
        self.release_countersign_authority = countersigning
        self.release_timestamp = now
        self._mutate(now)
        self._emit(
            KillSwitchReleased(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.kill_switch_id),
                aggregate_type="KillSwitchState",
                scope=self.scope,
                scope_ref=str(self.scope_ref),
                releasing_authority_ref=str(releasing.operator_id),
                countersigning_authority_ref=(
                    str(countersigning.operator_id) if countersigning else None
                ),
                previous_state=previous,
            )
        )

    def re_arm(
        self,
        tenant_id: TenantId,
        authority: TriggerAuthority,
        now: datetime,
    ) -> None:
        self._assert_tenant(tenant_id)
        previous = self.armed_state
        self._transition(KillSwitchArmedState.ARMED)
        self.trigger_authority = None
        self.trigger_reason = None
        self.trigger_timestamp = None
        self.trigger_hash = None
        self.release_authority = None
        self.release_countersign_authority = None
        self.release_timestamp = None
        self._mutate(now)
        self._emit(
            KillSwitchReArmed(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.kill_switch_id),
                aggregate_type="KillSwitchState",
                scope=self.scope,
                scope_ref=str(self.scope_ref),
                authority_ref=str(authority.operator_id),
                previous_state=previous,
            )
        )

    @staticmethod
    def _validate_platform_wide_release(
        releasing: ReleaseAuthority,
        countersigning: ReleaseAuthority | None,
    ) -> None:
        if countersigning is None:
            raise PlatformWideReleaseAuthorizationInsufficient(
                "requires two distinct authorities (redteam:ciso + oversight role)"
            )
        if releasing.operator_id == countersigning.operator_id:
            raise PlatformWideReleaseAuthorizationInsufficient(
                "same identity may not fulfill both release roles"
            )
        roles = {releasing.role.strip().lower(), countersigning.role.strip().lower()}
        if CISO_ROLE not in roles:
            raise PlatformWideReleaseAuthorizationInsufficient(
                f"one authority must hold {CISO_ROLE}"
            )
        oversight = roles - {CISO_ROLE}
        if not oversight or not oversight.issubset({r.lower() for r in OVERSIGHT_ROLES}):
            raise PlatformWideReleaseAuthorizationInsufficient(
                "second authority must hold a distinct oversight role "
                f"({', '.join(sorted(OVERSIGHT_ROLES))})"
            )
        if releasing.role.strip().lower() == countersigning.role.strip().lower():
            raise PlatformWideReleaseAuthorizationInsufficient(
                "releasing authorities must hold distinct roles"
            )
