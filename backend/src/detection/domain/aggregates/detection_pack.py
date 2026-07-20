"""DetectionPack aggregate root — curated, versioned rule collections."""

from __future__ import annotations

from typing import TYPE_CHECKING
from uuid import uuid7

from detection.domain.entities.pack_entities import PackRule, PackVersion
from detection.domain.events.pack_events import (
    DetectionPackCreated,
    DetectionPackDeprecated,
    DetectionPackPublished,
    DetectionPackVersionReleased,
    PackSubscriptionChanged,
    RuleAddedToPack,
    RuleRemovedFromPack,
)
from detection.domain.exceptions.domain_exceptions import (
    InvalidArgument,
    InvalidStateTransition,
    PackLifecycleBlocked,
    TenantMismatch,
)
from detection.domain.value_objects.enums import PackLifecycleState
from detection.domain.value_objects.identifiers import (
    DetectionPackId,
    PackRuleId,
    PackVersionId,
)
from detection.domain.value_objects.keys import RuleSemVer
from detection.domain.value_objects.pack import (
    CoverageMatrix,
    PackMetadata,
    PackSubscriptionScope,
)

if TYPE_CHECKING:
    from datetime import datetime

    from detection.domain.events.base import BaseDomainEvent
    from detection.domain.value_objects.enums import PackCategory
    from detection.domain.value_objects.identifiers import TenantId
    from detection.domain.value_objects.pack import (
        ComplianceFrameworkRef,
        PackKey,
        PackMaintainer,
    )

_ALLOWED: dict[PackLifecycleState, frozenset[PackLifecycleState]] = {
    PackLifecycleState.DRAFT: frozenset(
        {PackLifecycleState.PUBLISHED, PackLifecycleState.ARCHIVED}
    ),
    PackLifecycleState.PUBLISHED: frozenset(
        {PackLifecycleState.DEPRECATED, PackLifecycleState.ARCHIVED}
    ),
    PackLifecycleState.DEPRECATED: frozenset({PackLifecycleState.ARCHIVED}),
    PackLifecycleState.ARCHIVED: frozenset(),
}


class DetectionPack:
    """Curated rule pack with versioning, subscription, and coverage summary."""

    __slots__ = (
        "_pending_events",
        "_version",
        "category",
        "compliance_framework",
        "coverage_matrix",
        "created_at",
        "lifecycle_state",
        "maintainer",
        "metadata",
        "pack_id",
        "pack_key",
        "pack_versions",
        "rules",
        "semver",
        "subscription_scope",
        "tenant_id",
        "title",
        "updated_at",
    )

    def __init__(
        self,
        pack_id: DetectionPackId,
        tenant_id: TenantId,
        pack_key: PackKey,
        title: str,
        category: PackCategory,
        maintainer: PackMaintainer,
        lifecycle_state: PackLifecycleState,
        semver: RuleSemVer,
        created_at: datetime,
        updated_at: datetime,
        *,
        rules: list[PackRule] | None = None,
        pack_versions: list[PackVersion] | None = None,
        subscription_scope: PackSubscriptionScope | None = None,
        compliance_framework: ComplianceFrameworkRef | None = None,
        coverage_matrix: CoverageMatrix | None = None,
        metadata: PackMetadata | None = None,
        version: int = 0,
    ) -> None:
        self.pack_id = pack_id
        self.tenant_id = tenant_id
        self.pack_key = pack_key
        self.title = title
        self.category = category
        self.maintainer = maintainer
        self.lifecycle_state = lifecycle_state
        self.semver = semver
        self.rules = list(rules or [])
        self.pack_versions = list(pack_versions or [])
        self.subscription_scope = subscription_scope or PackSubscriptionScope()
        self.compliance_framework = compliance_framework
        self.coverage_matrix = coverage_matrix or CoverageMatrix.empty()
        self.metadata = metadata or PackMetadata()
        self.created_at = created_at
        self.updated_at = updated_at
        self._version = version
        self._pending_events: list[BaseDomainEvent] = []

    @property
    def version(self) -> int:
        return self._version

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
        if self.tenant_id != tenant_id:
            raise TenantMismatch(str(tenant_id), str(self.tenant_id))

    def _transition(self, target: PackLifecycleState) -> None:
        allowed = _ALLOWED.get(self.lifecycle_state, frozenset())
        if target not in allowed:
            raise InvalidStateTransition(
                self.lifecycle_state.value,
                target.value,
            )
        self.lifecycle_state = target

    @classmethod
    def create(
        cls,
        *,
        tenant_id: TenantId,
        pack_key: PackKey,
        title: str,
        category: PackCategory,
        maintainer: PackMaintainer,
        now: datetime,
        compliance_framework: ComplianceFrameworkRef | None = None,
        metadata: PackMetadata | None = None,
        pack_id: DetectionPackId | None = None,
        initial_semver: RuleSemVer | None = None,
    ) -> DetectionPack:
        if not title.strip():
            raise InvalidArgument("title", "required")
        pid = pack_id or DetectionPackId.generate()
        aggregate = cls(
            pack_id=pid,
            tenant_id=tenant_id,
            pack_key=pack_key,
            title=title.strip()[:512],
            category=category,
            maintainer=maintainer,
            lifecycle_state=PackLifecycleState.DRAFT,
            semver=initial_semver or RuleSemVer(0, 1, 0),
            created_at=now,
            updated_at=now,
            compliance_framework=compliance_framework,
            metadata=metadata,
            version=0,
        )
        aggregate._emit(
            DetectionPackCreated(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=tenant_id,
                aggregate_id=str(pid),
                aggregate_type="DetectionPack",
                pack_key=str(pack_key),
                category=category.value,
            )
        )
        return aggregate

    def validate_for_publish(self) -> None:
        if self.lifecycle_state != PackLifecycleState.DRAFT:
            raise PackLifecycleBlocked("only Draft packs can be validated for publish")
        if not self.rules:
            raise PackLifecycleBlocked("pack must contain at least one PackRule")
        if not self.title.strip():
            raise PackLifecycleBlocked("title required")

    def add_rule(
        self,
        *,
        tenant_id: TenantId,
        rule_id: str,
        now: datetime,
        rule_version: RuleSemVer | None = None,
        optional: bool = False,
    ) -> PackRule:
        self._assert_tenant(tenant_id)
        if self.lifecycle_state not in {
            PackLifecycleState.DRAFT,
            PackLifecycleState.PUBLISHED,
        }:
            raise PackLifecycleBlocked("cannot add rules in current lifecycle state")
        rid = rule_id.strip()
        if any(r.rule_id == rid for r in self.rules):
            raise InvalidArgument("rule_id", f"already in pack: {rid}")
        pack_rule = PackRule(
            pack_rule_id=PackRuleId.generate(),
            rule_id=rid,
            rule_version=rule_version,
            added_at=now,
            optional=optional,
        )
        self.rules.append(pack_rule)
        self._mutate(now)
        self._emit(
            RuleAddedToPack(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.pack_id),
                aggregate_type="DetectionPack",
                rule_id=rid,
                rule_version=str(rule_version) if rule_version else None,
            )
        )
        return pack_rule

    def remove_rule(self, *, tenant_id: TenantId, rule_id: str, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if self.lifecycle_state == PackLifecycleState.ARCHIVED:
            raise PackLifecycleBlocked("cannot remove rules from archived pack")
        rid = rule_id.strip()
        before = len(self.rules)
        self.rules = [r for r in self.rules if r.rule_id != rid]
        if len(self.rules) == before:
            raise InvalidArgument("rule_id", f"not in pack: {rid}")
        self._mutate(now)
        self._emit(
            RuleRemovedFromPack(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.pack_id),
                aggregate_type="DetectionPack",
                rule_id=rid,
            )
        )

    def release_version(
        self,
        *,
        tenant_id: TenantId,
        now: datetime,
        release_notes: str = "",
        bump: str = "patch",
    ) -> PackVersion:
        self._assert_tenant(tenant_id)
        if not self.rules:
            raise PackLifecycleBlocked("cannot release empty pack version")
        if bump == "major":
            self.semver = self.semver.bump_major()
        elif bump == "minor":
            self.semver = self.semver.bump_minor()
        else:
            self.semver = self.semver.bump_patch()
        snapshot = PackVersion(
            pack_version_id=PackVersionId.generate(),
            version=self.semver,
            rule_snapshots=tuple(
                (r.rule_id, str(r.rule_version) if r.rule_version else None)
                for r in self.rules
            ),
            released_at=now,
            release_notes=release_notes,
        )
        self.pack_versions.append(snapshot)
        self._mutate(now)
        self._emit(
            DetectionPackVersionReleased(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.pack_id),
                aggregate_type="DetectionPack",
                version=str(self.semver),
                rule_count=len(self.rules),
            )
        )
        return snapshot

    def publish(self, *, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        self.validate_for_publish()
        if not self.pack_versions:
            self.release_version(tenant_id=tenant_id, now=now, release_notes="initial")
        self._transition(PackLifecycleState.PUBLISHED)
        self._mutate(now)
        self._emit(
            DetectionPackPublished(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.pack_id),
                aggregate_type="DetectionPack",
                pack_key=str(self.pack_key),
                version=str(self.semver),
            )
        )

    def deprecate(self, *, tenant_id: TenantId, reason: str, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        if not reason.strip():
            raise InvalidArgument("reason", "required")
        self._transition(PackLifecycleState.DEPRECATED)
        self._mutate(now)
        self._emit(
            DetectionPackDeprecated(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.pack_id),
                aggregate_type="DetectionPack",
                reason=reason.strip()[:1024],
            )
        )

    def archive(self, *, tenant_id: TenantId, now: datetime) -> None:
        self._assert_tenant(tenant_id)
        self._transition(PackLifecycleState.ARCHIVED)
        self._mutate(now)

    def subscribe_tenant(
        self, *, tenant_id: TenantId, subscriber_tenant_id: str, now: datetime
    ) -> None:
        self._assert_tenant(tenant_id)
        if self.lifecycle_state != PackLifecycleState.PUBLISHED:
            raise PackLifecycleBlocked("only Published packs accept subscriptions")
        sid = subscriber_tenant_id.strip()
        if not sid:
            raise InvalidArgument("subscriber_tenant_id", "required")
        self.subscription_scope = self.subscription_scope.with_subscribed(sid)
        self._mutate(now)
        self._emit(
            PackSubscriptionChanged(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.pack_id),
                aggregate_type="DetectionPack",
                subscribed_tenant_id=sid,
                action="subscribed",
            )
        )

    def unsubscribe_tenant(
        self, *, tenant_id: TenantId, subscriber_tenant_id: str, now: datetime
    ) -> None:
        self._assert_tenant(tenant_id)
        sid = subscriber_tenant_id.strip()
        self.subscription_scope = self.subscription_scope.with_unsubscribed(sid)
        self._mutate(now)
        self._emit(
            PackSubscriptionChanged(
                event_id=str(uuid7()),
                occurred_at=now,
                tenant_id=self.tenant_id,
                aggregate_id=str(self.pack_id),
                aggregate_type="DetectionPack",
                subscribed_tenant_id=sid,
                action="unsubscribed",
            )
        )

    def refresh_coverage(
        self,
        *,
        tenant_id: TenantId,
        technique_to_rules: dict[str, list[str]],
        now: datetime,
    ) -> CoverageMatrix:
        self._assert_tenant(tenant_id)
        matrix = CoverageMatrix.from_technique_map(
            technique_to_rules, computed_at=now
        )
        self.coverage_matrix = matrix
        self._mutate(now)
        return matrix
