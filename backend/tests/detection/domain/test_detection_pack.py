"""DetectionPack aggregate tests — Phase 4."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from detection.domain.aggregates.detection_pack import DetectionPack
from detection.domain.events.pack_events import (
    DetectionPackCreated,
    DetectionPackPublished,
    PackSubscriptionChanged,
    RuleAddedToPack,
)
from detection.domain.exceptions.domain_exceptions import (
    InvalidArgument,
    InvalidStateTransition,
    PackLifecycleBlocked,
)
from detection.domain.value_objects.enums import PackCategory, PackLifecycleState
from detection.domain.value_objects.pack import PackKey, PackMaintainer
from tests.detection.phase4_helpers import make_pack, make_tenant


def test_create_emits_created_event() -> None:
    pack = make_pack()
    events = pack.pop_events()
    assert any(isinstance(e, DetectionPackCreated) for e in events)
    assert pack.lifecycle_state == PackLifecycleState.DRAFT


@pytest.mark.parametrize(
    "category",
    list(PackCategory),
)
def test_create_all_categories(category: PackCategory) -> None:
    tid = make_tenant()
    now = datetime.now(UTC)
    pack = DetectionPack.create(
        tenant_id=tid,
        pack_key=PackKey(f"ns.pack_{category.name.lower()[:8]}"),
        title="t",
        category=category,
        maintainer=PackMaintainer(identity="m"),
        now=now,
    )
    assert pack.category == category


@pytest.mark.parametrize("idx", range(20))
def test_add_rule_unique(idx: int) -> None:
    pack = make_pack(with_rule=False, pack_key=f"ns.pack{idx}")
    tid = pack.tenant_id
    now = datetime.now(UTC)
    rid = str(uuid4())
    pack.add_rule(tenant_id=tid, rule_id=rid, now=now)
    with pytest.raises(InvalidArgument):
        pack.add_rule(tenant_id=tid, rule_id=rid, now=now)
    assert any(isinstance(e, RuleAddedToPack) for e in pack.pop_events())


def test_publish_requires_rules() -> None:
    pack = make_pack(with_rule=False)
    with pytest.raises(PackLifecycleBlocked):
        pack.publish(tenant_id=pack.tenant_id, now=datetime.now(UTC))


def test_publish_releases_version_and_publishes() -> None:
    pack = make_pack()
    pack.publish(tenant_id=pack.tenant_id, now=datetime.now(UTC))
    assert pack.lifecycle_state == PackLifecycleState.PUBLISHED
    assert pack.pack_versions
    events = pack.pop_events()
    assert any(isinstance(e, DetectionPackPublished) for e in events)


def test_subscribe_only_when_published() -> None:
    pack = make_pack()
    with pytest.raises(PackLifecycleBlocked):
        pack.subscribe_tenant(
            tenant_id=pack.tenant_id,
            subscriber_tenant_id=str(uuid4()),
            now=datetime.now(UTC),
        )
    pack.publish(tenant_id=pack.tenant_id, now=datetime.now(UTC))
    sid = str(uuid4())
    pack.subscribe_tenant(
        tenant_id=pack.tenant_id, subscriber_tenant_id=sid, now=datetime.now(UTC)
    )
    assert pack.subscription_scope.contains(sid)
    assert any(isinstance(e, PackSubscriptionChanged) for e in pack.pop_events())


def test_unsubscribe() -> None:
    pack = make_pack()
    pack.publish(tenant_id=pack.tenant_id, now=datetime.now(UTC))
    sid = str(uuid4())
    now = datetime.now(UTC)
    pack.subscribe_tenant(tenant_id=pack.tenant_id, subscriber_tenant_id=sid, now=now)
    pack.unsubscribe_tenant(tenant_id=pack.tenant_id, subscriber_tenant_id=sid, now=now)
    assert not pack.subscription_scope.contains(sid)


def test_deprecate_and_archive() -> None:
    pack = make_pack()
    now = datetime.now(UTC)
    pack.publish(tenant_id=pack.tenant_id, now=now)
    pack.deprecate(tenant_id=pack.tenant_id, reason="legacy", now=now)
    assert pack.lifecycle_state == PackLifecycleState.DEPRECATED
    pack.archive(tenant_id=pack.tenant_id, now=now)
    assert pack.lifecycle_state == PackLifecycleState.ARCHIVED
    with pytest.raises((InvalidStateTransition, PackLifecycleBlocked)):
        pack.publish(tenant_id=pack.tenant_id, now=now)


def test_remove_rule() -> None:
    pack = make_pack(with_rule=False)
    tid = pack.tenant_id
    now = datetime.now(UTC)
    rid = str(uuid4())
    pack.add_rule(tenant_id=tid, rule_id=rid, now=now)
    pack.remove_rule(tenant_id=tid, rule_id=rid, now=now)
    assert pack.rules == []


def test_release_version_bumps() -> None:
    pack = make_pack()
    now = datetime.now(UTC)
    v1 = pack.release_version(tenant_id=pack.tenant_id, now=now, bump="patch")
    v2 = pack.release_version(tenant_id=pack.tenant_id, now=now, bump="minor")
    assert str(v1.version) != str(v2.version)


def test_refresh_coverage() -> None:
    pack = make_pack()
    matrix = pack.refresh_coverage(
        tenant_id=pack.tenant_id,
        technique_to_rules={"T1059": [str(uuid4())]},
        now=datetime.now(UTC),
    )
    assert matrix.entries[0].technique_id == "T1059"


@pytest.mark.parametrize("bad_key", ["Bad", "a", "ns.", ".name", "1ns.pack", "ns.pack!"])
def test_invalid_pack_key(bad_key: str) -> None:
    with pytest.raises(InvalidArgument):
        PackKey(bad_key)


@pytest.mark.parametrize("i", range(30))
def test_pack_key_valid_variants(i: int) -> None:
    key = PackKey(f"ns.pack_{i}")
    assert str(key).startswith("ns.")
