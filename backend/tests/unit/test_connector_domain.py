"""Unit tests for the Connector domain bounded context (Sprint 23).

Tests cover:
- Connector lifecycle state machine (all valid and invalid transitions)
- Discovery job recording (start, complete, fail, conflict guard)
- Sync job recording (start, complete, fail, conflict guard)
- Value objects (ConnectorVersion, ConnectorHealth, ConnectorConfiguration)
- Domain events emitted at each lifecycle step
- Equality and identity semantics
- Invariant guards (archived terminal, enable guard, etc.)
"""

from __future__ import annotations

import pytest

from redforge.domain.connectors.entity import Connector
from redforge.domain.connectors.events import (
    ConnectorArchived,
    ConnectorConfigured,
    ConnectorDisabled,
    ConnectorEnabled,
    ConnectorRegistered,
    ConnectorValidated,
    DiscoveryJobCompleted,
    DiscoveryJobFailed,
    DiscoveryJobStarted,
    SyncJobCompleted,
    SyncJobFailed,
)
from redforge.domain.connectors.exceptions import (
    ConnectorAlreadyArchivedError,
    ConnectorNotEnabledError,
    DiscoveryJobConflictError,
    InvalidConnectorTransitionError,
    SyncJobConflictError,
)
from redforge.domain.connectors.value_objects import (
    ConnectorCapability,
    ConnectorCapabilityType,
    ConnectorConfiguration,
    ConnectorCredentialReference,
    ConnectorHealth,
    ConnectorHealthStatus,
    ConnectorStatus,
    ConnectorType,
    ConnectorVersion,
    CredentialType,
    SynchronizationPolicy,
)
from redforge.shared.identifiers import EntityId

# ─── Fixtures ─────────────────────────────────────────────────────────────────


def _make_connector(
    connector_type: ConnectorType = ConnectorType.OPENAI,
    name: str = "Test Connector",
) -> Connector:
    org_id = EntityId.generate()
    return Connector.register(
        organization_id=org_id,
        connector_type=connector_type,
        name=name,
        description="Test",
        version=ConnectorVersion(connector_type_version="1.0.0", schema_version="1.0"),
        capabilities=(ConnectorCapability(capability_type=ConnectorCapabilityType.ASSET_DISCOVERY),),
    )


def _make_enabled_connector() -> Connector:
    c = _make_connector()
    config = ConnectorConfiguration(base_url="https://api.openai.com")
    c.configure(config, None)
    c.mark_validated(latency_ms=10.0)
    c.enable()
    return c


# ─── Connector.register() ─────────────────────────────────────────────────────


class TestConnectorRegister:
    def test_initial_status_is_registered(self) -> None:
        c = _make_connector()
        assert c.status == ConnectorStatus.REGISTERED

    def test_events_contains_registered(self) -> None:
        c = _make_connector()
        events = c.collect_events()
        assert len(events) == 1
        assert isinstance(events[0], ConnectorRegistered)

    def test_collect_events_clears_queue(self) -> None:
        c = _make_connector()
        c.collect_events()
        assert c.collect_events() == []

    def test_id_is_entity_id(self) -> None:
        c = _make_connector()
        assert isinstance(c.id, EntityId)

    def test_connector_type_stored(self) -> None:
        c = _make_connector(ConnectorType.ANTHROPIC)
        assert c.connector_type == ConnectorType.ANTHROPIC

    def test_is_not_enabled_initially(self) -> None:
        c = _make_connector()
        assert not c.is_enabled


# ─── Lifecycle: REGISTERED → CONFIGURED ──────────────────────────────────────


class TestConnectorConfigure:
    def test_configure_advances_status(self) -> None:
        c = _make_connector()
        config = ConnectorConfiguration(base_url="https://api.openai.com")
        c.configure(config, None)
        assert c.status == ConnectorStatus.CONFIGURED

    def test_configure_emits_event(self) -> None:
        c = _make_connector()
        c.collect_events()
        config = ConnectorConfiguration(base_url="https://api.openai.com")
        c.configure(config, None)
        events = c.collect_events()
        assert any(isinstance(e, ConnectorConfigured) for e in events)

    def test_configure_stores_credential_ref(self) -> None:
        c = _make_connector()
        cred = ConnectorCredentialReference(
            reference_id="ref-123", credential_type=CredentialType.API_KEY
        )
        config = ConnectorConfiguration(base_url="https://api.openai.com")
        c.configure(config, cred)
        assert c.credential_ref is not None
        assert c.credential_ref.reference_id == "ref-123"

    def test_configure_archived_raises(self) -> None:
        c = _make_connector()
        c.configure(ConnectorConfiguration(base_url=""), None)
        c.mark_validated(latency_ms=5.0)
        c.enable()
        c.archive(reason="done")
        with pytest.raises(ConnectorAlreadyArchivedError):
            c.configure(ConnectorConfiguration(base_url=""), None)


# ─── Lifecycle: CONFIGURED → VALIDATED ───────────────────────────────────────


class TestConnectorValidate:
    def test_mark_validated_advances_status(self) -> None:
        c = _make_connector()
        c.configure(ConnectorConfiguration(base_url=""), None)
        c.mark_validated(latency_ms=5.0)
        assert c.status == ConnectorStatus.VALIDATED

    def test_mark_validated_emits_event(self) -> None:
        c = _make_connector()
        c.configure(ConnectorConfiguration(base_url=""), None)
        c.collect_events()
        c.mark_validated(latency_ms=5.0)
        events = c.collect_events()
        assert any(isinstance(e, ConnectorValidated) for e in events)

    def test_cannot_validate_from_registered(self) -> None:
        c = _make_connector()
        with pytest.raises(InvalidConnectorTransitionError):
            c.mark_validated(latency_ms=0.0)


# ─── Lifecycle: VALIDATED → ENABLED ──────────────────────────────────────────


class TestConnectorEnable:
    def test_enable_sets_enabled(self) -> None:
        c = _make_enabled_connector()
        assert c.status == ConnectorStatus.ENABLED
        assert c.is_enabled

    def test_enable_emits_event(self) -> None:
        c = _make_connector()
        c.configure(ConnectorConfiguration(base_url=""), None)
        c.mark_validated(latency_ms=0.0)
        c.collect_events()
        c.enable()
        events = c.collect_events()
        assert any(isinstance(e, ConnectorEnabled) for e in events)

    def test_cannot_enable_from_registered(self) -> None:
        c = _make_connector()
        with pytest.raises(InvalidConnectorTransitionError):
            c.enable()


# ─── Lifecycle: ENABLED → DISABLED ───────────────────────────────────────────


class TestConnectorDisable:
    def test_disable_from_enabled(self) -> None:
        c = _make_enabled_connector()
        c.disable(reason="maintenance")
        assert c.status == ConnectorStatus.DISABLED
        assert not c.is_enabled

    def test_disable_emits_event(self) -> None:
        c = _make_enabled_connector()
        c.collect_events()
        c.disable()
        events = c.collect_events()
        assert any(isinstance(e, ConnectorDisabled) for e in events)

    def test_re_enable_from_disabled(self) -> None:
        c = _make_enabled_connector()
        c.disable()
        c.enable()
        assert c.status == ConnectorStatus.ENABLED

    def test_cannot_disable_from_registered(self) -> None:
        c = _make_connector()
        with pytest.raises(InvalidConnectorTransitionError):
            c.disable()


# ─── Lifecycle: ARCHIVED (terminal) ──────────────────────────────────────────


class TestConnectorArchive:
    def test_archive_from_enabled(self) -> None:
        c = _make_enabled_connector()
        c.archive(reason="decommissioned")
        assert c.status == ConnectorStatus.ARCHIVED

    def test_archive_emits_event(self) -> None:
        c = _make_enabled_connector()
        c.collect_events()
        c.archive()
        events = c.collect_events()
        assert any(isinstance(e, ConnectorArchived) for e in events)

    def test_cannot_mutate_archived_connector(self) -> None:
        c = _make_enabled_connector()
        c.archive()
        with pytest.raises(ConnectorAlreadyArchivedError):
            c.enable()

    def test_can_archive_from_registered(self) -> None:
        c = _make_connector()
        c.archive()  # allowed from any non-archived status
        assert c.status == ConnectorStatus.ARCHIVED


# ─── Discovery Jobs ───────────────────────────────────────────────────────────


class TestDiscoveryJobs:
    def test_start_discovery_adds_record(self) -> None:
        c = _make_enabled_connector()
        c.start_discovery_job("job-1")
        assert len(c.discovery_history) == 1
        assert c.discovery_history[0].job_id == "job-1"

    def test_start_discovery_emits_event(self) -> None:
        c = _make_enabled_connector()
        c.collect_events()
        c.start_discovery_job("job-1")
        events = c.collect_events()
        assert any(isinstance(e, DiscoveryJobStarted) for e in events)

    def test_complete_discovery_records_counts(self) -> None:
        c = _make_enabled_connector()
        c.start_discovery_job("job-1")
        c.complete_discovery_job("job-1", assets_discovered=5, assets_normalized=5, assets_failed=0)
        job = c.discovery_history[0]
        assert job.assets_discovered == 5
        assert job.succeeded

    def test_complete_discovery_emits_event(self) -> None:
        c = _make_enabled_connector()
        c.start_discovery_job("job-1")
        c.collect_events()
        c.complete_discovery_job("job-1", assets_discovered=3, assets_normalized=3, assets_failed=0)
        events = c.collect_events()
        assert any(isinstance(e, DiscoveryJobCompleted) for e in events)

    def test_fail_discovery_emits_event(self) -> None:
        c = _make_enabled_connector()
        c.start_discovery_job("job-1")
        c.collect_events()
        c.fail_discovery_job("job-1", "timeout")
        events = c.collect_events()
        assert any(isinstance(e, DiscoveryJobFailed) for e in events)

    def test_only_one_running_discovery_at_a_time(self) -> None:
        c = _make_enabled_connector()
        c.start_discovery_job("job-1")
        with pytest.raises(DiscoveryJobConflictError):
            c.start_discovery_job("job-2")

    def test_cannot_start_discovery_when_not_enabled(self) -> None:
        c = _make_connector()
        with pytest.raises(ConnectorNotEnabledError):
            c.start_discovery_job("job-1")

    def test_total_assets_discovered_sums_completed(self) -> None:
        c = _make_enabled_connector()
        c.start_discovery_job("job-1")
        c.complete_discovery_job("job-1", assets_discovered=10, assets_normalized=10, assets_failed=0)
        c.start_discovery_job("job-2")
        c.complete_discovery_job("job-2", assets_discovered=5, assets_normalized=5, assets_failed=0)
        assert c.total_assets_discovered == 15


# ─── Sync Jobs ────────────────────────────────────────────────────────────────


class TestSyncJobs:
    def test_start_sync_adds_record(self) -> None:
        c = _make_enabled_connector()
        c.start_sync_job("sync-1")
        assert len(c.sync_history) == 1

    def test_complete_sync_records_counts(self) -> None:
        c = _make_enabled_connector()
        c.start_sync_job("sync-1")
        c.complete_sync_job("sync-1", assets_added=3, assets_updated=1, assets_unchanged=10)
        job = c.sync_history[0]
        assert job.assets_added == 3
        assert job.assets_updated == 1

    def test_complete_sync_emits_event(self) -> None:
        c = _make_enabled_connector()
        c.start_sync_job("sync-1")
        c.collect_events()
        c.complete_sync_job("sync-1", assets_added=2, assets_updated=0, assets_unchanged=5)
        events = c.collect_events()
        assert any(isinstance(e, SyncJobCompleted) for e in events)

    def test_fail_sync_emits_event(self) -> None:
        c = _make_enabled_connector()
        c.start_sync_job("sync-1")
        c.collect_events()
        c.fail_sync_job("sync-1", "connection refused")
        events = c.collect_events()
        assert any(isinstance(e, SyncJobFailed) for e in events)

    def test_only_one_running_sync_at_a_time(self) -> None:
        c = _make_enabled_connector()
        c.start_sync_job("sync-1")
        with pytest.raises(SyncJobConflictError):
            c.start_sync_job("sync-2")

    def test_is_full_sync_stored(self) -> None:
        c = _make_enabled_connector()
        c.start_sync_job("sync-1", is_full_sync=True)
        assert c.sync_history[0].is_full_sync


# ─── Value Objects ────────────────────────────────────────────────────────────


class TestValueObjects:
    def test_connector_version_equality(self) -> None:
        v1 = ConnectorVersion(connector_type_version="1.0.0", schema_version="1.0")
        v2 = ConnectorVersion(connector_type_version="1.0.0", schema_version="1.0")
        assert v1 == v2

    def test_connector_health_unknown_factory(self) -> None:
        h = ConnectorHealth.unknown()
        assert h.status == ConnectorHealthStatus.UNKNOWN

    def test_connector_health_healthy_factory(self) -> None:
        h = ConnectorHealth.healthy(latency_ms=5.0)
        assert h.status == ConnectorHealthStatus.HEALTHY
        assert h.latency_ms == 5.0

    def test_connector_health_unreachable_factory(self) -> None:
        h = ConnectorHealth.unreachable("timeout", consecutive_failures=3)
        assert h.status == ConnectorHealthStatus.UNREACHABLE
        assert h.consecutive_failures == 3

    def test_connector_configuration_custom_config_tuple(self) -> None:
        cfg = ConnectorConfiguration(
            base_url="https://example.com",
            custom_config=(("region", "us-east-1"),),
        )
        assert cfg.custom_config == (("region", "us-east-1"),)

    def test_connector_credential_reference_hashable(self) -> None:
        cred = ConnectorCredentialReference(
            reference_id="ref-1", credential_type=CredentialType.API_KEY
        )
        # Should be usable in a set/dict key
        assert {cred} != None

    def test_synchronization_policy_defaults(self) -> None:
        policy = SynchronizationPolicy()
        assert policy.incremental
        assert policy.max_assets_per_run > 0


# ─── Health Update ────────────────────────────────────────────────────────────


class TestHealthUpdate:
    def test_update_health_stores_new_health(self) -> None:
        c = _make_enabled_connector()
        health = ConnectorHealth.healthy(latency_ms=12.5)
        c.update_health(health)
        assert c.health.status == ConnectorHealthStatus.HEALTHY
        assert c.health.latency_ms == 12.5

    def test_update_health_archived_allowed(self) -> None:
        c = _make_enabled_connector()
        c.archive()
        # update_health does not guard against archived state; monitoring continues
        c.update_health(ConnectorHealth.healthy())
        assert c.health.status == ConnectorHealthStatus.HEALTHY


# ─── Sync Policy ──────────────────────────────────────────────────────────────


class TestSyncPolicy:
    def test_update_sync_policy(self) -> None:
        c = _make_enabled_connector()
        policy = SynchronizationPolicy(cron_expression="0 */4 * * *")
        c.update_sync_policy(policy)
        assert c.sync_policy.cron_expression == "0 */4 * * *"
