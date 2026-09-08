from __future__ import annotations

from datetime import timedelta

import pytest

from infrastructure_intel.domain.aggregates.infrastructure import Infrastructure
from infrastructure_intel.domain.events.infrastructure_events import (
    CloudProviderSet,
    EvidenceCitationAdded,
    HostingProviderSet,
    InfrastructureDeprecated,
    InfrastructureObserved,
    InfrastructureReactivated,
    InfrastructureRevoked,
    InfrastructureSuperseded,
    NetworkOwnershipSet,
    RegionAdded,
    SourceAttributionAdded,
)
from infrastructure_intel.domain.exceptions.domain_exceptions import (
    InvalidLifecycleTransitionError,
    InvalidNormalizedIdentifierError,
    TenantMismatchError,
)
from infrastructure_intel.domain.factories.infrastructure_factory import (
    InfrastructureFactory,
)
from infrastructure_intel.domain.value_objects.enums import (
    CloudProvider,
    InfrastructureConfidence,
    InfrastructureLifecycleStatus,
    InfrastructureType,
)
from infrastructure_intel.domain.value_objects.evidence import EvidenceCitation
from infrastructure_intel.domain.value_objects.hosting import (
    CloudProviderRef,
    HostingProviderRef,
    NetworkOwnership,
    Region,
)
from infrastructure_intel.domain.value_objects.identifiers import InfrastructureId

T = InfrastructureType


def _observe(
    now,
    tenant_id=None,
    infrastructure_type: InfrastructureType = T.ASN,
    normalized_identifier: str = "AS15169",
    **kwargs,
) -> Infrastructure:
    return InfrastructureFactory().observe(
        tenant_id=tenant_id,
        infrastructure_type=infrastructure_type,
        normalized_identifier=normalized_identifier,
        now=now,
        **kwargs,
    )


# ── Construction ─────────────────────────────────────────────────────────


def test_observe_sets_active_lifecycle_and_first_version(now) -> None:
    record = _observe(now)
    assert record.lifecycle_status is InfrastructureLifecycleStatus.ACTIVE
    assert record.created_at == now
    assert record.updated_at == now
    assert record.row_version == 1
    assert len(record.version_history) == 1
    assert record.version_history[0].version == 1
    assert record.version_history[0].change_summary == "Observed"
    assert record.version_history[0].source == "infrastructure_intel"


def test_observe_normalizes_the_identifier_at_construction(now) -> None:
    record = _observe(now, normalized_identifier="  as 15169 ")
    assert record.normalized_identifier == "AS15169"


def test_observe_normalizes_per_type(now) -> None:
    domain = _observe(now, infrastructure_type=T.DOMAIN, normalized_identifier=" EVIL.Example.COM ")
    ip = _observe(now, infrastructure_type=T.IP_ADDRESS, normalized_identifier="2001:0DB8::0001")
    assert domain.normalized_identifier == "evil.example.com"
    assert ip.normalized_identifier == "2001:db8::1"


def test_observe_rejects_an_unnormalizable_identifier(now) -> None:
    with pytest.raises(InvalidNormalizedIdentifierError):
        _observe(now, infrastructure_type=T.IP_ADDRESS, normalized_identifier="not-an-ip")


def test_observe_defaults_are_conservative(now) -> None:
    record = _observe(now)
    assert record.confidence is InfrastructureConfidence.MEDIUM
    assert record.hosting_provider is None
    assert record.cloud_provider is None
    assert record.network_ownership is None
    assert record.regions == ()
    assert record.evidence_citations == ()
    assert record.source_attributions == ()
    assert record.superseded_by is None


def test_observe_accepts_the_full_initial_shape(now) -> None:
    record = _observe(
        now,
        hosting_provider=HostingProviderRef(provider_name="Shady Hosting BV"),
        cloud_provider=CloudProviderRef(provider=CloudProvider.AWS),
        regions=(Region(region_code="us-east-1"),),
        network_ownership=NetworkOwnership(registrant_organization="Shady Hosting BV"),
        confidence=InfrastructureConfidence.VERY_HIGH,
    )
    assert record.hosting_provider is not None
    assert record.hosting_provider.provider_name == "Shady Hosting BV"
    assert record.cloud_provider is not None
    assert record.cloud_provider.provider is CloudProvider.AWS
    assert record.regions == (Region(region_code="us-east-1"),)
    assert record.network_ownership is not None
    assert record.confidence is InfrastructureConfidence.VERY_HIGH


def test_observe_emits_infrastructure_observed_with_payload(now) -> None:
    record = _observe(now, confidence=InfrastructureConfidence.HIGH)
    events = record.pop_events()
    assert len(events) == 1
    event = events[0]
    assert isinstance(event, InfrastructureObserved)
    assert event.infrastructure_type == "asn"
    assert event.normalized_identifier == "AS15169"
    assert event.confidence == "high"
    assert event.aggregate_type == "Infrastructure"
    assert event.aggregate_id == str(record.infrastructure_id)


def test_a_global_record_renders_empty_tenant_in_events(now) -> None:
    record = _observe(now, tenant_id=None)
    assert record.pop_events()[0].tenant_id == ""


def test_a_tenant_record_renders_its_tenant_in_events(now, tenant_id) -> None:
    record = _observe(now, tenant_id=tenant_id)
    assert record.pop_events()[0].tenant_id == str(tenant_id)


def test_pop_events_drains_the_pending_list(now) -> None:
    record = _observe(now)
    assert len(record.pop_events()) == 1
    assert record.pop_events() == []


# ── Enrichment ───────────────────────────────────────────────────────────


def test_set_hosting_provider_records_a_version_and_emits(now) -> None:
    record = _observe(now)
    record.pop_events()
    later = now + timedelta(hours=1)
    record.set_hosting_provider(None, HostingProviderRef(provider_name="OVH"), later)

    assert record.hosting_provider is not None
    assert record.hosting_provider.provider_name == "OVH"
    assert len(record.version_history) == 2
    assert record.version_history[1].change_summary == "Hosting provider set: OVH"
    assert record.updated_at == later
    events = record.pop_events()
    assert isinstance(events[0], HostingProviderSet)
    assert events[0].provider_name == "OVH"


def test_set_hosting_provider_replaces_the_previous_assertion(now) -> None:
    record = _observe(now)
    record.set_hosting_provider(None, HostingProviderRef(provider_name="OVH"), now)
    record.set_hosting_provider(None, HostingProviderRef(provider_name="Hetzner"), now)
    assert record.hosting_provider is not None
    assert record.hosting_provider.provider_name == "Hetzner"


def test_set_cloud_provider_records_a_version_and_emits(now) -> None:
    record = _observe(now)
    record.pop_events()
    record.set_cloud_provider(None, CloudProviderRef(provider=CloudProvider.GCP), now)
    assert record.cloud_provider is not None
    assert record.cloud_provider.provider is CloudProvider.GCP
    events = record.pop_events()
    assert isinstance(events[0], CloudProviderSet)
    assert events[0].provider == "gcp"


def test_add_region_appends_and_emits(now) -> None:
    record = _observe(now)
    record.pop_events()
    record.add_region(None, Region(region_code="us-east-1"), now)
    assert record.regions == (Region(region_code="us-east-1"),)
    events = record.pop_events()
    assert isinstance(events[0], RegionAdded)
    assert events[0].region_code == "us-east-1"


def test_add_region_is_idempotent_on_the_collection(now) -> None:
    record = _observe(now)
    record.add_region(None, Region(region_code="us-east-1"), now)
    record.add_region(None, Region(region_code="us-east-1"), now)
    assert record.regions == (Region(region_code="us-east-1"),)
    # Every mutator still records a version, even when the collection
    # was already satisfied — the assertion itself is the event.
    assert len(record.version_history) == 3


def test_set_network_ownership_records_a_version_and_emits(now) -> None:
    record = _observe(now)
    record.pop_events()
    ownership = NetworkOwnership(
        registrant_organization="Shady Hosting BV",
        abuse_contact="abuse@shady.example",
        notes="RIR record",
    )
    record.set_network_ownership(None, ownership, now)
    assert record.network_ownership == ownership
    events = record.pop_events()
    assert isinstance(events[0], NetworkOwnershipSet)
    assert events[0].registrant_organization == "Shady Hosting BV"


def test_add_evidence_citation_appends_and_emits(now) -> None:
    record = _observe(now)
    record.pop_events()
    record.add_evidence_citation(None, EvidenceCitation("https://vendor/report"), now)
    assert len(record.evidence_citations) == 1
    events = record.pop_events()
    assert isinstance(events[0], EvidenceCitationAdded)
    assert events[0].citation == "https://vendor/report"


def test_evidence_citations_are_append_only_and_allow_duplicates(now) -> None:
    """Two independent sources citing the same URL is real signal —
    citations are an append-only log, not a set."""
    record = _observe(now)
    citation = EvidenceCitation("https://vendor/report")
    record.add_evidence_citation(None, citation, now)
    record.add_evidence_citation(None, citation, now)
    assert len(record.evidence_citations) == 2


def test_add_source_attribution_records_the_source_system_as_version_source(now, evidence) -> None:
    record = _observe(now)
    record.pop_events()
    record.add_source_attribution(None, evidence, now)
    assert record.source_attributions == (evidence,)
    assert record.version_history[-1].source == "redforge-analyst"
    events = record.pop_events()
    assert isinstance(events[0], SourceAttributionAdded)
    assert events[0].source_system == "redforge-analyst"
    assert events[0].confidence == "high"


# ── Tenant isolation ─────────────────────────────────────────────────────


def test_every_mutator_rejects_a_foreign_tenant(now, tenant_id, evidence) -> None:
    from infrastructure_intel.domain.value_objects.identifiers import TenantId

    record = _observe(now, tenant_id=tenant_id)
    foreign = TenantId.generate()

    with pytest.raises(TenantMismatchError):
        record.set_hosting_provider(foreign, HostingProviderRef(provider_name="OVH"), now)
    with pytest.raises(TenantMismatchError):
        record.set_cloud_provider(foreign, CloudProviderRef(provider=CloudProvider.AWS), now)
    with pytest.raises(TenantMismatchError):
        record.add_region(foreign, Region(region_code="us-east-1"), now)
    with pytest.raises(TenantMismatchError):
        record.set_network_ownership(foreign, NetworkOwnership(registrant_organization="x"), now)
    with pytest.raises(TenantMismatchError):
        record.add_evidence_citation(foreign, EvidenceCitation("c"), now)
    with pytest.raises(TenantMismatchError):
        record.add_source_attribution(foreign, evidence, now)
    with pytest.raises(TenantMismatchError):
        record.deprecate(foreign, evidence, now)
    with pytest.raises(TenantMismatchError):
        record.revoke(foreign, evidence, now)
    with pytest.raises(TenantMismatchError):
        record.supersede(foreign, InfrastructureId.generate(), evidence, now)


def test_a_global_record_rejects_a_tenant_actor(now, tenant_id, evidence) -> None:
    record = _observe(now, tenant_id=None)
    with pytest.raises(TenantMismatchError):
        record.deprecate(tenant_id, evidence, now)


def test_a_tenant_record_rejects_a_global_actor(now, tenant_id, evidence) -> None:
    record = _observe(now, tenant_id=tenant_id)
    with pytest.raises(TenantMismatchError):
        record.deprecate(None, evidence, now)


# ── Record lifecycle ─────────────────────────────────────────────────────


def test_deprecate_transitions_and_emits(now, evidence) -> None:
    record = _observe(now)
    record.pop_events()
    record.deprecate(None, evidence, now)
    assert record.lifecycle_status is InfrastructureLifecycleStatus.DEPRECATED
    assert record.version_history[-1].change_summary == "Deprecated"
    assert isinstance(record.pop_events()[0], InfrastructureDeprecated)


def test_revoke_transitions_and_emits(now, evidence) -> None:
    record = _observe(now)
    record.pop_events()
    record.revoke(None, evidence, now)
    assert record.lifecycle_status is InfrastructureLifecycleStatus.REVOKED
    assert isinstance(record.pop_events()[0], InfrastructureRevoked)


def test_supersede_sets_superseded_by_and_emits(now, evidence) -> None:
    record = _observe(now)
    record.pop_events()
    successor = InfrastructureId.generate()
    record.supersede(None, successor, evidence, now)
    assert record.lifecycle_status is InfrastructureLifecycleStatus.SUPERSEDED
    assert record.superseded_by == successor
    event = record.pop_events()[0]
    assert isinstance(event, InfrastructureSuperseded)
    assert event.superseded_by == str(successor)


def test_reactivate_from_deprecated_clears_superseded_by_and_emits(now, evidence) -> None:
    record = _observe(now)
    record.deprecate(None, evidence, now)
    record.pop_events()
    record.reactivate(None, evidence, now)
    assert record.lifecycle_status is InfrastructureLifecycleStatus.ACTIVE
    assert record.superseded_by is None
    assert isinstance(record.pop_events()[0], InfrastructureReactivated)


def test_revoked_is_terminal_on_the_aggregate(now, evidence) -> None:
    record = _observe(now)
    record.revoke(None, evidence, now)
    with pytest.raises(InvalidLifecycleTransitionError):
        record.reactivate(None, evidence, now)
    with pytest.raises(InvalidLifecycleTransitionError):
        record.deprecate(None, evidence, now)


def test_a_superseded_record_cannot_be_reactivated(now, evidence) -> None:
    record = _observe(now)
    record.supersede(None, InfrastructureId.generate(), evidence, now)
    with pytest.raises(InvalidLifecycleTransitionError):
        record.reactivate(None, evidence, now)


def test_a_superseded_record_may_still_be_revoked(now, evidence) -> None:
    record = _observe(now)
    record.supersede(None, InfrastructureId.generate(), evidence, now)
    record.revoke(None, evidence, now)
    assert record.lifecycle_status is InfrastructureLifecycleStatus.REVOKED


def test_a_failed_transition_leaves_the_aggregate_untouched(now, evidence) -> None:
    record = _observe(now)
    record.revoke(None, evidence, now)
    record.pop_events()
    versions_before = len(record.version_history)
    with pytest.raises(InvalidLifecycleTransitionError):
        record.deprecate(None, evidence, now)
    assert record.lifecycle_status is InfrastructureLifecycleStatus.REVOKED
    assert len(record.version_history) == versions_before
    assert record.pop_events() == []


# ── Version history ──────────────────────────────────────────────────────


def test_version_history_is_append_only_and_monotonic(now, evidence) -> None:
    record = _observe(now)
    record.set_hosting_provider(None, HostingProviderRef(provider_name="OVH"), now)
    record.set_cloud_provider(None, CloudProviderRef(provider=CloudProvider.AWS), now)
    record.add_region(None, Region(region_code="us-east-1"), now)
    record.set_network_ownership(None, NetworkOwnership(registrant_organization="x"), now)
    record.add_evidence_citation(None, EvidenceCitation("c"), now)
    record.add_source_attribution(None, evidence, now)
    record.deprecate(None, evidence, now)
    record.reactivate(None, evidence, now)

    versions = [v.version for v in record.version_history]
    assert versions == list(range(1, len(versions) + 1))
    assert len(versions) == 9


def test_every_mutator_emits_exactly_one_event(now, evidence) -> None:
    record = _observe(now)
    record.pop_events()
    record.set_hosting_provider(None, HostingProviderRef(provider_name="OVH"), now)
    record.set_cloud_provider(None, CloudProviderRef(provider=CloudProvider.AWS), now)
    record.add_region(None, Region(region_code="us-east-1"), now)
    record.set_network_ownership(None, NetworkOwnership(registrant_organization="x"), now)
    record.add_evidence_citation(None, EvidenceCitation("c"), now)
    record.add_source_attribution(None, evidence, now)
    record.deprecate(None, evidence, now)
    assert len(record.pop_events()) == 7


def test_row_version_is_never_touched_by_domain_behaviour(now, evidence) -> None:
    """`row_version` belongs exclusively to the repository's
    optimistic-concurrency guard — no domain mutator may move it."""
    record = _observe(now)
    record.add_region(None, Region(region_code="us-east-1"), now)
    record.deprecate(None, evidence, now)
    assert record.row_version == 1
