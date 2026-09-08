from __future__ import annotations

from datetime import timedelta

import pytest

from tool_intel.domain.aggregates.tool import Tool
from tool_intel.domain.events.tool_events import (
    AliasAdded,
    CapabilityAdded,
    EvidenceCitationAdded,
    PlatformAdded,
    SourceAttributionAdded,
    ToolDeprecated,
    ToolObserved,
    ToolReactivated,
    ToolRevoked,
    ToolSuperseded,
)
from tool_intel.domain.exceptions.domain_exceptions import (
    InvalidCanonicalNameError,
    InvalidLifecycleTransitionError,
    TenantMismatchError,
)
from tool_intel.domain.factories.tool_factory import ToolFactory
from tool_intel.domain.value_objects.enums import (
    ToolCapability,
    ToolCategory,
    ToolConfidence,
    ToolLifecycleStatus,
    ToolPlatform,
)
from tool_intel.domain.value_objects.evidence import EvidenceCitation
from tool_intel.domain.value_objects.identifiers import ToolId
from tool_intel.domain.value_objects.taxonomy import ToolAlias, ToolFamily


def _observe(now, tenant_id=None, canonical_name="mimikatz", **kwargs) -> Tool:
    return ToolFactory().observe(
        tenant_id=tenant_id, canonical_name=canonical_name, now=now, **kwargs
    )


# ── Construction ─────────────────────────────────────────────────────────


def test_observe_sets_active_lifecycle_and_first_version(now) -> None:
    tool = _observe(now)
    assert tool.lifecycle_status is ToolLifecycleStatus.ACTIVE
    assert tool.created_at == now
    assert tool.updated_at == now
    assert tool.row_version == 1
    assert len(tool.version_history) == 1
    assert tool.version_history[0].version == 1
    assert tool.version_history[0].change_summary == "Observed"
    assert tool.version_history[0].source == "tool_intel"


def test_observe_normalizes_canonical_name_at_construction(now) -> None:
    tool = _observe(now, canonical_name="  Cobalt-Strike  ")
    assert tool.canonical_name == "cobalt strike"


def test_observe_rejects_an_unnormalizable_canonical_name(now) -> None:
    with pytest.raises(InvalidCanonicalNameError):
        _observe(now, canonical_name="   ")


def test_observe_defaults_are_conservative(now) -> None:
    tool = _observe(now)
    assert tool.category is ToolCategory.OTHER
    assert tool.confidence is ToolConfidence.MEDIUM
    assert tool.family is None
    assert tool.aliases == ()
    assert tool.platforms == ()
    assert tool.capabilities == ()
    assert tool.superseded_by is None


def test_observe_accepts_the_full_initial_shape(now) -> None:
    tool = _observe(
        now,
        canonical_name="cobalt strike",
        category=ToolCategory.COMMAND_AND_CONTROL_FRAMEWORK,
        family=ToolFamily(family_name="Cobalt Strike"),
        aliases=(ToolAlias("beacon"),),
        platforms=(ToolPlatform.WINDOWS, ToolPlatform.LINUX),
        capabilities=(ToolCapability.COMMAND_AND_CONTROL,),
        confidence=ToolConfidence.VERY_HIGH,
    )
    assert tool.category is ToolCategory.COMMAND_AND_CONTROL_FRAMEWORK
    assert tool.family is not None
    assert tool.family.family_name == "Cobalt Strike"
    assert tool.platforms == (ToolPlatform.WINDOWS, ToolPlatform.LINUX)
    assert tool.capabilities == (ToolCapability.COMMAND_AND_CONTROL,)
    assert tool.confidence is ToolConfidence.VERY_HIGH


def test_observe_emits_tool_observed_with_payload(now) -> None:
    tool = _observe(
        now,
        canonical_name="cobalt strike",
        category=ToolCategory.COMMAND_AND_CONTROL_FRAMEWORK,
        family=ToolFamily(family_name="Cobalt Strike"),
    )
    events = tool.pop_events()
    assert len(events) == 1
    event = events[0]
    assert isinstance(event, ToolObserved)
    assert event.canonical_name == "cobalt strike"
    assert event.category == "command_and_control_framework"
    assert event.family == "Cobalt Strike"
    assert event.aggregate_type == "Tool"
    assert event.aggregate_id == str(tool.tool_id)


def test_a_global_record_renders_empty_tenant_in_events(now) -> None:
    tool = _observe(now, tenant_id=None)
    assert tool.pop_events()[0].tenant_id == ""


def test_a_tenant_record_renders_its_tenant_in_events(now, tenant_id) -> None:
    tool = _observe(now, tenant_id=tenant_id)
    assert tool.pop_events()[0].tenant_id == str(tenant_id)


def test_pop_events_drains_the_pending_list(now) -> None:
    tool = _observe(now)
    assert len(tool.pop_events()) == 1
    assert tool.pop_events() == []


# ── Enrichment ───────────────────────────────────────────────────────────


def test_add_alias_appends_records_a_version_and_emits(now) -> None:
    tool = _observe(now)
    tool.pop_events()
    later = now + timedelta(hours=1)
    tool.add_alias(None, ToolAlias("mimilib"), later)

    assert tool.aliases == (ToolAlias("mimilib"),)
    assert len(tool.version_history) == 2
    assert tool.version_history[1].change_summary == "Alias added: mimilib"
    assert tool.updated_at == later
    events = tool.pop_events()
    assert isinstance(events[0], AliasAdded)
    assert events[0].alias == "mimilib"


def test_add_alias_is_idempotent_on_the_collection(now) -> None:
    tool = _observe(now)
    tool.add_alias(None, ToolAlias("mimilib"), now)
    tool.add_alias(None, ToolAlias("mimilib"), now)
    assert tool.aliases == (ToolAlias("mimilib"),)
    # Every mutator still records a version, even when the collection
    # was already satisfied — the assertion itself is the event.
    assert len(tool.version_history) == 3


def test_add_platform_appends_and_emits(now) -> None:
    tool = _observe(now)
    tool.pop_events()
    tool.add_platform(None, ToolPlatform.WINDOWS, now)
    assert tool.platforms == (ToolPlatform.WINDOWS,)
    events = tool.pop_events()
    assert isinstance(events[0], PlatformAdded)
    assert events[0].platform == "windows"


def test_add_platform_is_idempotent_on_the_collection(now) -> None:
    tool = _observe(now)
    tool.add_platform(None, ToolPlatform.WINDOWS, now)
    tool.add_platform(None, ToolPlatform.WINDOWS, now)
    assert tool.platforms == (ToolPlatform.WINDOWS,)


def test_add_capability_appends_and_emits(now) -> None:
    tool = _observe(now)
    tool.pop_events()
    tool.add_capability(None, ToolCapability.CREDENTIAL_DUMPING, now)
    assert tool.capabilities == (ToolCapability.CREDENTIAL_DUMPING,)
    events = tool.pop_events()
    assert isinstance(events[0], CapabilityAdded)
    assert events[0].capability == "credential_dumping"


def test_add_capability_is_idempotent_on_the_collection(now) -> None:
    tool = _observe(now)
    tool.add_capability(None, ToolCapability.PERSISTENCE, now)
    tool.add_capability(None, ToolCapability.PERSISTENCE, now)
    assert tool.capabilities == (ToolCapability.PERSISTENCE,)


def test_add_evidence_citation_appends_and_emits(now) -> None:
    tool = _observe(now)
    tool.pop_events()
    tool.add_evidence_citation(None, EvidenceCitation("https://vendor/report"), now)
    assert len(tool.evidence_citations) == 1
    events = tool.pop_events()
    assert isinstance(events[0], EvidenceCitationAdded)
    assert events[0].citation == "https://vendor/report"


def test_evidence_citations_are_append_only_and_allow_duplicates(now) -> None:
    """Two independent sources citing the same URL is real signal —
    citations are an append-only log, not a set."""
    tool = _observe(now)
    citation = EvidenceCitation("https://vendor/report")
    tool.add_evidence_citation(None, citation, now)
    tool.add_evidence_citation(None, citation, now)
    assert len(tool.evidence_citations) == 2


def test_add_source_attribution_records_the_source_system_as_version_source(now, evidence) -> None:
    tool = _observe(now)
    tool.pop_events()
    tool.add_source_attribution(None, evidence, now)
    assert tool.source_attributions == (evidence,)
    assert tool.version_history[-1].source == "redforge-analyst"
    events = tool.pop_events()
    assert isinstance(events[0], SourceAttributionAdded)
    assert events[0].source_system == "redforge-analyst"
    assert events[0].confidence == "high"


# ── Tenant isolation ─────────────────────────────────────────────────────


def test_every_mutator_rejects_a_foreign_tenant(now, tenant_id, evidence) -> None:
    from tool_intel.domain.value_objects.identifiers import TenantId

    tool = _observe(now, tenant_id=tenant_id)
    foreign = TenantId.generate()

    with pytest.raises(TenantMismatchError):
        tool.add_alias(foreign, ToolAlias("x"), now)
    with pytest.raises(TenantMismatchError):
        tool.add_platform(foreign, ToolPlatform.LINUX, now)
    with pytest.raises(TenantMismatchError):
        tool.add_capability(foreign, ToolCapability.EXECUTION, now)
    with pytest.raises(TenantMismatchError):
        tool.add_evidence_citation(foreign, EvidenceCitation("c"), now)
    with pytest.raises(TenantMismatchError):
        tool.add_source_attribution(foreign, evidence, now)
    with pytest.raises(TenantMismatchError):
        tool.deprecate(foreign, evidence, now)
    with pytest.raises(TenantMismatchError):
        tool.revoke(foreign, evidence, now)
    with pytest.raises(TenantMismatchError):
        tool.supersede(foreign, ToolId.generate(), evidence, now)


def test_a_global_record_rejects_a_tenant_actor(now, tenant_id, evidence) -> None:
    tool = _observe(now, tenant_id=None)
    with pytest.raises(TenantMismatchError):
        tool.deprecate(tenant_id, evidence, now)


def test_a_tenant_record_rejects_a_global_actor(now, tenant_id, evidence) -> None:
    tool = _observe(now, tenant_id=tenant_id)
    with pytest.raises(TenantMismatchError):
        tool.deprecate(None, evidence, now)


# ── Record lifecycle ─────────────────────────────────────────────────────


def test_deprecate_transitions_and_emits(now, evidence) -> None:
    tool = _observe(now)
    tool.pop_events()
    tool.deprecate(None, evidence, now)
    assert tool.lifecycle_status is ToolLifecycleStatus.DEPRECATED
    assert tool.version_history[-1].change_summary == "Deprecated"
    assert isinstance(tool.pop_events()[0], ToolDeprecated)


def test_revoke_transitions_and_emits(now, evidence) -> None:
    tool = _observe(now)
    tool.pop_events()
    tool.revoke(None, evidence, now)
    assert tool.lifecycle_status is ToolLifecycleStatus.REVOKED
    assert isinstance(tool.pop_events()[0], ToolRevoked)


def test_supersede_sets_superseded_by_and_emits(now, evidence) -> None:
    tool = _observe(now)
    tool.pop_events()
    successor = ToolId.generate()
    tool.supersede(None, successor, evidence, now)
    assert tool.lifecycle_status is ToolLifecycleStatus.SUPERSEDED
    assert tool.superseded_by == successor
    event = tool.pop_events()[0]
    assert isinstance(event, ToolSuperseded)
    assert event.superseded_by == str(successor)


def test_reactivate_from_deprecated_clears_superseded_by_and_emits(now, evidence) -> None:
    tool = _observe(now)
    tool.deprecate(None, evidence, now)
    tool.pop_events()
    tool.reactivate(None, evidence, now)
    assert tool.lifecycle_status is ToolLifecycleStatus.ACTIVE
    assert tool.superseded_by is None
    assert isinstance(tool.pop_events()[0], ToolReactivated)


def test_revoked_is_terminal_on_the_aggregate(now, evidence) -> None:
    tool = _observe(now)
    tool.revoke(None, evidence, now)
    with pytest.raises(InvalidLifecycleTransitionError):
        tool.reactivate(None, evidence, now)
    with pytest.raises(InvalidLifecycleTransitionError):
        tool.deprecate(None, evidence, now)


def test_a_superseded_record_cannot_be_reactivated(now, evidence) -> None:
    tool = _observe(now)
    tool.supersede(None, ToolId.generate(), evidence, now)
    with pytest.raises(InvalidLifecycleTransitionError):
        tool.reactivate(None, evidence, now)


def test_a_superseded_record_may_still_be_revoked(now, evidence) -> None:
    tool = _observe(now)
    tool.supersede(None, ToolId.generate(), evidence, now)
    tool.revoke(None, evidence, now)
    assert tool.lifecycle_status is ToolLifecycleStatus.REVOKED


def test_a_failed_transition_leaves_the_aggregate_untouched(now, evidence) -> None:
    tool = _observe(now)
    tool.revoke(None, evidence, now)
    tool.pop_events()
    versions_before = len(tool.version_history)
    with pytest.raises(InvalidLifecycleTransitionError):
        tool.deprecate(None, evidence, now)
    assert tool.lifecycle_status is ToolLifecycleStatus.REVOKED
    assert len(tool.version_history) == versions_before
    assert tool.pop_events() == []


# ── Version history ──────────────────────────────────────────────────────


def test_version_history_is_append_only_and_monotonic(now, evidence) -> None:
    tool = _observe(now)
    tool.add_alias(None, ToolAlias("a"), now)
    tool.add_platform(None, ToolPlatform.LINUX, now)
    tool.add_capability(None, ToolCapability.DISCOVERY, now)
    tool.add_evidence_citation(None, EvidenceCitation("c"), now)
    tool.add_source_attribution(None, evidence, now)
    tool.deprecate(None, evidence, now)
    tool.reactivate(None, evidence, now)

    versions = [v.version for v in tool.version_history]
    assert versions == list(range(1, len(versions) + 1))
    assert len(versions) == 8


def test_every_mutator_emits_exactly_one_event(now, evidence) -> None:
    tool = _observe(now)
    tool.pop_events()
    tool.add_alias(None, ToolAlias("a"), now)
    tool.add_platform(None, ToolPlatform.LINUX, now)
    tool.add_capability(None, ToolCapability.DISCOVERY, now)
    tool.add_evidence_citation(None, EvidenceCitation("c"), now)
    tool.add_source_attribution(None, evidence, now)
    tool.deprecate(None, evidence, now)
    assert len(tool.pop_events()) == 6


def test_row_version_is_never_touched_by_domain_behaviour(now, evidence) -> None:
    """`row_version` belongs exclusively to the repository's
    optimistic-concurrency guard — no domain mutator may move it."""
    tool = _observe(now)
    tool.add_alias(None, ToolAlias("a"), now)
    tool.deprecate(None, evidence, now)
    assert tool.row_version == 1
