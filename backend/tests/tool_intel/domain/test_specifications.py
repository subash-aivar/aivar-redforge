from __future__ import annotations

from tool_intel.domain.factories.tool_factory import ToolFactory
from tool_intel.domain.specifications.tool_specifications import (
    ActiveToolSpecification,
    DeprecatedOrRevokedToolSpecification,
    IsGlobalToolSpecification,
    IsTenantToolSpecification,
    SupersededToolSpecification,
)
from tool_intel.domain.value_objects.identifiers import ToolId


def test_active_specification_matches_a_freshly_observed_tool(now) -> None:
    tool = ToolFactory().observe(tenant_id=None, canonical_name="mimikatz", now=now)
    assert ActiveToolSpecification().is_satisfied_by(tool)
    assert not DeprecatedOrRevokedToolSpecification().is_satisfied_by(tool)
    assert not SupersededToolSpecification().is_satisfied_by(tool)


def test_deprecated_or_revoked_specification(now, evidence) -> None:
    deprecated = ToolFactory().observe(tenant_id=None, canonical_name="a tool", now=now)
    deprecated.deprecate(None, evidence, now)
    revoked = ToolFactory().observe(tenant_id=None, canonical_name="b tool", now=now)
    revoked.revoke(None, evidence, now)

    spec = DeprecatedOrRevokedToolSpecification()
    assert spec.is_satisfied_by(deprecated)
    assert spec.is_satisfied_by(revoked)
    assert not ActiveToolSpecification().is_satisfied_by(deprecated)
    assert not ActiveToolSpecification().is_satisfied_by(revoked)


def test_superseded_specification(now, evidence) -> None:
    tool = ToolFactory().observe(tenant_id=None, canonical_name="old tool", now=now)
    tool.supersede(None, ToolId.generate(), evidence, now)
    assert SupersededToolSpecification().is_satisfied_by(tool)
    assert not DeprecatedOrRevokedToolSpecification().is_satisfied_by(tool)


def test_scope_specifications(now, tenant_id) -> None:
    global_tool = ToolFactory().observe(tenant_id=None, canonical_name="g tool", now=now)
    tenant_tool = ToolFactory().observe(tenant_id=tenant_id, canonical_name="t tool", now=now)

    assert IsGlobalToolSpecification().is_satisfied_by(global_tool)
    assert not IsGlobalToolSpecification().is_satisfied_by(tenant_tool)
    assert IsTenantToolSpecification().is_satisfied_by(tenant_tool)
    assert not IsTenantToolSpecification().is_satisfied_by(global_tool)


def test_reactivation_restores_the_active_specification(now, evidence) -> None:
    tool = ToolFactory().observe(tenant_id=None, canonical_name="c tool", now=now)
    tool.deprecate(None, evidence, now)
    assert not ActiveToolSpecification().is_satisfied_by(tool)
    tool.reactivate(None, evidence, now)
    assert ActiveToolSpecification().is_satisfied_by(tool)
