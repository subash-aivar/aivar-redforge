from __future__ import annotations

import ast
from pathlib import Path
from uuid import uuid4

import pytest

from campaign.domain.ports.i_exposure_scope_query_port import ExposureScopeRequest
from campaign.infrastructure.acl.exposure_scope_m32_adapter import ExposureScopeM32Adapter
from exposure.application.commands.exposure_commands import IngestVulnerabilitySignalCommand
from exposure.infrastructure.container import ExposureContainer
from exposure.infrastructure.persistence.in_memory_unit_of_work import InMemoryUnitOfWork
from redforge.shared.identifiers import EntityId

RI = Path(__file__).resolve().parents[2] / "src" / "remediation_impact"


def _imports(path: Path) -> list[str]:
    tree = ast.parse(path.read_text())
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.append(node.module)
    return names


def test_remediation_impact_layout() -> None:
    assert (RI / "domain/aggregates/exposure_reduction_plan.py").exists()
    assert (RI / "domain/services/greedy_marginal_contribution.py").exists()
    assert (RI / "api/v1/routes.py").exists()


def test_no_exposure_domain_outside_acl() -> None:
    for path in RI.rglob("*.py"):
        if "acl" in path.parts:
            continue
        for name in _imports(path):
            assert not name.startswith("exposure.domain"), f"{path} imports {name}"


@pytest.mark.asyncio
async def test_m30_scope_adapter_contract() -> None:
    uow = InMemoryUnitOfWork()
    container = ExposureContainer(uow_factory=lambda: uow)
    tenant = EntityId.generate()
    asset = uuid4()
    await container.ingestion.ingest_vulnerability(
        IngestVulnerabilitySignalCommand(
            tenant_id=tenant,
            event_id="scope-m30",
            vulnerability_instance_id="vi-m30",
            asset_ref_id=asset,
            cvss_base=8.0,
            is_kev=True,
            technique_refs=(),
            cve_ids=("CVE-M30",),
            actor_roles=("exposure:analyst",),
        )
    )
    await container.score_worker.run_pipeline_once(
        container.debouncer, container.dispatcher, debounce_seconds=0
    )
    adapter = ExposureScopeM32Adapter(container.scope_service)
    resp = await adapter.query_scope(ExposureScopeRequest(tenant_id=tenant, max_assets=50))
    assert resp.tenant_id == str(tenant)
    assert resp.total_eligible >= 1
    assert resp.query_duration_ms >= 0
