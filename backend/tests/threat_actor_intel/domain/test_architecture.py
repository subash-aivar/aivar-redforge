from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3] / "src" / "threat_actor_intel"
FORBIDDEN_CONTEXT_IMPORT = re.compile(
    r"^\s*(from|import)\s+(cloud_security|ai_posture|ai_security|exposure|"
    r"redforge\.domain\.threat_intel|redforge\.application\.threat_intel|"
    r"vulnerability|vulnerability_engine|integration_hub|risk_engine|"
    r"attack_surface_management|credential_vault|detection|siem_detection)\b",
    re.M,
)
# `redforge.domain.identity`/`redforge.api.security` (platform RBAC —
# `Permission`, `TenantContext`, `require_permission`) and
# `redforge.shared`/`redforge.infrastructure.database.base` are the
# platform's genuinely shared kernel, not another bounded context's
# private domain — every mature context's own API/infrastructure layer
# depends on them the same way (see e.g. `risk_engine.api.v1.
# risk_profiles`'s own `from redforge.domain.identity.value_objects
# import Permission`). Only `redforge.domain.threat_intel` (the legacy
# M21 module) is forbidden, per ADR-M51.1-01 — never a blanket ban on
# all of `redforge.domain`.


def test_layout_has_domain_layer_only() -> None:
    assert (ROOT / "domain" / "aggregates").is_dir()
    assert (ROOT / "domain" / "value_objects").is_dir()
    assert (ROOT / "domain" / "events").is_dir()
    assert (ROOT / "domain" / "exceptions").is_dir()
    assert (ROOT / "domain" / "specifications").is_dir()
    assert (ROOT / "domain" / "policies").is_dir()
    assert (ROOT / "domain" / "factories").is_dir()


def test_application_infrastructure_and_api_layers_all_exist() -> None:
    """M51.1 Phase 2 added application; Phase 3 added infrastructure;
    Phase 4 adds api (see ADR-M51.1-01 through -10 and the M51.1
    Repository Impact Analysis's phased sequence) — see
    `tests/threat_actor_intel/api/test_architecture.py` for that
    layer's own boundary checks."""
    assert (ROOT / "application").is_dir()
    assert (ROOT / "infrastructure").is_dir()
    assert (ROOT / "api").is_dir()


def test_no_entities_or_domain_services_directory() -> None:
    """No entity or domain-service directory exists — the M51A final
    report explains why neither was justified by the single-aggregate
    scope of this milestone (see the report's "why no domain service"
    section)."""
    assert not (ROOT / "domain" / "entities").exists()
    assert not (ROOT / "domain" / "services").exists()


def test_context_does_not_import_forbidden_bounded_contexts() -> None:
    """M51A's explicit boundary: threat_actor_intel must never import
    from any other bounded context — including
    `redforge.domain.threat_intel`, whose `AttackTechnique`/
    `FusedIndicator` are referenced only via opaque id value objects
    (`AttackTechniqueReference`/`FusedIndicatorReference`), never
    imported directly. Only the truly-shared `redforge.shared` is
    legitimate to reuse."""
    for path in ROOT.rglob("*.py"):
        text = path.read_text()
        match = FORBIDDEN_CONTEXT_IMPORT.search(text)
        if match:
            raise AssertionError(
                f"{path} imports a forbidden bounded-context module: {match.group()}"
            )


def test_no_infrastructure_imports_in_domain_layer() -> None:
    infra_import = re.compile(
        r"^\s*(from|import)\s+(fastapi|sqlalchemy|asyncpg|alembic|redis|celery|kafka)\b", re.M
    )
    for path in (ROOT / "domain").rglob("*.py"):
        text = path.read_text()
        if infra_import.search(text):
            raise AssertionError(f"{path} imports infrastructure from the domain layer")


def test_no_infrastructure_imports_in_application_layer() -> None:
    """M51.1 Phase 2: the application layer defines ports only — no
    concrete FastAPI/ORM/broker dependency exists until Phase 3/4."""
    infra_import = re.compile(
        r"^\s*(from|import)\s+(fastapi|sqlalchemy|asyncpg|alembic|redis|celery|kafka)\b", re.M
    )
    for path in (ROOT / "application").rglob("*.py"):
        text = path.read_text()
        if infra_import.search(text):
            raise AssertionError(f"{path} imports infrastructure from the application layer")


def test_uses_shared_kernel_tenant_id() -> None:
    text = (ROOT / "domain" / "value_objects" / "identifiers.py").read_text()
    assert "from redforge.shared.identifiers import EntityId" in text
    assert "TenantId = EntityId" in text


def test_no_blanket_type_ignore_suppressions() -> None:
    banned = re.compile(r"#\s*type:\s*ignore\s*(?!\[)")
    for path in ROOT.rglob("*.py"):
        text = path.read_text()
        match = banned.search(text)
        if match:
            raise AssertionError(f"{path} uses a blanket '# type: ignore': {match.group()}")
