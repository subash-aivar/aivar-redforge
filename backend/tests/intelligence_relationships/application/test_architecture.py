from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3] / "src" / "intelligence_relationships"

_INFRA_IMPORT = re.compile(
    r"^\s*(from|import)\s+(fastapi|sqlalchemy|asyncpg|alembic|redis|celery|kafka)\b", re.M
)


def test_application_layer_exists() -> None:
    assert (ROOT / "application").is_dir()


def test_no_infrastructure_imports_in_application_layer() -> None:
    for path in (ROOT / "application").rglob("*.py"):
        text = path.read_text()
        if _INFRA_IMPORT.search(text):
            raise AssertionError(f"{path} imports infrastructure from the application layer")


def test_application_service_does_not_import_orm_or_concrete_adapters() -> None:
    service_file = ROOT / "application" / "services" / "relationship_application_service.py"
    text = service_file.read_text()
    import_lines = "\n".join(
        line for line in text.splitlines() if line.strip().startswith(("import ", "from "))
    )
    assert "sqlalchemy" not in import_lines.lower()
    assert "fastapi" not in import_lines.lower()
    assert "infrastructure" not in import_lines.lower()


def test_acl_ports_are_read_only_existence_checks() -> None:
    """The three cross-context ACL ports expose exactly one method —
    `exists` — and nothing that could mutate another context."""
    from intelligence_relationships.application.ports.i_attack_pattern_identity_port import (
        IAttackPatternIdentityPort,
    )
    from intelligence_relationships.application.ports.i_ioc_identity_port import (
        IIocIdentityPort,
    )
    from intelligence_relationships.application.ports.i_threat_actor_identity_port import (
        IThreatActorIdentityPort,
    )

    for port in (IIocIdentityPort, IThreatActorIdentityPort, IAttackPatternIdentityPort):
        assert port.__abstractmethods__ == frozenset({"exists"})


def test_dtos_carry_only_primitives() -> None:
    """No domain value object or aggregate reference may cross the
    application boundary."""
    dto_text = (ROOT / "application" / "dtos" / "relationship_dtos.py").read_text()
    assert "intelligence_relationships.domain" not in dto_text
