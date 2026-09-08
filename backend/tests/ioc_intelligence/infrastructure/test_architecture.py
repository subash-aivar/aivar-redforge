from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3] / "src" / "ioc_intelligence"
LEGACY_ROOT = Path(__file__).resolve().parents[3] / "src" / "redforge"

_INFRA_IMPORT = re.compile(
    r"^\s*(from|import)\s+(fastapi|sqlalchemy|asyncpg|alembic|redis|celery|kafka)\b", re.M
)
_IOC_INFRA_IMPORT = re.compile(r"^\s*(from|import)\s+ioc_intelligence\.infrastructure\b", re.M)
_LEGACY_ORM_IMPORT = re.compile(
    r"^\s*(from|import)\s+redforge\.infrastructure\.database\.models\.threat_intel\b"
    r"|^\s*(from|import)\s+redforge\.infrastructure\.database\.repositories"
    r"\.threat_intel_repository\b",
    re.M,
)
_IOC_ORM_IMPORT = re.compile(
    r"^\s*(from|import)\s+ioc_intelligence\.infrastructure\.persistence\b", re.M
)


def test_infrastructure_layer_exists() -> None:
    assert (ROOT / "infrastructure").is_dir()


def test_no_orm_or_infra_imports_in_domain_layer() -> None:
    for path in (ROOT / "domain").rglob("*.py"):
        text = path.read_text()
        if _INFRA_IMPORT.search(text):
            raise AssertionError(f"{path} imports infrastructure from the domain layer")


def test_no_orm_or_infra_imports_in_application_layer() -> None:
    for path in (ROOT / "application").rglob("*.py"):
        text = path.read_text()
        if _INFRA_IMPORT.search(text):
            raise AssertionError(f"{path} imports infrastructure from the application layer")


def test_domain_never_imports_ioc_infrastructure() -> None:
    for path in (ROOT / "domain").rglob("*.py"):
        text = path.read_text()
        if _IOC_INFRA_IMPORT.search(text):
            raise AssertionError(f"{path} imports ioc_intelligence.infrastructure from domain")


def test_application_never_imports_ioc_infrastructure() -> None:
    for path in (ROOT / "application").rglob("*.py"):
        text = path.read_text()
        if _IOC_INFRA_IMPORT.search(text):
            raise AssertionError(f"{path} imports ioc_intelligence.infrastructure from application")


def test_api_layer_exists() -> None:
    """M51.2 Phase A4 adds the API layer."""
    assert (ROOT / "api").is_dir()


def test_no_legacy_orm_imports_in_ioc_domain_or_application() -> None:
    """M51.2 Phase A5: `redforge.infrastructure.database.models.
    threat_intel`/`...repositories.threat_intel_repository` may only be
    imported from `ioc_intelligence.infrastructure.acl` (the ACL
    adapters that exist precisely to translate them) — never from IOC's
    own domain or application layer."""
    for layer in ("domain", "application"):
        for path in (ROOT / layer).rglob("*.py"):
            text = path.read_text()
            if _LEGACY_ORM_IMPORT.search(text):
                raise AssertionError(f"{path} imports legacy threat_intel ORM/repository directly")


def test_no_ioc_persistence_imports_in_legacy_threat_intel_domain_or_application() -> None:
    """The reverse direction: `redforge.domain.threat_intel`/
    `redforge.application.threat_intel` must never import
    `ioc_intelligence.infrastructure.persistence` — legacy threat_intel
    remains an input source, not aware of IOC's own persistence at
    all."""
    for subpath in ("domain/threat_intel", "application/threat_intel"):
        directory = LEGACY_ROOT / subpath
        if not directory.is_dir():
            continue
        for path in directory.rglob("*.py"):
            text = path.read_text()
            if _IOC_ORM_IMPORT.search(text):
                raise AssertionError(f"{path} imports ioc_intelligence persistence directly")
