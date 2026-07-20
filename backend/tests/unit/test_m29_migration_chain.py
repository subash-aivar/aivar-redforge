"""Assert M29 Phase 5/6 Alembic revision chain: 0067→0068→0069→0070."""

from __future__ import annotations

import importlib.util
from pathlib import Path


def _load_revision(path: Path) -> tuple[str, str | None]:
    spec = importlib.util.spec_from_file_location(path.stem, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.revision, module.down_revision


def test_m29_phase5_migration_revision_chain() -> None:
    versions = (
        Path(__file__).resolve().parents[2]
        / "src"
        / "redforge"
        / "infrastructure"
        / "database"
        / "migrations"
        / "versions"
    )
    r67, d67 = _load_revision(versions / "0067_execution_pipeline_foundation.py")
    r68, d68 = _load_revision(versions / "0068_evidence_foundation.py")
    r69, d69 = _load_revision(versions / "0069_payload_foundation.py")
    r70, d70 = _load_revision(versions / "0070_m29_read_model_foundation.py")

    assert r67 == "0067"
    assert r68 == "0068" and d68 == "0067"
    assert r69 == "0069" and d69 == "0068"
    assert r70 == "0070" and d70 == "0069"
    assert d67 == "0066"
