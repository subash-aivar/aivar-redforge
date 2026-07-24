from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2] / "src" / "siem_shared"
SIEM_CONTEXT_IMPORT = re.compile(
    r"from (siem_ingestion|siem_normalization|siem_storage|siem_detection|"
    r"siem_correlation|siem_investigation|siem_alerting|siem_search|siem_analytics)\."
)
INFRA_IMPORT = re.compile(r"from (fastapi|sqlalchemy|asyncpg|alembic)\b")


def test_layout() -> None:
    assert (ROOT / "domain" / "value_objects").is_dir()
    assert (ROOT / "domain" / "services").is_dir()
    assert (ROOT / "domain" / "exceptions").is_dir()


def test_shared_kernel_depends_on_no_siem_context() -> None:
    """siem_shared is the shared kernel — it must never depend on any
    downstream siem_* bounded context (M37 §1)."""
    for path in ROOT.rglob("*.py"):
        text = path.read_text()
        if SIEM_CONTEXT_IMPORT.search(text):
            raise AssertionError(f"{path} imports a downstream siem_* context")


def test_shared_kernel_has_no_infrastructure_imports() -> None:
    """The shared kernel contains only value objects and versioning
    contracts — no behavior, no infrastructure (M37 §1)."""
    for path in ROOT.rglob("*.py"):
        text = path.read_text()
        if INFRA_IMPORT.search(text):
            raise AssertionError(f"{path} imports infrastructure")


def test_only_permitted_cross_context_import_is_integration_hub() -> None:
    """M41 ADR-G6 permits (requires) reusing Integration Hub's
    `RelationshipType` verbatim. No other existing bounded context may
    be imported from the shared kernel — everything else it needs is
    either local or from `redforge.shared`."""
    cross_context_import = re.compile(r"^\s*from ([a-z_]+)\.", re.MULTILINE)
    allowed = {"redforge", "siem_shared", "integration_hub"} | set(sys.stdlib_module_names)
    for path in ROOT.rglob("*.py"):
        for match in cross_context_import.finditer(path.read_text()):
            module = match.group(1)
            if module not in allowed:
                raise AssertionError(f"{path} imports disallowed cross-context module {module!r}")


def test_canonical_event_has_no_mutator_methods() -> None:
    """CanonicalEvent is immutable and append-only (M37 §2.1) — it must
    expose no method that changes its own state, only construction and
    serialization."""
    text = (ROOT / "domain" / "value_objects" / "canonical_event.py").read_text()
    method_defs = re.findall(r"^\s{4}def (\w+)\(self", text, re.MULTILINE)
    allowed_methods = {"to_dict"}
    assert set(method_defs) <= allowed_methods, method_defs
