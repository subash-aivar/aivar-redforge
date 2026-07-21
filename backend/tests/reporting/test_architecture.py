"""Architecture constraints for reporting BC (M33 Phase 2 / ADR-M33-001)."""

from __future__ import annotations

import ast
from pathlib import Path

RI = Path(__file__).resolve().parents[2] / "src" / "reporting"

FORBIDDEN_IMPORT_PREFIXES = (
    "exposure_reporting",
    "openai",
)


def _imports(path: Path) -> list[str]:
    tree = ast.parse(path.read_text())
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.append(node.module)
    return names


def test_layout() -> None:
    assert (RI / "domain/aggregates/report_template.py").exists()
    assert (RI / "domain/aggregates/scheduled_report.py").exists()
    assert (RI / "domain/aggregates/report_instance.py").exists()
    assert (RI / "domain/services/report_generation_service.py").exists()
    assert (RI / "domain/services/scheduled_report_service.py").exists()
    assert (RI / "domain/ports/i_analytics_kpi_query_port.py").exists()
    assert (RI / "domain/ports/i_ml_signal_query_port.py").exists()
    assert (RI / "domain/ports/i_report_delivery_port.py").exists()
    assert (RI / "infrastructure/workers/report_scheduler_worker.py").exists()
    assert (RI / "infrastructure/container.py").exists()
    assert (RI / "api/v1/routes.py").exists()
    assert (RI / "api/dependencies.py").exists()
    assert (RI / "py.typed").exists()


def test_no_exposure_reporting_imports() -> None:
    for path in RI.rglob("*.py"):
        for name in _imports(path):
            assert not name.startswith("exposure_reporting"), f"{path} imports {name}"


def test_no_llm_dependency_in_reporting_bc() -> None:
    for path in RI.rglob("*.py"):
        text = path.read_text().lower()
        assert "openai" not in text, f"{path} references openai"
        for name in _imports(path):
            assert not name.startswith("openai"), f"{path} imports {name}"
            assert "llm" not in name.lower(), f"{path} imports {name}"

    gen = (RI / "domain/services/report_generation_service.py").read_text()
    assert "ADR-M33-001" in gen
    assert "NO LLM" in gen or "no LLM" in gen.lower() or "no llm" in gen.lower()


def test_analytics_domain_imports_only_in_acl() -> None:
    for path in RI.rglob("*.py"):
        if "acl" in path.parts:
            continue
        for name in _imports(path):
            assert not name.startswith("analytics.domain"), (
                f"{path} imports analytics.domain outside ACL: {name}"
            )


def test_router_export() -> None:
    from reporting.api.v1 import router

    assert router.prefix == "/reporting"
