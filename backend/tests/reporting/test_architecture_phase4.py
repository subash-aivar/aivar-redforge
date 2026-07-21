from __future__ import annotations

import ast
from pathlib import Path

REPORTING = Path(__file__).resolve().parents[2] / "src" / "reporting"


def test_ibi_export_port_has_no_vendor_impl() -> None:
    text = (REPORTING / "domain/ports/i_bi_export_port.py").read_text().lower()
    assert "tableau" in text  # mentioned as future vendor, interface-only
    assert "class ibiexportport" in text
    # No vendor adapter modules
    acl = REPORTING / "infrastructure" / "acl"
    names = {p.name.lower() for p in acl.glob("*.py")}
    assert "tableau_adapter.py" not in names
    assert "powerbi_adapter.py" not in names
    assert "looker_adapter.py" not in names


def test_no_llm_and_no_exposure_reporting() -> None:
    for path in REPORTING.rglob("*.py"):
        content = path.read_text()
        lowered = content.lower()
        assert "openai" not in lowered
        assert "langchain" not in lowered
        tree = ast.parse(content)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                assert not node.module.startswith("exposure_reporting")
