import ast
from pathlib import Path

AGENT = Path(__file__).resolve().parents[2] / "src" / "ai_agent_governance"


def _imports(path: Path) -> list[str]:
    tree = ast.parse(path.read_text())
    names: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            names.append(node.module)
    return names


def test_no_ai_posture_domain_application_imports() -> None:
    for path in AGENT.rglob("*.py"):
        for name in _imports(path):
            assert not name.startswith("ai_posture.domain")
            assert not name.startswith("ai_posture.application")
