"""Base class for JSON-backed FrameworkDefinitionPort adapters."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from redforge.domain.compliance.value_objects import FrameworkKey


class JsonFrameworkAdapter:
    """Loads framework metadata and requirements from a bundled JSON fixture.

    Subclasses only need to declare ``_FRAMEWORK_KEY`` and the fixture
    filename.  The fixture lives in
    ``infrastructure/compliance/fixtures/<filename>.json``.
    """

    _FRAMEWORK_KEY: FrameworkKey
    _FIXTURE_NAME: str

    @property
    def framework_key(self) -> FrameworkKey:
        return self._FRAMEWORK_KEY

    def _load_fixture(self) -> dict[str, Any]:
        fixtures_dir = Path(__file__).parent.parent / "fixtures"
        path = fixtures_dir / self._FIXTURE_NAME
        with path.open(encoding="utf-8") as fh:
            data: dict[str, Any] = json.load(fh)
            return data

    def load_metadata(self) -> dict[str, Any]:
        result: dict[str, Any] = self._load_fixture()["metadata"]
        return result

    def load_requirements(self) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = self._load_fixture()["requirements"]
        return result
