"""M22 Phase 6 — ATT&CK Navigator export size cap."""

from __future__ import annotations

from redforge.application.threat_intel.navigator_export_service import (
    MAX_TECHNIQUES_IN_LAYER,
    AttackNavigatorExportService,
    NavigatorLayer,
)


def test_navigator_json_shape_and_cap_constant() -> None:
    assert MAX_TECHNIQUES_IN_LAYER == 400
    service = AttackNavigatorExportService(session_factory=None)  # type: ignore[arg-type]
    layer = NavigatorLayer(
        name="Test",
        domain="enterprise-attack",
        versions={"attack": "14", "navigator": "4.9", "layer": "4.5"},
        techniques=[
            {
                "techniqueID": "T1059",
                "score": 3.0,
                "color": "",
                "comment": "",
                "enabled": True,
                "metadata": [],
                "links": [],
                "showSubtechniques": False,
            }
        ],
        truncated=False,
    )
    payload = service.to_navigator_json(layer)
    assert payload["domain"] == "enterprise-attack"
    assert payload["techniques"][0]["techniqueID"] == "T1059"
    assert "versions" in payload
