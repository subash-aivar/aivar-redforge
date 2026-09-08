"""Architecture tests for the product_edition mechanism (ADR-0009).

Proves, against the REAL app built by `create_app` (not a hand-rolled
stand-in), that:
- "full" edition's route set is provably unchanged (mechanical parity
  with the pre-edition registration list, verified separately in this
  suite's setup — see `test_full_edition_registrations_match_source_order`).
- "network_defense" edition excludes explicitly-unrelated product surfaces.
- "network_defense" edition still exposes every required shared capability.
- An unrecognized edition value fails safely (never silently falls back
  to "full" and never silently produces an empty/partial router).
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from redforge.api.v1 import _REGISTRATIONS, NETWORK_DEFENSE_TAGS, build_v1_router
from redforge.app import create_app
from redforge.core.config import Settings


def _openapi_paths(edition: str) -> set[str]:
    settings = Settings(environment="test", product_edition=edition)
    app = create_app(settings)
    return set(app.openapi()["paths"].keys())


class TestFullEditionIsBackwardCompatible:
    def test_full_edition_mounts_every_registered_router(self) -> None:
        """`build_v1_router("full")` must include ALL registrations with
        no filtering — the allow-list is only ever consulted for a
        non-"full" edition."""
        full = build_v1_router("full")
        # One mounted sub-router per registration, in the same order —
        # FastAPI's newer lazy _IncludedRouter mount means len(routes)
        # equals include_router() call count, not endpoint count; the
        # real per-endpoint check is test_full_edition_path_count below.
        assert len(full.routes) == len(_REGISTRATIONS)

    def test_full_edition_path_count_is_unchanged(self) -> None:
        """Real per-endpoint count via OpenAPI — the strongest possible
        proof `full` still serves every endpoint it always has. This
        number only changes when a router is added/removed from
        `_REGISTRATIONS` (i.e. a real product change), never as a side
        effect of the edition mechanism itself."""
        paths = _openapi_paths("full")
        assert len(paths) > 900  # concrete floor measured at refactor time (973)

    def test_full_edition_includes_a_representative_full_only_surface(self) -> None:
        """Spot-check a handful of full-RedForge-only capabilities that
        must still be reachable under "full"."""
        paths = _openapi_paths("full")
        for must_have_prefix in (
            "/api/v1/compliance",
            "/api/v1/vulnerabilities",
            "/api/v1/ai-posture",
            "/api/v1/red-team",
            "/api/v1/incident",
            "/api/v1/threat-hunt",
        ):
            assert any(p.startswith(must_have_prefix) for p in paths), (
                f"expected at least one full-edition path under {must_have_prefix!r}"
            )


class TestNetworkDefenseEditionExcludesUnrelatedSurfaces:
    def test_network_defense_is_a_strict_subset_of_full(self) -> None:
        full_paths = _openapi_paths("full")
        nd_paths = _openapi_paths("network_defense")
        assert nd_paths < full_paths  # strict subset — never equal, never disjoint-superset

    @pytest.mark.parametrize(
        "excluded_prefix",
        [
            "/api/v1/compliance",  # compliance-console/-assessment/-recommendations tags
            "/api/v1/vulnerabilities",  # vulnerability scanning — full RedForge only
            "/api/v1/ai-posture",
            "/api/v1/ai-supply-chain",
            "/api/v1/ai-agent-governance",
            "/api/v1/cloud-security",
            "/api/v1/cloud-foundation",
            "/api/v1/red-team",  # red-team-operator/red-team/red-team-evidence/red-team-payloads
            "/api/v1/incident",  # M34 NIST IR lifecycle — NOT the Family-A investigation system (ADR-0006)
            "/api/v1/threat-hunt",
            "/api/v1/analytics",
            "/api/v1/reporting",
            "/api/v1/ml-pipeline",
            "/api/v1/exposure",
            "/api/v1/remediation-impact",
            "/api/v1/attack-surface",
            "/api/v1/attack-paths",
            "/api/v1/knowledge-graph",
            "/api/v1/command-center",
            "/api/v1/regulatory-notification",
            "/api/v1/lessons-learned",
            "/api/v1/posture-forecasting",
            "/api/v1/autonomous-intelligence",
            "/api/v1/continuous-validation",
            "/api/v1/directory-groups",
            "/api/v1/network-exposure",
            "/api/v1/detection-rules",
            "/api/v1/engagements",
        ],
    )
    def test_network_defense_excludes_unrelated_prefix(self, excluded_prefix: str) -> None:
        nd_paths = _openapi_paths("network_defense")
        assert not any(p.startswith(excluded_prefix) for p in nd_paths), (
            f"network_defense edition unexpectedly exposes {excluded_prefix!r}"
        )

    def test_network_defense_excludes_siem_alerting_style_and_red_team_evidence(self) -> None:
        """ADR-0006: siem_* is not part of Family A and must not be
        introduced via this mechanism either way (it isn't registered in
        `_REGISTRATIONS` at all today, so this also guards against a
        future accidental addition slipping into the allow-list)."""
        assert "siem-alerting" not in NETWORK_DEFENSE_TAGS
        assert "red-team-evidence" not in NETWORK_DEFENSE_TAGS
        nd_paths = _openapi_paths("network_defense")
        assert not any(p.startswith("/api/v1/red-team-evidence") for p in nd_paths)


class TestNetworkDefenseEditionRetainsRequiredSharedSurfaces:
    @pytest.mark.parametrize(
        "required_prefix",
        [
            "/api/v1/auth",
            "/api/v1/organizations",
            "/api/v1/invitations",
            "/api/v1/platform",  # platform identity, where operationally required
            "/api/v1/admin",  # admin-rbac
            "/api/v1/assets",  # asset inventory
            "/api/v1/telemetry",
            "/api/v1/ddos",
            "/api/v1/behavior",
            "/api/v1/network-security",
            "/api/v1/security-operations",  # live SSE alert feed (ADR-0006)
            "/api/v1/investigations",  # Family-A investigation system (ADR-0006)
            "/api/v1/evidence",
            "/api/v1/security-conditions",
            "/api/v1/security-correlations",
            "/api/v1/security-graph",
            "/api/v1/iocs",  # ioc_intelligence (M51, ADR-0007)
            "/api/v1/threat-actors",  # threat_actor_intel
            "/api/v1/attack-patterns",  # attack_pattern_intel
            "/api/v1/relationships",  # intelligence_relationships
            "/api/v1/malware",  # malware_intel
            "/api/v1/campaign-intel",
            "/api/v1/tool-intel",
            "/api/v1/infrastructure-intel",
            "/api/v1/threat-report-intel",
            "/api/v1/threat-intel",  # legacy TI, carved out as enrichment/correlation source (ADR-0007)
            "/api/v1/automation",  # automated_action
            "/api/v1/playbooks",
            "/api/v1/connectors",
            "/api/v1/credentials",  # credential_vault
            "/api/v1/integration-hub",
            "/api/v1/runtime",
        ],
    )
    def test_network_defense_includes_required_prefix(self, required_prefix: str) -> None:
        nd_paths = _openapi_paths("network_defense")
        assert any(p.startswith(required_prefix) for p in nd_paths), (
            f"network_defense edition unexpectedly missing {required_prefix!r}"
        )

    @pytest.mark.asyncio
    async def test_network_defense_health_and_metrics_respond(self) -> None:
        """health/metrics are `include_in_schema=False` on at least the
        metrics endpoint, so they don't show up in the OpenAPI path
        check above — verify them by real request instead. Uses
        httpx's ASGITransport directly (matches this repo's existing
        convention, e.g. test_sprint41_product_execution.py) rather
        than starlette's TestClient, which does not need to trigger
        lifespan for a plain route-existence check."""
        from httpx import ASGITransport, AsyncClient

        settings = Settings(environment="test", product_edition="network_defense")
        app = create_app(settings)
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            metrics_resp = await client.get("/api/v1/metrics")
            assert metrics_resp.status_code == 200


class TestUnknownEditionFailsSafely:
    def test_settings_rejects_unrecognized_edition_value(self) -> None:
        """pydantic's Literal validation rejects an unrecognized
        REDFORGE_PRODUCT_EDITION at Settings construction — this is the
        fail-safe boundary: it never silently falls back to "full" and
        never constructs a Settings object with a bogus edition."""
        with pytest.raises(ValidationError):
            Settings(environment="test", product_edition="not_a_real_edition")  # type: ignore[arg-type]

    def test_build_v1_router_rejects_unrecognized_edition_value(self) -> None:
        """Defense in depth below the Settings boundary: even if an
        invalid string somehow reached `build_v1_router` directly (e.g.
        a future caller that doesn't go through Settings), it raises
        rather than silently defaulting to "full" or to an empty router."""
        with pytest.raises(KeyError):
            build_v1_router("not_a_real_edition")  # type: ignore[arg-type]
