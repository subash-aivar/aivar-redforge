"""Docker/Compose product_edition consistency guard (ADR-0009).

Proves the Network Defense compose overlay never lets the frontend
build arg and the backend runtime env diverge — a divergence would
produce exactly the frontend<->backend edition mismatch
`frontend/src/lib/editionMismatch.ts` exists to detect at runtime, and
should instead never ship in the first place.

Deliberately a small, standalone parser rather than a generic
compose-testing framework — this is the one place ADR-0009 calls out as
worth a genuinely new test file.
"""

from __future__ import annotations

from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[3]
NETWORK_DEFENSE_COMPOSE = REPO_ROOT / "docker-compose.network-defense.yml"
BASE_COMPOSE = REPO_ROOT / "docker-compose.yml"


def _load(path: Path) -> dict:
    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f)


class TestNetworkDefenseComposeEditionConsistency:
    def test_files_exist(self) -> None:
        assert NETWORK_DEFENSE_COMPOSE.is_file()
        assert BASE_COMPOSE.is_file()

    def test_backend_and_frontend_build_args_both_set_network_defense(self) -> None:
        doc = _load(NETWORK_DEFENSE_COMPOSE)
        backend_arg = doc["services"]["backend"]["build"]["args"]["PRODUCT_EDITION"]
        frontend_arg = doc["services"]["frontend"]["build"]["args"]["PRODUCT_EDITION"]
        assert backend_arg == "network_defense"
        assert frontend_arg == "network_defense"
        assert backend_arg == frontend_arg

    def test_backend_runtime_env_matches_its_own_build_arg(self) -> None:
        """The backend's `REDFORGE_PRODUCT_EDITION` runtime env must
        agree with its own `PRODUCT_EDITION` build arg — the two are
        set independently in the Dockerfile/compose (build-time ARG vs
        runtime ENV) and could silently drift."""
        doc = _load(NETWORK_DEFENSE_COMPOSE)
        backend = doc["services"]["backend"]
        build_arg = backend["build"]["args"]["PRODUCT_EDITION"]
        runtime_env = backend["environment"]["REDFORGE_PRODUCT_EDITION"]
        assert build_arg == runtime_env == "network_defense"

    def test_frontend_has_no_conflicting_runtime_env_override(self) -> None:
        """NEXT_PUBLIC_* is baked in at build time — the overlay must
        not also set a runtime `environment.NEXT_PUBLIC_PRODUCT_EDITION`
        that could diverge from the build arg actually baked into the
        image."""
        doc = _load(NETWORK_DEFENSE_COMPOSE)
        frontend = doc["services"]["frontend"]
        frontend_env = frontend.get("environment") or {}
        assert "NEXT_PUBLIC_PRODUCT_EDITION" not in frontend_env

    def test_base_compose_sets_no_edition_build_args_full_by_default(self) -> None:
        """The normal Full RedForge path must remain backward
        compatible: no edition build args required, defaulting to
        "full" end-to-end via the Dockerfiles' own `ARG ...=full`
        defaults."""
        doc = _load(BASE_COMPOSE)
        for service_name in ("backend", "frontend"):
            service = doc["services"][service_name]
            build_args = (service.get("build") or {}).get("args") or {}
            assert "PRODUCT_EDITION" not in build_args
            env = service.get("environment") or {}
            assert "REDFORGE_PRODUCT_EDITION" not in env
            assert "NEXT_PUBLIC_PRODUCT_EDITION" not in env
