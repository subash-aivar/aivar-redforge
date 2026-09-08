"""Architecture guard tests for the Network Defense Edition foundation
(Phase 0.2). These prove the constraints ADR-0006/0007/0008/0009
explicitly forbid are NOT violated by the product_edition mechanism —
not by inspecting intent, but by inspecting the actual repository state.
"""

from __future__ import annotations

import re
from pathlib import Path

BACKEND_SRC = Path(__file__).resolve().parents[2] / "src"
MIGRATIONS_DIR = (
    BACKEND_SRC / "redforge" / "infrastructure" / "database" / "migrations" / "versions"
)

# Files allowed to reference `product_edition` — the ONLY places edition
# logic may live. Any other match means edition checks have leaked out of
# the centralized mechanism (ADR-0009: "must NOT become hundreds of
# scattered feature-flag checks").
_EDITION_AWARE_FILES = {
    BACKEND_SRC / "redforge" / "core" / "config.py",
    BACKEND_SRC / "redforge" / "api" / "v1" / "__init__.py",
    BACKEND_SRC / "redforge" / "api" / "router.py",
    BACKEND_SRC / "redforge" / "app.py",
}


def _iter_python_source_files():
    for path in BACKEND_SRC.rglob("*.py"):
        if "__pycache__" in path.parts:
            continue
        yield path


class TestProductEditionLogicIsCentralized:
    def test_product_edition_referenced_only_in_the_allow_listed_files(self) -> None:
        pattern = re.compile(r"\bproduct_edition\b")
        offenders: list[Path] = []
        for path in _iter_python_source_files():
            if path in _EDITION_AWARE_FILES:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            if pattern.search(text):
                offenders.append(path)
        assert offenders == [], (
            f"product_edition logic leaked outside the centralized allow-list: {offenders}"
        )

    def test_only_one_edition_to_tag_allowlist_exists(self) -> None:
        """There must be exactly one filtering table (`_EDITION_TAG_ALLOWLISTS`
        in `api/v1/__init__.py`) — not a second one anywhere else."""
        hits = []
        for path in _iter_python_source_files():
            text = path.read_text(encoding="utf-8", errors="ignore")
            if "_EDITION_TAG_ALLOWLISTS" in text or "NETWORK_DEFENSE_TAGS" in text:
                hits.append(path)
        v1_init = BACKEND_SRC / "redforge" / "api" / "v1" / "__init__.py"
        assert v1_init in hits
        # Every OTHER hit must only be a consumer (e.g. a test importing
        # NETWORK_DEFENSE_TAGS to assert against it), never a second
        # definition of an edition->tags table.
        for path in hits:
            if path == v1_init:
                continue
            text = path.read_text(encoding="utf-8", errors="ignore")
            assert "_EDITION_TAG_ALLOWLISTS" not in text or "import" in text.split(
                "_EDITION_TAG_ALLOWLISTS"
            )[0].rsplit("\n", 1)[-1]


class TestNoSecondRbacSystem:
    def test_role_permissions_table_is_still_singular(self) -> None:
        """ROLE_PERMISSIONS remains the one and only role->permission
        table — product_edition never adds a second one, and no
        edition-specific Permission/Role values were introduced."""
        from redforge.domain.identity.value_objects import ROLE_PERMISSIONS, MembershipRole

        assert set(ROLE_PERMISSIONS.keys()) == set(MembershipRole)
        for name in dir(MembershipRole):
            assert "NETWORK" not in name.upper() or name.startswith("_")

    def test_no_edition_scoped_permission_was_introduced(self) -> None:
        from redforge.domain.identity.value_objects import Permission

        for perm in Permission:
            assert "edition" not in perm.value.lower()
            assert "network_defense" not in perm.value.lower()


class TestNoForkedMigrationChain:
    def test_migration_chain_is_strictly_linear(self) -> None:
        """Every migration file has exactly one down_revision, and no two
        files share the same down_revision (which would indicate a
        branch) — confirms product_edition introduced no schema fork."""
        down_revisions: dict[str, str] = {}
        revisions: set[str] = set()
        for path in sorted(MIGRATIONS_DIR.glob("*.py")):
            if path.name == "__init__.py":
                continue
            text = path.read_text(encoding="utf-8")
            rev_match = re.search(r'^revision:\s*str\s*=\s*"([^"]+)"', text, re.M)
            down_match = re.search(r'^down_revision:\s*str(?:\s*\|\s*None)?\s*=\s*(.+)$', text, re.M)
            assert rev_match, f"{path.name}: no `revision` assignment found"
            revision = rev_match.group(1)
            assert revision not in revisions, f"duplicate revision id {revision!r}"
            revisions.add(revision)
            if down_match:
                down_raw = down_match.group(1).strip()
                if down_raw != "None":
                    down_rev = down_raw.strip('"')
                    assert down_rev not in down_revisions, (
                        f"branch detected: both {down_revisions.get(down_rev)!r} and "
                        f"{path.name!r} declare down_revision={down_rev!r}"
                    )
                    down_revisions[down_rev] = path.name


class TestNoDuplicateCanonicalCore:
    def test_no_new_bounded_context_package_was_added_this_phase(self) -> None:
        """Phase 0.2 is foundation-only (product_edition + router/nav
        filtering) — it must not add a new top-level bounded-context
        package under backend/src (that would be new product ownership,
        forbidden by the mission's own 'do not build new detection
        logic' instruction, and would risk duplicating an existing
        canonical core module under a new name)."""
        top_level_dirs = {
            p.name
            for p in BACKEND_SRC.iterdir()
            if p.is_dir() and not p.name.endswith(".egg-info") and p.name != "__pycache__"
        }
        # Nothing edition/network-defense-named should exist as its own
        # top-level package — the mechanism lives inside existing
        # `redforge` core files, not a new package.
        for name in top_level_dirs:
            assert "network_defense" not in name
            assert name != "product_edition"

    def test_router_registration_count_is_unchanged_from_pre_edition_checkpoint(self) -> None:
        """Proves no router/bounded context was added or removed while
        introducing the edition mechanism — exactly the same 96
        registrations as the M51 WIP checkpoint (aa3f1c5), just
        restructured into a filterable list."""
        from redforge.api.v1 import _REGISTRATIONS

        assert len(_REGISTRATIONS) == 96


class TestNoNewDetectionPipelineOrSiemDependency:
    def test_no_siem_import_in_edition_aware_files(self) -> None:
        """ADR-0006: Network Defense Edition must not depend on siem_*
        for new product work. None of the edition-mechanism files may
        IMPORT it — mentioning it in a comment (to document that it is
        deliberately excluded, as `api/v1/__init__.py` does) is fine and
        expected; an actual `import siem_*`/`from siem_*` is not."""
        import_pattern = re.compile(r"^\s*(?:from|import)\s+siem_\w+", re.M)
        for path in _EDITION_AWARE_FILES:
            text = path.read_text(encoding="utf-8", errors="ignore")
            assert not import_pattern.search(text), (
                f"{path} imports siem_*, forbidden by ADR-0006"
            )

    def test_network_defense_tags_contains_no_siem_tag(self) -> None:
        from redforge.api.v1 import NETWORK_DEFENSE_TAGS

        assert not any(tag.startswith("siem") for tag in NETWORK_DEFENSE_TAGS)

    def test_network_defense_tags_contains_no_incident_m34_tag(self) -> None:
        """ADR-0006: `incident` (M34) is explicitly NOT the canonical
        investigation system for Network Defense Edition — only
        `investigations` (Family A) is."""
        from redforge.api.v1 import NETWORK_DEFENSE_TAGS

        assert "incident" not in NETWORK_DEFENSE_TAGS
        assert "investigations" in NETWORK_DEFENSE_TAGS


class TestM51ThreatIntelRemainsCanonical:
    def test_all_nine_m51_threat_intel_tags_are_allow_listed(self) -> None:
        """ADR-0007: the M51 native suite is canonical for Network
        Defense Edition's Threat Intelligence surface."""
        from redforge.api.v1 import NETWORK_DEFENSE_TAGS

        m51_tags = {
            "ioc-intelligence",
            "threat-actor-intel",
            "attack-pattern-intel",
            "intelligence-relationships",
            "malware-intel",
            "campaign-intel",
            "tool-intel",
            "infrastructure-intel",
            "threat-report-intel",
        }
        assert m51_tags <= NETWORK_DEFENSE_TAGS

    def test_legacy_threat_intel_present_only_as_carve_out_not_expanded(self) -> None:
        """Legacy `threat_intel`/`threat-intel-feed-sync` remain allowed
        (ADR-0007's explicit enrichment/correlation carve-out), but
        `threat-fusion` and `threat-intel-reference-data` — broader
        legacy surfaces not required for network correlation — are NOT
        allow-listed, proving the carve-out wasn't silently widened."""
        from redforge.api.v1 import NETWORK_DEFENSE_TAGS

        assert "threat-intel" in NETWORK_DEFENSE_TAGS
        assert "threat-intel-feed-sync" in NETWORK_DEFENSE_TAGS
        assert "threat-fusion" not in NETWORK_DEFENSE_TAGS
        assert "threat-intel-reference-data" not in NETWORK_DEFENSE_TAGS
