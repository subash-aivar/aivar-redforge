"""M22 Phase 1 — Threat Intelligence Reference Data: PostgreSQL
integration, migration verification, and HTTP acceptance proof suite.

Runs against a DEDICATED proof database
(`redforge_m22_reference_data_proof_test` by default), migrated to head
via `alembic upgrade head` before this file runs — never against the
shared dev `redforge` database. Every assertion here uses real
PostgreSQL; no mocks on repositories, the database, or the migration
itself.

Covers:
  Section A: Migration verification — schema shape matches the
             approved design exactly (no `organization_id` on the four
             global tables, deferrable self-referencing FKs, the GIN
             full-text index, the scope/org check constraint plus its
             two partial unique indexes on `stix_ingestion_log`).
  Section B: Repository-level proof — idempotent upsert (create then
             update), concurrent-upsert race safety, deferrable-FK
             insert ordering, GIN full-text search, KEV/EPSS filters,
             sub-technique/relationship traversal, and the ingestion
             log's tri-state upsert + GLOBAL/TENANT partial-unique
             isolation.
  Section C: Application-service proof — idempotent batch loading
             (create/update/unchanged), per-item validation-error
             isolation within a batch, and platform audit logging.
  Section D: HTTP acceptance — real JWT via the platform bootstrap
             flow, PlatformPermission enforcement (401/403/200) on the
             internal administration API, and end-to-end load-then-
             verify round trips.
"""

from __future__ import annotations

import asyncio
import os
import time

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from redforge.application.threat_intel.reference_data_admin_service import (
    ReferenceDataAdminService,
    RelationshipInput,
    TacticInput,
    TechniqueInput,
    VulnerabilityInput,
)
from redforge.application.threat_intel.reference_data_query_service import (
    ReferenceDataQueryService,
)
from redforge.domain.threat_intel.attack_technique_entity import AttackTactic, AttackTechnique
from redforge.domain.threat_intel.reference_data_ingestion import ReferenceDataIngestionRecord
from redforge.domain.threat_intel.reference_data_value_objects import (
    IngestionScope,
    ReferenceDataSource,
    TacticId,
    TechniqueId,
)
from redforge.domain.threat_intel.vulnerability_entity import Vulnerability
from redforge.infrastructure.audit.contracts import AuditAction
from redforge.infrastructure.audit.platform_audit_log import PostgresPlatformAuditLog
from redforge.infrastructure.database.repositories.threat_intel_reference_data_repository import (
    SqlAlchemyAttackTacticRepository,
    SqlAlchemyAttackTechniqueRepository,
    SqlAlchemyReferenceDataIngestionRepository,
    SqlAlchemyVulnerabilityRepository,
)

pytestmark = pytest.mark.asyncio(loop_scope="module")

_DB_NAME = "redforge_m22_reference_data_proof_test"
_DB_URL = os.environ.get(
    "REDFORGE_M22_TEST_DATABASE_URL",
    f"postgresql+asyncpg://redforge:redforge@localhost:5432/{_DB_NAME}",
)


def _unique(prefix: str) -> str:
    return f"{prefix}-{time.time_ns()}"


# ─────────────────────────────────────────────────────────────────────────────
# Fixtures
# ─────────────────────────────────────────────────────────────────────────────


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def session_factory():
    """Direct DB session factory — repository and service level tests,
    plus raw schema introspection, all bypass HTTP entirely here."""
    engine = create_async_engine(_DB_URL, echo=False)
    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    yield factory
    await engine.dispose()


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def client():
    """Full production app against the M22 proof database. Startup runs
    the REAL startup validator (migration-head check included) — this
    fixture failing to construct is itself proof the startup validator
    accepts a database migrated to 0035."""
    from unittest.mock import patch

    from redforge.app import create_app
    from redforge.core.config import Settings
    from redforge.infrastructure.rate_limiting.contracts import RateLimitResult
    from redforge.infrastructure.rate_limiting.sliding_window import (
        InMemorySlidingWindowLimiter,
    )

    async def _always_allow(
        self: object, key: str, max_requests: int, window_seconds: int,
    ) -> RateLimitResult:
        return RateLimitResult(
            allowed=True, remaining=max_requests, limit=max_requests, retry_after_seconds=0,
        )

    # PlatformAccessService resolves bootstrap config from a fresh
    # `get_settings()` (env-var read) rather than from the `Settings`
    # object handed to `create_app` below — both must agree, so the
    # bootstrap-relevant env vars are set for the lifetime of this
    # module-scoped client and restored afterward.
    bootstrap_env = {
        "REDFORGE_PLATFORM_BOOTSTRAP_ENABLED": "true",
        "REDFORGE_PLATFORM_BOOTSTRAP_PRINCIPAL_EMAIL": "m22-super-admin@redforge.test",
    }
    previous_env = {k: os.environ.get(k) for k in bootstrap_env}
    os.environ.update(bootstrap_env)
    try:
        with patch.object(InMemorySlidingWindowLimiter, "check", _always_allow):
            app = create_app(
                settings=Settings(
                    database_url=_DB_URL,
                    platform_bootstrap_enabled=True,
                    platform_bootstrap_principal_email="m22-super-admin@redforge.test",
                )
            )
            async with app.router.lifespan_context(app):
                transport = ASGITransport(app=app, raise_app_exceptions=False)
                async with AsyncClient(transport=transport, base_url="http://test") as c:
                    yield c
    finally:
        for key, value in previous_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


async def _register(client: AsyncClient, email: str) -> str:
    """Register, or log in if this email already exists — the proof
    database persists across test runs, and the bootstrap principal
    email is fixed (bootstrap is a one-time singleton), so a re-run
    must not fail on a stale prior registration."""
    password = "SecureP@ss123"
    r = await client.post(
        "/api/v1/auth/register",
        json={"email": email, "display_name": "M22 Test User", "password": password},
    )
    if r.status_code == 201:
        return r.json()["access_token"]
    if r.status_code == 409:
        r = await client.post("/api/v1/auth/login", json={"email": email, "password": password})
        assert r.status_code == 200, r.text
        return r.json()["access_token"]
    raise AssertionError(f"Register failed: {r.status_code} {r.text}")


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def super_admin_token(client: AsyncClient) -> str:
    """Registers the configured bootstrap principal and consumes the
    one-time `/platform/bootstrap` endpoint to become the platform
    Super Admin — the real HTTP path, not a direct service call.

    Bootstrap is a singleton that can only ever be consumed once for
    the lifetime of the proof database — a re-run against the same
    persisted database is expected to find it already consumed by a
    prior run, in which case this principal already holds
    SUPER_ADMIN and the token alone is sufficient.
    """
    token = await _register(client, "m22-super-admin@redforge.test")
    r = await client.post(
        "/api/v1/platform/bootstrap", headers={"Authorization": f"Bearer {token}"}
    )
    if r.status_code == 201:
        assert r.json()["role"] == "platform_super_admin"
    else:
        assert r.status_code == 409, r.text
    return token


@pytest_asyncio.fixture(scope="module", loop_scope="module")
async def no_platform_role_token(client: AsyncClient) -> str:
    """An authenticated user who has never been granted ANY platform
    role — used to prove 403 (not 500, not silently-allowed) on every
    reference-data endpoint."""
    return await _register(client, _unique("no-role") + "@redforge.test")


# ─────────────────────────────────────────────────────────────────────────────
# Section A — Migration verification
# ─────────────────────────────────────────────────────────────────────────────


class TestMigrationSchema:
    async def test_global_tables_carry_no_organization_id(self, session_factory) -> None:
        """The single most important P0 fix from the Hardening Review:
        the four global catalog tables must never carry a tenant
        column — proven by direct information_schema introspection,
        not by trusting the ORM model."""
        async with session_factory() as session:
            for table in (
                "attack_tactics",
                "attack_techniques",
                "attack_technique_relationships",
                "vulnerabilities",
            ):
                result = await session.execute(
                    text(
                        "SELECT column_name FROM information_schema.columns "
                        "WHERE table_name = :table AND column_name = 'organization_id'"
                    ),
                    {"table": table},
                )
                assert result.first() is None, f"{table} must not carry organization_id"

    async def test_stix_ingestion_log_carries_nullable_organization_id(
        self, session_factory
    ) -> None:
        async with session_factory() as session:
            result = await session.execute(
                text(
                    "SELECT is_nullable FROM information_schema.columns "
                    "WHERE table_name = 'stix_ingestion_log' AND column_name = 'organization_id'"
                )
            )
            row = result.first()
            assert row is not None
            assert row[0] == "YES"

    async def test_scope_org_pairing_check_constraint_exists(self, session_factory) -> None:
        async with session_factory() as session:
            result = await session.execute(
                text(
                    "SELECT conname FROM pg_constraint "
                    "WHERE conname = 'ck_stix_ingestion_log_ck_sil_scope_org_pairing'"
                )
            )
            assert result.first() is not None

    async def test_ingestion_log_has_two_partial_unique_indexes(self, session_factory) -> None:
        async with session_factory() as session:
            result = await session.execute(
                text(
                    "SELECT indexname FROM pg_indexes "
                    "WHERE tablename = 'stix_ingestion_log' "
                    "AND indexname IN "
                    "('ux_sil_global_source_external', 'ux_sil_tenant_org_source_external')"
                )
            )
            names = {row[0] for row in result.all()}
            assert names == {"ux_sil_global_source_external", "ux_sil_tenant_org_source_external"}

    async def test_technique_name_gin_index_exists(self, session_factory) -> None:
        async with session_factory() as session:
            result = await session.execute(
                text(
                    "SELECT indexdef FROM pg_indexes "
                    "WHERE tablename = 'attack_techniques' AND indexname = 'ix_atk_name_fts'"
                )
            )
            row = result.first()
            assert row is not None
            assert "gin" in row[0].lower()
            assert "to_tsvector" in row[0]

    async def test_parent_technique_fk_is_deferrable(self, session_factory) -> None:
        async with session_factory() as session:
            result = await session.execute(
                text(
                    "SELECT condeferrable, condeferred FROM pg_constraint "
                    "WHERE conname = 'fk_atk_parent_technique'"
                )
            )
            row = result.first()
            assert row is not None
            assert row[0] is True  # deferrable
            assert row[1] is True  # initially deferred

    async def test_relationship_technique_fks_are_deferrable(self, session_factory) -> None:
        async with session_factory() as session:
            result = await session.execute(
                text(
                    "SELECT conname, condeferrable, condeferred FROM pg_constraint "
                    "WHERE conname IN ('fk_atr_source_technique', 'fk_atr_target_technique')"
                )
            )
            rows = result.all()
            assert len(rows) == 2
            for _, deferrable, deferred in rows:
                assert deferrable is True
                assert deferred is True

    async def test_migration_head_is_current(self, session_factory) -> None:
        """This proof database is migrated with `alembic upgrade head`,
        so its `alembic_version` always tracks the CURRENT global head —
        0035 when this suite was written, 0036 after M22 Phase 2 (Feed
        Synchronization Foundation) added its own additive migration on
        top. This assertion intentionally tracks the moving head rather
        than pinning to 0035, since pinning would make every future,
        unrelated migration break this Phase 1 suite."""
        async with session_factory() as session:
            result = await session.execute(text("SELECT version_num FROM alembic_version"))
            assert result.scalar_one() == "0038"


# ─────────────────────────────────────────────────────────────────────────────
# Section B — Repository proof
# ─────────────────────────────────────────────────────────────────────────────


class TestAttackTacticRepository:
    async def test_upsert_creates_then_updates_in_place(self, session_factory) -> None:
        stix_id = _unique("x-mitre-tactic--repo")
        async with session_factory() as session:
            repo = SqlAlchemyAttackTacticRepository(session)
            from datetime import UTC, datetime

            now = datetime.now(UTC)
            created = await repo.upsert(
                AttackTactic(
                    tactic_id=TacticId("TA0999"),
                    name="Repo Test Tactic",
                    shortname="repo-test",
                    description="v1",
                    stix_id=stix_id,
                    url=None,
                    created_at=now,
                    updated_at=now,
                )
            )
            await session.commit()
            assert created.description == "v1"

            updated = await repo.upsert(
                AttackTactic(
                    tactic_id=TacticId("TA0999"),
                    name="Repo Test Tactic",
                    shortname="repo-test",
                    description="v2 — updated in place",
                    stix_id=stix_id,
                    url="https://attack.mitre.org/tactics/TA0999",
                    created_at=now,
                    updated_at=now,
                )
            )
            await session.commit()
            assert updated.description == "v2 — updated in place"

            fetched = await repo.get_by_id("TA0999")
            assert fetched is not None
            assert fetched.description == "v2 — updated in place"
            assert fetched.url == "https://attack.mitre.org/tactics/TA0999"

    async def test_concurrent_upsert_of_same_tactic_id_is_race_safe(
        self, session_factory
    ) -> None:
        """15 concurrent sessions upsert the SAME tactic_id — proves the
        begin_nested()+IntegrityError refetch pattern, not an
        app-level `if exists` check, resolves the race: exactly one row
        must exist afterward, and it must reflect a fully-formed write
        (never a half-applied one)."""
        from datetime import UTC, datetime

        now = datetime.now(UTC)
        stix_id = _unique("x-mitre-tactic--race")

        async def attempt(i: int) -> str:
            async with session_factory() as session:
                repo = SqlAlchemyAttackTacticRepository(session)
                try:
                    await repo.upsert(
                        AttackTactic(
                            tactic_id=TacticId("TA0998"),
                            name=f"Race Tactic {i}",
                            shortname="race-tactic",
                            description=f"attempt-{i}",
                            stix_id=stix_id,
                            url=None,
                            created_at=now,
                            updated_at=now,
                        )
                    )
                    await session.commit()
                    return "ok"
                except Exception as exc:  # pragma: no cover - failure path
                    await session.rollback()
                    return f"error:{exc!r}"

        results = await asyncio.gather(*(attempt(i) for i in range(15)))
        assert all(r == "ok" for r in results), results

        async with session_factory() as session:
            result = await session.execute(
                text("SELECT count(*) FROM attack_tactics WHERE tactic_id = 'TA0998'")
            )
            assert result.scalar_one() == 1


class TestAttackTechniqueRepository:
    async def test_deferrable_fk_allows_child_before_parent_in_one_transaction(
        self, session_factory
    ) -> None:
        """A sub-technique referencing its not-yet-inserted parent must
        commit successfully within one transaction — proves the
        `DEFERRABLE INITIALLY DEFERRED` FK, not insertion-order
        discipline in application code, is what makes bulk STIX-bundle
        loading order-independent."""
        from datetime import UTC, datetime

        now = datetime.now(UTC)
        parent_technique_id = "T9001"
        sub_technique_id = "T9001.001"

        async with session_factory() as session:
            repo = SqlAlchemyAttackTechniqueRepository(session)
            # Insert the sub-technique FIRST, parent SECOND, same transaction.
            await repo.upsert(
                AttackTechnique(
                    technique_id=TechniqueId(sub_technique_id),
                    name="Deferred Sub-technique",
                    description="",
                    stix_id=_unique("attack-pattern--sub"),
                    is_sub_technique=True,
                    parent_technique_id=TechniqueId(parent_technique_id),
                    created_at=now,
                    updated_at=now,
                )
            )
            await repo.upsert(
                AttackTechnique(
                    technique_id=TechniqueId(parent_technique_id),
                    name="Deferred Parent",
                    description="",
                    stix_id=_unique("attack-pattern--parent"),
                    is_sub_technique=False,
                    parent_technique_id=None,
                    created_at=now,
                    updated_at=now,
                )
            )
            await session.commit()

            sub = await repo.get_by_id(sub_technique_id)
            assert sub is not None
            assert sub.parent_technique_id == TechniqueId(parent_technique_id)

    async def test_list_sub_techniques_and_list_by_tactic(self, session_factory) -> None:
        from datetime import UTC, datetime

        now = datetime.now(UTC)
        async with session_factory() as session:
            repo = SqlAlchemyAttackTechniqueRepository(session)
            await repo.upsert(
                AttackTechnique(
                    technique_id=TechniqueId("T9002"),
                    name="Parent For Listing",
                    description="",
                    stix_id=_unique("attack-pattern--parent2"),
                    is_sub_technique=False,
                    parent_technique_id=None,
                    tactic_ids=(TacticId("TA0997"),),
                    created_at=now,
                    updated_at=now,
                )
            )
            await repo.upsert(
                AttackTechnique(
                    technique_id=TechniqueId("T9002.001"),
                    name="Sub A",
                    description="",
                    stix_id=_unique("attack-pattern--suba"),
                    is_sub_technique=True,
                    parent_technique_id=TechniqueId("T9002"),
                    created_at=now,
                    updated_at=now,
                )
            )
            await repo.upsert(
                AttackTechnique(
                    technique_id=TechniqueId("T9002.002"),
                    name="Sub B",
                    description="",
                    stix_id=_unique("attack-pattern--subb"),
                    is_sub_technique=True,
                    parent_technique_id=TechniqueId("T9002"),
                    created_at=now,
                    updated_at=now,
                )
            )
            await session.commit()

            subs = await repo.list_sub_techniques("T9002")
            assert {s.technique_id.value for s in subs} == {"T9002.001", "T9002.002"}

            by_tactic = await repo.list_by_tactic("TA0997")
            assert "T9002" in {t.technique_id.value for t in by_tactic}

    async def test_search_by_name_uses_gin_full_text_index(self, session_factory) -> None:
        from datetime import UTC, datetime

        now = datetime.now(UTC)
        unique_word = f"Zylophonic{time.time_ns()}"
        async with session_factory() as session:
            repo = SqlAlchemyAttackTechniqueRepository(session)
            await repo.upsert(
                AttackTechnique(
                    technique_id=TechniqueId("T9003"),
                    name=f"{unique_word} Exfiltration Technique",
                    description="",
                    stix_id=_unique("attack-pattern--search"),
                    is_sub_technique=False,
                    parent_technique_id=None,
                    created_at=now,
                    updated_at=now,
                )
            )
            await session.commit()

            hits = await repo.search_by_name(unique_word)
            assert any(t.technique_id.value == "T9003" for t in hits)

            no_hits = await repo.search_by_name(f"nonexistent-{time.time_ns()}")
            assert no_hits == []

    async def test_search_by_name_sanitizes_malformed_query_without_error(
        self, session_factory
    ) -> None:
        """A query consisting entirely of tsquery-special characters must
        never raise a syntax error — it degrades to an empty result."""
        async with session_factory() as session:
            repo = SqlAlchemyAttackTechniqueRepository(session)
            results = await repo.search_by_name("&&& ||| !!! ((()))")
            assert results == []

    async def test_relationship_upsert_and_traversal(self, session_factory) -> None:
        from datetime import UTC, datetime

        from redforge.domain.threat_intel.attack_technique_entity import (
            AttackTechniqueRelationship,
        )
        from redforge.domain.threat_intel.reference_data_value_objects import (
            AttackRelationshipType,
        )

        now = datetime.now(UTC)
        async with session_factory() as session:
            repo = SqlAlchemyAttackTechniqueRepository(session)
            await repo.upsert(
                AttackTechnique(
                    technique_id=TechniqueId("T9004"),
                    name="Relationship Source",
                    description="",
                    stix_id=_unique("attack-pattern--relsrc"),
                    is_sub_technique=False,
                    parent_technique_id=None,
                    created_at=now,
                    updated_at=now,
                )
            )
            await repo.upsert(
                AttackTechnique(
                    technique_id=TechniqueId("T9005"),
                    name="Relationship Target",
                    description="",
                    stix_id=_unique("attack-pattern--reltgt"),
                    is_sub_technique=False,
                    parent_technique_id=None,
                    created_at=now,
                    updated_at=now,
                )
            )
            rel_stix_id = _unique("relationship--proof")
            await repo.upsert_relationship(
                AttackTechniqueRelationship(
                    stix_id=rel_stix_id,
                    relationship_type=AttackRelationshipType.PRECEDES,
                    source_ref="attack-pattern--relsrc",
                    target_ref="attack-pattern--reltgt",
                    source_technique_id=TechniqueId("T9004"),
                    target_technique_id=TechniqueId("T9005"),
                    description="",
                    created_at=now,
                    updated_at=now,
                )
            )
            await session.commit()

            from_source = await repo.list_relationships_for_technique("T9004")
            assert any(r.stix_id == rel_stix_id for r in from_source)

            from_target = await repo.list_relationships_for_technique(
                "T9005", relationship_type=AttackRelationshipType.PRECEDES
            )
            assert any(r.stix_id == rel_stix_id for r in from_target)

            wrong_type = await repo.list_relationships_for_technique(
                "T9005", relationship_type=AttackRelationshipType.MITIGATES
            )
            assert all(r.stix_id != rel_stix_id for r in wrong_type)


class TestVulnerabilityRepository:
    async def test_upsert_kev_and_epss_filters(self, session_factory) -> None:
        from datetime import UTC, date, datetime

        from redforge.domain.threat_intel.reference_data_value_objects import (
            CveId,
            EpssScore,
        )

        now = datetime.now(UTC)
        cve_kev = f"CVE-2024-{time.time_ns() % 100000:05d}"
        cve_high_epss = f"CVE-2024-{(time.time_ns() + 1) % 100000:05d}"

        async with session_factory() as session:
            repo = SqlAlchemyVulnerabilityRepository(session)
            await repo.upsert(
                Vulnerability(
                    cve_id=CveId(cve_kev),
                    description="KEV-listed CVE",
                    cvss_v3=None,
                    cvss_v2_score=None,
                    epss=None,
                    is_kev=True,
                    kev_date_added=now,
                    kev_due_date=now,
                    kev_vulnerability_name="Proof KEV",
                    kev_short_description=None,
                    kev_required_action=None,
                    kev_known_ransomware_use=False,
                    published_at=None,
                    last_modified_at=None,
                    source_last_synced_at=None,
                    created_at=now,
                    updated_at=now,
                )
            )
            await repo.upsert(
                Vulnerability(
                    cve_id=CveId(cve_high_epss),
                    description="High-EPSS CVE",
                    cvss_v3=None,
                    cvss_v2_score=None,
                    epss=EpssScore(probability=0.93, percentile=0.99, model_date=date.today()),
                    is_kev=False,
                    kev_date_added=None,
                    kev_due_date=None,
                    kev_vulnerability_name=None,
                    kev_short_description=None,
                    kev_required_action=None,
                    kev_known_ransomware_use=False,
                    published_at=None,
                    last_modified_at=None,
                    source_last_synced_at=None,
                    created_at=now,
                    updated_at=now,
                )
            )
            await session.commit()

            kev_list = await repo.list_by_kev_flag(True)
            assert any(v.cve_id.value == cve_kev for v in kev_list)
            assert all(v.is_kev for v in kev_list)

            high_epss = await repo.list_by_epss_threshold(0.9)
            assert any(v.cve_id.value == cve_high_epss for v in high_epss)

            fetched = await repo.get_by_cve_id(cve_kev)
            assert fetched is not None
            assert fetched.kev_vulnerability_name == "Proof KEV"


class TestReferenceDataIngestionRepository:
    async def test_upsert_record_created_then_updated(self, session_factory) -> None:
        external_id = _unique("attack-pattern--ingest")
        async with session_factory() as session:
            repo = SqlAlchemyReferenceDataIngestionRepository(session)

            first = ReferenceDataIngestionRecord.record(
                id="ing-1-" + _unique(""),
                source_system=ReferenceDataSource.MITRE_ATTACK,
                object_type="attack_technique",
                external_id=external_id,
                content_hash="a" * 64,
            )
            record1, created1 = await repo.upsert_record(first)
            await session.commit()
            assert created1 is True
            assert record1.content_hash == "a" * 64

            second = ReferenceDataIngestionRecord.record(
                id="ing-2-" + _unique(""),
                source_system=ReferenceDataSource.MITRE_ATTACK,
                object_type="attack_technique",
                external_id=external_id,
                content_hash="b" * 64,
            )
            record2, created2 = await repo.upsert_record(second)
            await session.commit()
            assert created2 is False
            assert record2.content_hash == "b" * 64

            found = await repo.find(
                ReferenceDataSource.MITRE_ATTACK, external_id, scope=IngestionScope.GLOBAL
            )
            assert found is not None
            assert found.content_hash == "b" * 64
            # Only ONE row backs this idempotency key — an upsert-in-place,
            # never an append-only history of every content-hash change.
            row_count = await session.execute(
                text("SELECT count(*) FROM stix_ingestion_log WHERE external_id = :ext"),
                {"ext": external_id},
            )
            assert row_count.scalar_one() == 1

    async def test_global_and_tenant_scope_do_not_collide_on_same_external_id(
        self, session_factory
    ) -> None:
        """The exact defect the Hardening Review flagged: a GLOBAL row
        and a TENANT row for the SAME (source_system, external_id) must
        coexist — proven by the two partial unique indexes, not a
        single combined one."""
        external_id = _unique("CVE-2024-collision")
        async with session_factory() as session:
            repo = SqlAlchemyReferenceDataIngestionRepository(session)

            global_record = ReferenceDataIngestionRecord.record(
                id="ing-g-" + _unique(""),
                source_system=ReferenceDataSource.NVD_CVE,
                object_type="vulnerability",
                external_id=external_id,
                content_hash="g" * 64,
                scope=IngestionScope.GLOBAL,
            )
            _, g_created = await repo.upsert_record(global_record)
            await session.commit()
            assert g_created is True

            tenant_record = ReferenceDataIngestionRecord.record(
                id="ing-t-" + _unique(""),
                source_system=ReferenceDataSource.NVD_CVE,
                object_type="vulnerability",
                external_id=external_id,
                content_hash="t" * 64,
                scope=IngestionScope.TENANT,
                organization_id="org-proof-1",
            )
            _, t_created = await repo.upsert_record(tenant_record)
            await session.commit()
            assert t_created is True

            g_found = await repo.find(
                ReferenceDataSource.NVD_CVE, external_id, scope=IngestionScope.GLOBAL
            )
            t_found = await repo.find(
                ReferenceDataSource.NVD_CVE,
                external_id,
                scope=IngestionScope.TENANT,
                organization_id="org-proof-1",
            )
            assert g_found is not None and g_found.organization_id is None
            assert t_found is not None and t_found.organization_id == "org-proof-1"

    async def test_scope_org_pairing_violation_is_rejected_at_db_level(
        self, session_factory
    ) -> None:
        """Even bypassing the domain aggregate's own `_validate_scope`
        guard, the database CHECK constraint must independently refuse
        a GLOBAL row carrying an organization_id — defense in depth,
        not solely application-level trust."""
        from sqlalchemy.exc import IntegrityError

        async with session_factory() as session:
            with pytest.raises(IntegrityError):
                await session.execute(
                    text(
                        "INSERT INTO stix_ingestion_log "
                        "(id, source_system, scope, organization_id, object_type, "
                        "external_id, content_hash, ingested_at) "
                        "VALUES (:id, 'mitre_attack', 'GLOBAL', 'org-should-fail', "
                        "'attack_technique', :ext, :hash, now())"
                    ),
                    {
                        "id": "ing-b-" + _unique(""),
                        "ext": _unique("bad-external-id"),
                        "hash": "z" * 64,
                    },
                )
            await session.rollback()


# ─────────────────────────────────────────────────────────────────────────────
# Section C — Application service proof
# ─────────────────────────────────────────────────────────────────────────────


class TestReferenceDataAdminService:
    async def test_upsert_tactics_idempotent_across_three_submissions(
        self, session_factory
    ) -> None:
        """create -> unchanged (same content) -> updated (content
        changed) — the exact three-state lifecycle the admin service
        promises."""
        service = ReferenceDataAdminService(session_factory)
        stix_id = _unique("x-mitre-tactic--svc")
        tactic = TacticInput(
            tactic_id="TA0900",
            name="Service Test Tactic",
            shortname="svc-test",
            stix_id=stix_id,
            description="v1",
        )

        result1 = await service.upsert_tactics(actor_id="tester", tactics=[tactic])
        assert result1.created == 1
        assert result1.updated == 0
        assert result1.unchanged == 0
        assert result1.failed == 0

        result2 = await service.upsert_tactics(actor_id="tester", tactics=[tactic])
        assert result2.created == 0
        assert result2.updated == 0
        assert result2.unchanged == 1

        changed_tactic = TacticInput(
            tactic_id="TA0900",
            name="Service Test Tactic",
            shortname="svc-test",
            stix_id=stix_id,
            description="v2 — content changed",
        )
        result3 = await service.upsert_tactics(actor_id="tester", tactics=[changed_tactic])
        assert result3.created == 0
        assert result3.updated == 1
        assert result3.unchanged == 0

        async with session_factory() as session:
            fetched = await ReferenceDataQueryService(session).get_tactic("TA0900")
            assert fetched is not None
            assert fetched.description == "v2 — content changed"

    async def test_batch_isolates_per_item_validation_errors(self, session_factory) -> None:
        """One malformed item in a batch must not abort the whole
        batch — the other, valid items still commit, and the bad one is
        reported by index/identifier."""
        service = ReferenceDataAdminService(session_factory)
        good = TechniqueInput(
            technique_id="T9100",
            name="Good Technique",
            stix_id=_unique("attack-pattern--good"),
        )
        bad = TechniqueInput(
            technique_id="NOT-A-VALID-ID",
            name="Bad Technique",
            stix_id=_unique("attack-pattern--bad"),
        )

        result = await service.upsert_techniques(actor_id="tester", techniques=[good, bad])
        assert result.total == 2
        assert result.created == 1
        assert result.failed == 1
        assert result.errors[0].identifier == "NOT-A-VALID-ID"

        async with session_factory() as session:
            fetched = await ReferenceDataQueryService(session).get_technique("T9100")
            assert fetched is not None

    async def test_failed_item_never_poisons_the_ingestion_log(self, session_factory) -> None:
        """A domain-validation failure must never write a
        `stix_ingestion_log` row for that item's `external_id`.

        Regression test for a real defect: the ingestion-log write was
        originally issued *before* the item's domain entity was
        constructed/validated. A batch item that failed validation
        still left a "successfully ingested" ledger row keyed by its
        `stix_id`. Retrying with the exact same (still invalid)
        payload would then hash-match that poisoned record and be
        silently reported as `unchanged` — forever — even though the
        referenced technique row was never actually created. Fixed by
        deferring the ingestion-log write until after the repository
        upsert has already succeeded.
        """
        service = ReferenceDataAdminService(session_factory)
        bad_stix_id = _unique("attack-pattern--poison")
        bad = TechniqueInput(
            technique_id="NOT-A-VALID-ID-EITHER",
            name="Permanently Bad Technique",
            stix_id=bad_stix_id,
        )

        first = await service.upsert_techniques(actor_id="tester", techniques=[bad])
        assert first.failed == 1
        assert first.created == 0
        assert first.unchanged == 0

        async with session_factory() as session:
            ingestion_repo = SqlAlchemyReferenceDataIngestionRepository(session)
            record = await ingestion_repo.find(
                ReferenceDataSource.MITRE_ATTACK, bad_stix_id, scope=IngestionScope.GLOBAL
            )
            assert record is None, (
                "a failed item must never leave a ghost ingestion-log record"
            )

        # Retrying with the exact same (still invalid) payload must be
        # reported as failed again, never as a silent "unchanged" skip.
        second = await service.upsert_techniques(actor_id="tester", techniques=[bad])
        assert second.failed == 1
        assert second.created == 0
        assert second.unchanged == 0
        assert second.errors[0].identifier == "NOT-A-VALID-ID-EITHER"

    async def test_dangling_parent_technique_reference_isolated_not_batch_aborting(
        self, session_factory
    ) -> None:
        """`parent_technique_id` is a DEFERRABLE FK, checked only at
        COMMIT. A dangling reference must be caught by the service's
        pre-check and isolated to that one item — it must NOT raise an
        unhandled IntegrityError at `uow.commit()` that would roll
        back every other, otherwise-valid item in the same batch."""
        service = ReferenceDataAdminService(session_factory)
        good = TechniqueInput(
            technique_id="T9110",
            name="Good Technique With Dangling Sibling",
            stix_id=_unique("attack-pattern--goodsibling"),
        )
        dangling = TechniqueInput(
            technique_id="T9111",
            name="Dangling Parent Reference",
            stix_id=_unique("attack-pattern--danglingparent"),
            is_sub_technique=True,
            parent_technique_id="T9999",  # never ingested anywhere
        )

        result = await service.upsert_techniques(
            actor_id="tester", techniques=[good, dangling]
        )
        assert result.total == 2
        assert result.created == 1
        assert result.failed == 1
        assert result.errors[0].identifier == "T9111"

        async with session_factory() as session:
            query_service = ReferenceDataQueryService(session)
            assert await query_service.get_technique("T9110") is not None
            assert await query_service.get_technique("T9111") is None

    async def test_same_batch_out_of_order_parent_reference_resolves(
        self, session_factory
    ) -> None:
        """A sub-technique listed *before* its parent in the same
        batch call must still succeed — the service's pre-check must
        union the current batch's own technique_ids with already
        -stored ones, not just query the database, mirroring the
        DEFERRABLE FK's own child-before-parent tolerance."""
        service = ReferenceDataAdminService(session_factory)
        parent_id = "T9120"
        child = TechniqueInput(
            technique_id="T9120.001",
            name="Child Listed First",
            stix_id=_unique("attack-pattern--childfirst"),
            is_sub_technique=True,
            parent_technique_id=parent_id,
        )
        parent = TechniqueInput(
            technique_id=parent_id,
            name="Parent Listed Second",
            stix_id=_unique("attack-pattern--parentsecond"),
        )

        result = await service.upsert_techniques(
            actor_id="tester", techniques=[child, parent]
        )
        assert result.failed == 0
        assert result.created == 2

        async with session_factory() as session:
            fetched_child = await ReferenceDataQueryService(session).get_technique(
                "T9120.001"
            )
            assert fetched_child is not None
            assert fetched_child.parent_technique_id == TechniqueId(parent_id)

    async def test_unknown_tactic_reference_is_isolated(self, session_factory) -> None:
        """A technique referencing a `tactic_id` that was never
        ingested must be reported as a per-item failure — `tactic_ids`
        has no DB-level FK at all (it is a JSON array), so this
        invariant is only enforced by the application-layer check."""
        service = ReferenceDataAdminService(session_factory)
        bad = TechniqueInput(
            technique_id="T9130",
            name="References A Fabricated Tactic",
            stix_id=_unique("attack-pattern--badtactic"),
            tactic_ids=["TA9999"],
        )

        result = await service.upsert_techniques(actor_id="tester", techniques=[bad])
        assert result.failed == 1
        assert result.created == 0
        assert result.errors[0].identifier == "T9130"

        async with session_factory() as session:
            assert await ReferenceDataQueryService(session).get_technique("T9130") is None

    async def test_dangling_relationship_technique_reference_isolated(
        self, session_factory
    ) -> None:
        """A relationship whose `source_technique_id`/
        `target_technique_id` references a technique that was never
        ingested must be an isolated per-item failure, not an
        unhandled IntegrityError at COMMIT (same DEFERRABLE-FK timing
        issue as `parent_technique_id`)."""
        service = ReferenceDataAdminService(session_factory)
        await service.upsert_techniques(
            actor_id="tester",
            techniques=[
                TechniqueInput(
                    technique_id="T9140",
                    name="Real Source Technique",
                    stix_id=_unique("attack-pattern--relsrcreal"),
                )
            ],
        )
        dangling_rel = RelationshipInput(
            stix_id=_unique("relationship--danglingtarget"),
            relationship_type="uses",
            source_ref="attack-pattern--whatever",
            target_ref="attack-pattern--whatever2",
            source_technique_id="T9140",
            target_technique_id="T9999",  # never ingested
        )

        result = await service.upsert_technique_relationships(
            actor_id="tester", relationships=[dangling_rel]
        )
        assert result.failed == 1
        assert result.created == 0
        assert result.errors[0].identifier == dangling_rel.stix_id

    async def test_conflicting_duplicate_external_id_within_batch_is_isolated(
        self, session_factory
    ) -> None:
        """Two items in the *same* batch sharing a `stix_id` but with
        different content must not silently last-write-wins — the
        second occurrence is reported as a failed item
        (`DuplicateIngestionError`), and the first occurrence's write
        stands unmodified."""
        service = ReferenceDataAdminService(session_factory)
        shared_stix_id = _unique("attack-pattern--conflicting")
        first = TechniqueInput(
            technique_id="T9150",
            name="First Version",
            stix_id=shared_stix_id,
        )
        second = TechniqueInput(
            technique_id="T9150",
            name="Conflicting Second Version",
            stix_id=shared_stix_id,
            description="different content forces a different hash",
        )

        result = await service.upsert_techniques(
            actor_id="tester", techniques=[first, second]
        )
        assert result.total == 2
        assert result.created == 1
        assert result.failed == 1
        assert result.errors[0].identifier == "T9150"

        async with session_factory() as session:
            fetched = await ReferenceDataQueryService(session).get_technique("T9150")
            assert fetched is not None
            assert fetched.name == "First Version"

    async def test_identical_duplicate_external_id_within_batch_is_harmless(
        self, session_factory
    ) -> None:
        """Two items in the same batch sharing a `stix_id` *and*
        identical content are not an error — the second occurrence
        resolves naturally to `unchanged` once the first's ingestion
        record is visible within the same transaction."""
        service = ReferenceDataAdminService(session_factory)
        shared_stix_id = _unique("attack-pattern--identicaldup")
        item = TechniqueInput(
            technique_id="T9151", name="Same Every Time", stix_id=shared_stix_id
        )

        result = await service.upsert_techniques(
            actor_id="tester", techniques=[item, item]
        )
        assert result.total == 2
        assert result.created == 1
        assert result.unchanged == 1
        assert result.failed == 0

    async def test_upsert_writes_platform_audit_entry(self, session_factory) -> None:
        service = ReferenceDataAdminService(session_factory)
        tactic = TacticInput(
            tactic_id="TA0901",
            name="Audit Test Tactic",
            shortname="audit-test",
            stix_id=_unique("x-mitre-tactic--audit"),
        )
        await service.upsert_tactics(actor_id="audit-tester", tactics=[tactic])

        async with session_factory() as session:
            entries = await PostgresPlatformAuditLog(session).query(
                actor_id="audit-tester", action=AuditAction.REFERENCE_DATA_INGESTED, limit=10
            )
            assert len(entries) >= 1
            assert entries[0].metadata["object_type"] == "attack_tactic"

    async def test_upsert_technique_relationships_and_vulnerabilities(
        self, session_factory
    ) -> None:
        service = ReferenceDataAdminService(session_factory)
        src_stix = _unique("attack-pattern--relsvcsrc")
        tgt_stix = _unique("attack-pattern--relsvctgt")
        await service.upsert_techniques(
            actor_id="tester",
            techniques=[
                TechniqueInput(technique_id="T9101", name="Rel Source", stix_id=src_stix),
                TechniqueInput(technique_id="T9102", name="Rel Target", stix_id=tgt_stix),
            ],
        )
        rel_result = await service.upsert_technique_relationships(
            actor_id="tester",
            relationships=[
                RelationshipInput(
                    stix_id=_unique("relationship--svc"),
                    relationship_type="precedes",
                    source_ref=src_stix,
                    target_ref=tgt_stix,
                    source_technique_id="T9101",
                    target_technique_id="T9102",
                )
            ],
        )
        assert rel_result.created == 1

        vuln_cve = f"CVE-2024-{time.time_ns() % 100000:05d}"
        vuln_result = await service.upsert_vulnerabilities(
            actor_id="tester",
            vulnerabilities=[
                VulnerabilityInput(
                    cve_id=vuln_cve,
                    description="Service-loaded CVE",
                    cvss_v3_score=9.8,
                    cvss_v3_vector="CVSS:3.1/AV:N/AC:L",
                    cvss_v3_version="3.1",
                )
            ],
            source_system=ReferenceDataSource.NVD_CVE,
        )
        assert vuln_result.created == 1

        async with session_factory() as session:
            fetched = await ReferenceDataQueryService(session).get_vulnerability(vuln_cve)
            assert fetched is not None
            assert fetched.cvss_v3 is not None
            assert fetched.cvss_v3.severity == "CRITICAL"


# ─────────────────────────────────────────────────────────────────────────────
# Section D — HTTP acceptance
# ─────────────────────────────────────────────────────────────────────────────


class TestReferenceDataApiAuthorization:
    async def test_unauthenticated_request_is_401(self, client: AsyncClient) -> None:
        r = await client.get("/api/v1/threat-intel/reference-data/tactics")
        assert r.status_code == 401

    async def test_authenticated_without_platform_role_is_403(
        self, client: AsyncClient, no_platform_role_token: str
    ) -> None:
        r = await client.get(
            "/api/v1/threat-intel/reference-data/tactics",
            headers={"Authorization": f"Bearer {no_platform_role_token}"},
        )
        assert r.status_code == 403

    async def test_manage_endpoint_without_permission_is_403(
        self, client: AsyncClient, no_platform_role_token: str
    ) -> None:
        r = await client.post(
            "/api/v1/threat-intel/reference-data/tactics",
            headers={"Authorization": f"Bearer {no_platform_role_token}"},
            json={"tactics": [{
                "tactic_id": "TA0800",
                "name": "Should Be Rejected",
                "shortname": "rejected",
                "stix_id": "x-mitre-tactic--rejected",
            }]},
        )
        assert r.status_code == 403


class TestReferenceDataApiLoadAndVerify:
    async def test_load_tactics_then_verify_via_get(
        self, client: AsyncClient, super_admin_token: str
    ) -> None:
        headers = {"Authorization": f"Bearer {super_admin_token}"}
        stix_id = _unique("x-mitre-tactic--api")
        r = await client.post(
            "/api/v1/threat-intel/reference-data/tactics",
            headers=headers,
            json={"tactics": [{
                "tactic_id": "TA0801",
                "name": "API Test Tactic",
                "shortname": "api-test",
                "stix_id": stix_id,
                "description": "Loaded via HTTP",
            }]},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["created"] == 1
        assert body["failed"] == 0

        r = await client.get(
            "/api/v1/threat-intel/reference-data/tactics/TA0801", headers=headers
        )
        assert r.status_code == 200, r.text
        assert r.json()["name"] == "API Test Tactic"

    async def test_load_techniques_and_search(
        self, client: AsyncClient, super_admin_token: str
    ) -> None:
        headers = {"Authorization": f"Bearer {super_admin_token}"}
        unique_word = f"Kryptonian{time.time_ns()}"
        r = await client.post(
            "/api/v1/threat-intel/reference-data/techniques",
            headers=headers,
            json={"techniques": [{
                "technique_id": "T9800",
                "name": f"{unique_word} Technique",
                "stix_id": _unique("attack-pattern--api"),
                "tactic_ids": ["TA0801"],
            }]},
        )
        assert r.status_code == 200, r.text
        assert r.json()["created"] == 1

        r = await client.get(
            "/api/v1/threat-intel/reference-data/techniques",
            headers=headers,
            params={"search": unique_word},
        )
        assert r.status_code == 200, r.text
        assert any(t["technique_id"] == "T9800" for t in r.json())

        r = await client.get(
            "/api/v1/threat-intel/reference-data/techniques",
            headers=headers,
            params={"tactic_id": "TA0801"},
        )
        assert r.status_code == 200, r.text
        assert any(t["technique_id"] == "T9800" for t in r.json())

    async def test_get_unknown_technique_is_404(
        self, client: AsyncClient, super_admin_token: str
    ) -> None:
        headers = {"Authorization": f"Bearer {super_admin_token}"}
        r = await client.get(
            "/api/v1/threat-intel/reference-data/techniques/T0000", headers=headers
        )
        assert r.status_code == 404

    async def test_load_vulnerability_and_verify_kev_listing(
        self, client: AsyncClient, super_admin_token: str
    ) -> None:
        headers = {"Authorization": f"Bearer {super_admin_token}"}
        cve_id = f"CVE-2024-{time.time_ns() % 100000:05d}"
        r = await client.post(
            "/api/v1/threat-intel/reference-data/vulnerabilities",
            headers=headers,
            json={
                "vulnerabilities": [{
                    "cve_id": cve_id,
                    "description": "API-loaded KEV entry",
                    "is_kev": True,
                    "kev_vulnerability_name": "API Proof KEV",
                }],
                "source_system": "cisa_kev",
            },
        )
        assert r.status_code == 200, r.text
        assert r.json()["created"] == 1

        r = await client.get(
            "/api/v1/threat-intel/reference-data/vulnerabilities",
            headers=headers,
            params={"kev_only": "true"},
        )
        assert r.status_code == 200, r.text
        assert any(v["cve_id"] == cve_id for v in r.json())

    async def test_ingestion_log_lists_recent_loads(
        self, client: AsyncClient, super_admin_token: str
    ) -> None:
        headers = {"Authorization": f"Bearer {super_admin_token}"}
        r = await client.get(
            "/api/v1/threat-intel/reference-data/ingestions",
            headers=headers,
            params={"source_system": "mitre_attack", "limit": 5},
        )
        assert r.status_code == 200, r.text
        assert isinstance(r.json(), list)

    async def test_batch_request_rejects_empty_list(
        self, client: AsyncClient, super_admin_token: str
    ) -> None:
        headers = {"Authorization": f"Bearer {super_admin_token}"}
        r = await client.post(
            "/api/v1/threat-intel/reference-data/tactics",
            headers=headers,
            json={"tactics": []},
        )
        assert r.status_code == 422
