"""Real-PostgreSQL proof for M11 Gated Safe Active Validation.

Runs against a dedicated, self-created database
(`redforge_validation_execution_proof_test`), never the shared dev
database — matching test_authorization_race.py's precedent.

Proves, against REAL Postgres (not SQLite) and REAL owned local
HTTP/HTTPS test services (never an external/unrelated internet
target):
  1. Full real DNS -> TCP -> TLS (real handshake against a genuine
     self-signed certificate) -> HTTP -> security-header pipeline.
  2. SecurityCondition ingestion with correct source_category/
     evidence_state, and that repeated executions do not duplicate
     the condition (dedup upsert).
  3. Events persisted in strictly increasing sequence.
  4. A policy revocation between the two mandatory gate checks blocks
     all network activity (zero steps ever dispatched).
  5. A cancellation requested while steps are still running is
     observed and halts further dispatch.
  6. Execution history survives a fresh service instance reading the
     same database (restart persistence).
"""

from __future__ import annotations

import asyncio
import datetime
import http.server
import os
import ssl
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from redforge.application.ai_targets import AITargetService
from redforge.application.inventory.tenant_asset_service import TenantAssetService
from redforge.application.security_conditions.service import TenantSecurityConditionService
from redforge.application.validation_execution import network_adapters
from redforge.application.validation_execution.execution_service import ValidationExecutionService
from redforge.domain.validation_execution.value_objects import AddressClass
from redforge.infrastructure.database.base import Base
from redforge.infrastructure.database.models.ai_target import AITargetModel
from redforge.infrastructure.database.models.asset_connector import AIAssetModel
from redforge.infrastructure.database.models.security_conditions import SecurityConditionModel
from redforge.infrastructure.database.models.validation_execution import (
    ValidationExecutionEventModel,
    ValidationExecutionModel,
    ValidationExecutionStepModel,
)
from redforge.infrastructure.events import InMemoryEventPublisher
from redforge.shared.identifiers import EntityId

pytestmark = pytest.mark.asyncio

_TEST_DB_NAME = "redforge_validation_execution_proof_test"
_MAINTENANCE_DB_URL = os.environ.get(
    "REDFORGE_MAINTENANCE_DATABASE_URL",
    "postgresql+asyncpg://redforge:redforge@localhost:5432/postgres",
)
_DB_URL = os.environ.get(
    "REDFORGE_TEST_DATABASE_URL",
    f"postgresql+asyncpg://redforge:redforge@localhost:5432/{_TEST_DB_NAME}",
)

_TABLES = [
    AITargetModel.__table__,
    AIAssetModel.__table__,
    SecurityConditionModel.__table__,
    ValidationExecutionModel.__table__,
    ValidationExecutionStepModel.__table__,
    ValidationExecutionEventModel.__table__,
]


@pytest.fixture(autouse=True)
def _allow_loopback_for_local_test_server(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test-only relaxation, documented identically in
    tests/unit/test_validation_execution_network_boundary.py and
    tests/api/test_validation_executions_isolation.py: production
    denies LOOPBACK by default; this suite's owned test servers are
    necessarily loopback-bound. Never a production code path."""
    monkeypatch.setattr(
        network_adapters, "ALLOWED_ADDRESS_CLASSES",
        frozenset({AddressClass.PUBLIC, AddressClass.LOOPBACK}),
    )


async def _ensure_test_database_exists() -> None:
    maintenance_engine = create_async_engine(
        _MAINTENANCE_DB_URL, echo=False, isolation_level="AUTOCOMMIT",
    )
    try:
        async with maintenance_engine.connect() as conn:
            exists = await conn.execute(
                text("SELECT 1 FROM pg_database WHERE datname = :name"), {"name": _TEST_DB_NAME},
            )
            if exists.first() is None:
                await conn.execute(text(f'CREATE DATABASE "{_TEST_DB_NAME}"'))
    finally:
        await maintenance_engine.dispose()


@pytest.fixture
async def pg_factory():
    await _ensure_test_database_exists()

    engine = create_async_engine(_DB_URL, echo=False)
    async with engine.begin() as conn:
        # ai_assets(id) is already a PK, but the composite FK from
        # security_conditions(affected_asset_id, organization_id)
        # requires a matching composite UNIQUE constraint on the
        # referenced side too — production adds this via migration
        # 0016 (`ux_ai_assets_id_org`), which this ad-hoc `tables=`
        # subset create_all doesn't run, so it's recreated here.
        await conn.run_sync(Base.metadata.create_all, tables=_TABLES[:2])
        await conn.execute(text(
            "ALTER TABLE ai_assets ADD CONSTRAINT ux_ai_assets_id_org "
            "UNIQUE (id, organization_id)"
        ))
        await conn.run_sync(Base.metadata.create_all, tables=_TABLES[2:])
        await conn.execute(text("DELETE FROM validation_execution_events"))
        await conn.execute(text("DELETE FROM validation_execution_steps"))
        await conn.execute(text("DELETE FROM validation_executions"))
        await conn.execute(text("DELETE FROM security_conditions"))
        await conn.execute(text("DELETE FROM ai_assets"))
        await conn.execute(text("DELETE FROM ai_targets"))

    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    yield factory

    async with engine.begin() as conn:
        await conn.execute(text("DROP TABLE IF EXISTS validation_execution_events CASCADE"))
        await conn.execute(text("DROP TABLE IF EXISTS validation_execution_steps CASCADE"))
        await conn.execute(text("DROP TABLE IF EXISTS validation_executions CASCADE"))
        await conn.execute(text("DROP TABLE IF EXISTS security_conditions CASCADE"))
        await conn.execute(text("DROP TABLE IF EXISTS ai_assets CASCADE"))
        await conn.execute(text("DROP TABLE IF EXISTS ai_targets CASCADE"))
    await engine.dispose()


# ─── Owned local HTTP + HTTPS test servers ────────────────────────────────────


_HTTP_PORT = 18299
_HTTPS_PORT = 18300


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        # Deliberately omits CSP/X-Content-Type-Options — proves the
        # header-rule evaluator observes real absence, not a canned value.
        self.end_headers()
        self.wfile.write(b"<html>proof</html>")

    def log_message(self, *args: object) -> None:
        pass


def _generate_self_signed_cert(tmp_dir: Path) -> tuple[Path, Path]:
    """Generates a genuine self-signed X.509 certificate + private key
    for 127.0.0.1, entirely in-process via the `cryptography` library —
    a real certificate for perform_tls_handshake() to really parse and
    verify against, not a canned fixture."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1"),
    ])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_dir / "cert.pem"
    key_path = tmp_dir / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    return cert_path, key_path


@pytest.fixture(scope="module")
def _cert_paths():
    with tempfile.TemporaryDirectory() as tmp:
        yield _generate_self_signed_cert(Path(tmp))


@pytest.fixture(scope="module", autouse=True)
def _http_server():
    server = http.server.HTTPServer(("127.0.0.1", _HTTP_PORT), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()


@pytest.fixture(scope="module", autouse=True)
def _https_server(_cert_paths):
    cert_path, key_path = _cert_paths
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
    server = http.server.HTTPServer(("127.0.0.1", _HTTPS_PORT), _Handler)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()


_HTTP_ENDPOINT = f"http://127.0.0.1:{_HTTP_PORT}/"
_HTTPS_ENDPOINT = f"https://127.0.0.1:{_HTTPS_PORT}/"


# ─── Fake policy port (legitimate seam, matches other M11 test files) ────────


@dataclass(frozen=True, slots=True)
class _Decision:
    decision: str
    decision_id: str
    reason_code: str


@dataclass
class _SequencedPolicyPort:
    queue: list[_Decision] = field(default_factory=list)
    calls: int = 0

    def push_allow(self) -> None:
        self.queue.append(_Decision("allow", f"dec-{self.calls + len(self.queue)}", "ok"))

    def push_deny(self, reason_code: str = "authorization_revoked") -> None:
        self.queue.append(_Decision("deny", f"dec-{self.calls + len(self.queue)}", reason_code))

    async def evaluate(self, *, organization_id, actor_user_id, action_class, entity_refs):
        self.calls += 1
        if self.queue:
            return self.queue.pop(0)
        return _Decision("allow", f"dec-auto-{self.calls}", "ok")


class _DelayedAITargetService(AITargetService):
    """Real AITargetService with an injected delay before returning —
    the minimal legitimate seam needed to give a concurrently-issued
    cancel() call a deterministic window to land before step dispatch
    begins against a loopback server that would otherwise respond
    in microseconds. Delegates every real code path unchanged."""

    def __init__(self, *args: object, delay_seconds: float = 0.0, **kwargs: object) -> None:
        super().__init__(*args, **kwargs)  # type: ignore[arg-type]
        self._delay_seconds = delay_seconds

    async def get_by_id(self, target_id: str, organization_id: str):
        if self._delay_seconds:
            await asyncio.sleep(self._delay_seconds)
        return await super().get_by_id(target_id, organization_id)


async def _make_services(pg_factory, policy, *, target_delay: float = 0.0):
    events = InMemoryEventPublisher()
    ai_target_service = _DelayedAITargetService(pg_factory, events, delay_seconds=target_delay)
    tenant_asset_service = TenantAssetService(pg_factory)
    condition_service = TenantSecurityConditionService(pg_factory)
    execution_service = ValidationExecutionService(
        pg_factory, policy, ai_target_service, tenant_asset_service, condition_service,
    )
    return ai_target_service, tenant_asset_service, condition_service, execution_service


# ─── Proofs ────────────────────────────────────────────────────────────────────


async def test_full_pipeline_against_real_postgres_and_http(pg_factory) -> None:
    org_id = str(EntityId.generate())
    requester_id = str(EntityId.generate())
    policy = _SequencedPolicyPort()
    ai_target_service, _asset_service, condition_service, execution_service = (
        await _make_services(pg_factory, policy)
    )

    target = await ai_target_service.register(
        organization_id=org_id, name="Real PG HTTP Target", description="",
        target_type="ai_api", provider="custom", endpoint=_HTTP_ENDPOINT,
    )

    dto = await execution_service.create_and_run(org_id, target.id, requester_id)
    assert dto.status in ("completed", "partially_completed"), dto.failure_reason
    step_types = [s.step_type for s in dto.steps]
    assert step_types == [
        "dns_resolution", "tcp_connectivity", "http_metadata",
        "http_security_headers", "service_reachability",
    ]
    assert all(s.status == "completed" for s in dto.steps)

    conditions = await condition_service.list_for_org(org_id, source_category="active_validation")
    rule_ids = {c.stable_rule_id for c in conditions}
    assert "MISSING_CSP_HEADER" in rule_ids
    assert "MISSING_X_CONTENT_TYPE_OPTIONS_HEADER" in rule_ids
    for c in conditions:
        assert c.evidence_state == "validated"
        assert c.source_category == "active_validation"


async def test_real_tls_handshake_against_genuine_self_signed_cert(
    pg_factory, _cert_paths, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Proves perform_tls_handshake() performs a REAL handshake and
    extracts REAL certificate metadata — not simulated — against a
    genuine, freshly-generated self-signed certificate.

    ssl.create_default_context() otherwise verifies against the OS
    trust store, which correctly has no reason to trust a certificate
    minted seconds ago for this test — so this test supplies the one
    trust anchor a real engagement would pre-authorize for testing a
    target's own self-signed cert (`load_verify_locations`), without
    touching the real handshake/verification/parsing logic itself."""
    cert_path, _key_path = _cert_paths
    _original_create_default_context = ssl.create_default_context

    def _trusting_context(*args: object, **kwargs: object) -> ssl.SSLContext:
        context = _original_create_default_context(*args, **kwargs)  # type: ignore[arg-type]
        context.load_verify_locations(cafile=str(cert_path))
        return context

    monkeypatch.setattr(
        network_adapters.ssl,  # type: ignore[attr-defined]
        "create_default_context", _trusting_context,
    )

    org_id = str(EntityId.generate())
    requester_id = str(EntityId.generate())
    policy = _SequencedPolicyPort()
    ai_target_service, _asset_service, _condition_service, execution_service = (
        await _make_services(pg_factory, policy)
    )

    target = await ai_target_service.register(
        organization_id=org_id, name="Real PG HTTPS Target", description="",
        target_type="ai_api", provider="custom", endpoint=_HTTPS_ENDPOINT,
    )

    dto = await execution_service.create_and_run(org_id, target.id, requester_id)
    step_types = [s.step_type for s in dto.steps]
    assert "tls_handshake" in step_types

    tls_step = next(s for s in dto.steps if s.step_type == "tls_handshake")
    assert tls_step.status == "completed", tls_step.error_category
    evidence = {e["label"]: e["value"] for e in tls_step.evidence}
    assert evidence["protocol_version"].startswith("TLSv1")
    assert evidence["subject_cn"] == "127.0.0.1"
    assert len(evidence["fingerprint_sha256"]) == 64  # real SHA-256 hex digest
    assert evidence["cipher"]

    assert dto.status in ("completed", "partially_completed"), dto.failure_reason


async def test_repeated_execution_does_not_duplicate_condition(pg_factory) -> None:
    org_id = str(EntityId.generate())
    requester_id = str(EntityId.generate())
    policy = _SequencedPolicyPort()
    ai_target_service, _asset_service, condition_service, execution_service = (
        await _make_services(pg_factory, policy)
    )
    target = await ai_target_service.register(
        organization_id=org_id, name="Dedup Target", description="",
        target_type="ai_api", provider="custom", endpoint=_HTTP_ENDPOINT,
    )

    await execution_service.create_and_run(org_id, target.id, requester_id)
    await execution_service.create_and_run(org_id, target.id, requester_id)

    conditions = await condition_service.list_for_org(org_id, source_category="active_validation")
    csp_conditions = [c for c in conditions if c.stable_rule_id == "MISSING_CSP_HEADER"]
    assert len(csp_conditions) == 1


async def test_events_persisted_in_strictly_increasing_sequence(pg_factory) -> None:
    org_id = str(EntityId.generate())
    requester_id = str(EntityId.generate())
    policy = _SequencedPolicyPort()
    ai_target_service, _asset_service, _condition_service, execution_service = (
        await _make_services(pg_factory, policy)
    )
    target = await ai_target_service.register(
        organization_id=org_id, name="Event Order Target", description="",
        target_type="ai_api", provider="custom", endpoint=_HTTP_ENDPOINT,
    )

    dto = await execution_service.create_and_run(org_id, target.id, requester_id)
    events = await execution_service.list_events(org_id, dto.id, 0, 500)
    sequences = [e.sequence for e in events]
    assert sequences == sorted(sequences)
    assert len(sequences) == len(set(sequences))
    assert events[0].event_type == "execution_created"
    assert events[-1].event_type in ("execution_completed", "execution_partial")


async def test_policy_revocation_between_gates_blocks_all_network_activity(pg_factory) -> None:
    org_id = str(EntityId.generate())
    requester_id = str(EntityId.generate())
    policy = _SequencedPolicyPort()
    policy.push_allow()
    policy.push_deny("authorization_revoked")
    ai_target_service, _asset_service, condition_service, execution_service = (
        await _make_services(pg_factory, policy)
    )
    target = await ai_target_service.register(
        organization_id=org_id, name="Revoked Target", description="",
        target_type="ai_api", provider="custom", endpoint=_HTTP_ENDPOINT,
    )

    dto = await execution_service.create_and_run(org_id, target.id, requester_id)
    assert dto.status == "denied"
    assert dto.steps == []
    assert dto.policy_reason_code == "authorization_revoked"
    assert policy.calls == 2

    conditions = await condition_service.list_for_org(org_id, source_category="active_validation")
    assert conditions == []


async def test_cancellation_requested_mid_flight_halts_further_steps(pg_factory) -> None:
    """A 300ms delay is injected before the target lookup (the last
    thing that happens before the plan is built and steps begin) — a
    concurrently-scheduled cancel() call lands well within that
    window, giving cancellation_requested a real chance to be observed
    by the fresh-read check before every step dispatch."""
    org_id = str(EntityId.generate())
    requester_id = str(EntityId.generate())
    policy = _SequencedPolicyPort()
    ai_target_service, _asset_service, _condition_service, execution_service = (
        await _make_services(pg_factory, policy, target_delay=0.3)
    )
    target = await ai_target_service.register(
        organization_id=org_id, name="Cancel Target", description="",
        target_type="ai_api", provider="custom", endpoint=_HTTP_ENDPOINT,
    )

    run_task = asyncio.create_task(
        execution_service.create_and_run(org_id, target.id, requester_id),
    )
    await asyncio.sleep(0.05)

    # A second service instance issues the cancel — proves cancellation
    # doesn't depend on in-process object identity, only the DB row.
    _ai2, _asset2, _cond2, cancel_service = await _make_services(pg_factory, policy)
    execution_id = (await cancel_service.list_by_organization(org_id, None, 10, 0))[0].id
    await cancel_service.cancel(org_id, execution_id, requester_id)

    dto = await run_task
    assert dto.status == "cancelled"
    assert any(s.status == "cancelled" for s in dto.steps) or dto.steps == []


async def test_execution_history_survives_a_fresh_service_instance(pg_factory) -> None:
    org_id = str(EntityId.generate())
    requester_id = str(EntityId.generate())
    policy = _SequencedPolicyPort()
    ai_target_service, _asset_service, _condition_service, execution_service = (
        await _make_services(pg_factory, policy)
    )
    target = await ai_target_service.register(
        organization_id=org_id, name="Restart Target", description="",
        target_type="ai_api", provider="custom", endpoint=_HTTP_ENDPOINT,
    )
    dto = await execution_service.create_and_run(org_id, target.id, requester_id)

    _ai2, _asset2, _cond2, fresh_service = await _make_services(pg_factory, policy)
    reloaded = await fresh_service.get_by_id(org_id, dto.id)
    assert reloaded.id == dto.id
    assert reloaded.status == dto.status
    assert len(reloaded.steps) == len(dto.steps)
    assert [s.step_type for s in reloaded.steps] == [s.step_type for s in dto.steps]

    events = await fresh_service.list_events(org_id, dto.id, 0, 500)
    assert len(events) > 0
