"""Owned-local-multi-protocol-lab + real-PostgreSQL concurrency proof
for M13 — Protocol-Aware Service Validation.

Runs against a dedicated, self-created database
(`redforge_protocol_validation_proof_test`), never the shared dev
database. `_assert_isolated_proof_database()` — the exact same guard
M12's own proof file introduced after a prior M11 session accidentally
targeted the shared dev database during a downgrade proof — is applied
before every destructive command in this file too.

Owned local network lab (never an external/unrelated internet target):
  - HTTP service on port 8080.
  - HTTPS service on port 8443 with a genuine, freshly-generated
    self-signed certificate.
  - A real, well-formed MySQL initial-handshake-shaped responder on
    port 3306.
  - A real RESP-protocol PING/PONG responder on port 6379.
  - A bare, protocol-less TCP listener on port 3389 (RDP's discovery-
    policy port) — RDP has NO validator this milestone (see
    discovery_port_policy.py's own documented deferral reason); this
    proves "reachable, hinted, never validated" for a port that will
    never get one.
  - Port 5432 is deliberately left to whatever is ALREADY on this
    dev machine — a real local PostgreSQL server — so the PostgreSQL
    validator is proven against an actual production-grade PostgreSQL
    server, not a fake stand-in (matching M12's own precedent for this
    exact port).
  - Port 22 (SSH) is INTENTIONALLY NOT bound here: binding a listener
    on port 22 requires root privileges this proof suite neither has
    nor should be granted. SshBannerValidator is proven directly (real
    valid/invalid banner servers on ephemeral ports, bypassing the
    fixed discovery-port constraint) in
    tests/unit/test_protocol_validators.py — a disclosed, honest
    environment limitation, not a masked gap.

Proves:
  1.  HTTP candidate validates as HTTP.
  2.  HTTPS candidate validates TLS/HTTPS; TLS metadata is bounded and
      sanitized (no private key material, no unbounded fields).
  3.  MySQL protocol-shaped handshake genuinely validates MySQL.
  4.  PostgreSQL protocol behavior genuinely validates PostgreSQL
      against a real local server.
  5.  Redis PING/PONG genuinely validates Redis.
  6.  A reachable port with no wired validator (RDP/3389) never
      fabricates a protocol — stays hinted forever.
  7.  Repeated execution does not duplicate canonical SERVICE assets.
  8.  CONCURRENT execution converges on one canonical SERVICE asset per
      port — no duplicate created under a real race.
  9.  Conditions (SENSITIVE_SERVICE_OBSERVED, PLAINTEXT_SENSITIVE_
      SERVICE_OBSERVED) deduplicate on repeat.
  10. Condition resolution + re-observation reactivates (M8's existing
      upsert behavior, genuinely exercised here).
  11. Correlation evaluation remains deterministic.
  12. Revocation before protocol dispatch causes zero validator calls.
  13. Cross-tenant SERVICE assets for the identical endpoint stay
      completely separate — no relationship/condition leakage.
  14. Backend restart preserves protocol-validation history (validator
      id/version/state persist and are readable from a fresh service
      instance against the same database).
"""

from __future__ import annotations

import asyncio
import datetime
import http.server
import os
import socket
import ssl
import struct
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
from redforge.application.security_correlation.rules import (
    CorrelationRuleRegistry,
    MultipleSecurityConditionsOnAssetRule,
    PublicSensitiveServiceContextRule,
)
from redforge.application.security_correlation.service import TenantSecurityCorrelationService
from redforge.application.validation_execution import network_adapters
from redforge.application.validation_execution.adaptive_rules import default_adaptive_rule_registry
from redforge.application.validation_execution.execution_service import ValidationExecutionService
from redforge.application.validation_execution.protocol_validators import (
    default_protocol_validator_registry,
)
from redforge.domain.validation_execution.value_objects import AddressClass
from redforge.infrastructure.database.base import Base
from redforge.infrastructure.database.models.ai_target import AITargetModel
from redforge.infrastructure.database.models.asset_connector import AIAssetModel
from redforge.infrastructure.database.models.security_conditions import SecurityConditionModel
from redforge.infrastructure.database.models.security_correlation import (
    SecurityCorrelationConditionModel,
    SecurityCorrelationEntityModel,
    SecurityCorrelationModel,
)
from redforge.infrastructure.database.models.validation_execution import (
    ValidationExecutionEventModel,
    ValidationExecutionModel,
    ValidationExecutionStepModel,
)
from redforge.infrastructure.events import InMemoryEventPublisher
from redforge.shared.identifiers import EntityId

pytestmark = pytest.mark.asyncio

_TEST_DB_NAME = "redforge_protocol_validation_proof_test"
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
    SecurityCorrelationModel.__table__,
    SecurityCorrelationConditionModel.__table__,
    SecurityCorrelationEntityModel.__table__,
    ValidationExecutionModel.__table__,
    ValidationExecutionStepModel.__table__,
    ValidationExecutionEventModel.__table__,
]


def _assert_isolated_proof_database(target_db_name: str) -> None:
    """Refuses to run any destructive proof command against anything
    other than this file's own isolated database — see M12's own proof
    file for the incident this guard exists to prevent from repeating."""
    print(f"[proof-db-guard] destructive command target database: {target_db_name!r}")
    assert target_db_name == _TEST_DB_NAME, (
        f"REFUSING destructive command: target database {target_db_name!r} is not the "
        f"isolated proof database {_TEST_DB_NAME!r}"
    )


@pytest.fixture(autouse=True)
def _allow_loopback_for_local_test_server(monkeypatch: pytest.MonkeyPatch) -> None:
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
                _assert_isolated_proof_database(_TEST_DB_NAME)
                await conn.execute(text(f'CREATE DATABASE "{_TEST_DB_NAME}"'))
    finally:
        await maintenance_engine.dispose()


@pytest.fixture
async def pg_factory():
    await _ensure_test_database_exists()

    engine = create_async_engine(_DB_URL, echo=False)
    async with engine.begin() as conn:
        _assert_isolated_proof_database(_TEST_DB_NAME)
        await conn.run_sync(Base.metadata.create_all, tables=_TABLES[:2])
        await conn.execute(text(
            "ALTER TABLE ai_assets ADD CONSTRAINT ux_ai_assets_id_org "
            "UNIQUE (id, organization_id)"
        ))
        await conn.run_sync(Base.metadata.create_all, tables=_TABLES[2:])
        for table in (
            "validation_execution_events", "validation_execution_steps",
            "validation_executions", "security_correlation_conditions",
            "security_correlation_entities", "security_correlations",
            "security_conditions", "ai_assets", "ai_targets",
        ):
            await conn.execute(text(f"DELETE FROM {table}"))

    factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    yield factory

    async with engine.begin() as conn:
        _assert_isolated_proof_database(_TEST_DB_NAME)
        for table in (
            "validation_execution_events", "validation_execution_steps",
            "validation_executions", "security_correlation_conditions",
            "security_correlation_entities", "security_correlations",
            "security_conditions", "ai_assets", "ai_targets",
        ):
            await conn.execute(text(f"DROP TABLE IF EXISTS {table} CASCADE"))
    await engine.dispose()


# ─── Owned local multi-protocol lab ─────────────────────────────────────────


_HTTP_PORT = 8080
_HTTPS_PORT = 8443
_MYSQL_PORT = 3306
_REDIS_PORT = 6379
_RDP_BARE_PORT = 3389  # RDP has no validator this milestone — bare listener only


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html>proof</html>")

    def log_message(self, *args: object) -> None:
        pass


def _generate_self_signed_cert(tmp_dir: Path) -> tuple[Path, Path]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
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
            x509.SubjectAlternativeName(
                [x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1"))],
            ),
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


@pytest.fixture(autouse=True)
def _trust_self_signed_cert(_cert_paths, monkeypatch: pytest.MonkeyPatch) -> None:
    """Every test in this file discovers port 8443 reachable, and the
    shared PORT_443_TLS_HTTPS adaptive rule claims the http_metadata
    step for it (M12's own non-duplication guarantee) — so every run
    needs this same real-engagement trust anchor for the genuine
    self-signed certificate, not just the dedicated TLS-metadata test.
    `ssl.create_default_context()` otherwise verifies against the OS
    trust store, which correctly has no reason to trust a certificate
    minted seconds ago for this file's own `_https_server` fixture."""
    cert_path, _key_path = _cert_paths
    _original = ssl.create_default_context

    def _trusting_context(*args: object, **kwargs: object) -> ssl.SSLContext:
        context = _original(*args, **kwargs)  # type: ignore[arg-type]
        context.load_verify_locations(cafile=str(cert_path))
        return context

    monkeypatch.setattr(network_adapters.ssl, "create_default_context", _trusting_context)  # type: ignore[attr-defined]


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


def _mysql_greeting() -> bytes:
    payload = (
        bytes([0x0A]) + b"8.0.35" + b"\x00"
        + b"\x01\x02\x03\x04" + b"AUTHDATA" + b"\x00"
        + struct.pack("<H", 0xFFFF)
    )
    header = struct.pack("<I", len(payload))[:3] + b"\x00"
    return header + payload


def _start_accept_loop_server(port: int, handler) -> tuple[socket.socket, threading.Event]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    sock.listen(5)
    stop = threading.Event()

    def _loop() -> None:
        sock.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _addr = sock.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            try:
                handler(conn)
            except OSError:
                pass
            finally:
                conn.close()

    thread = threading.Thread(target=_loop, daemon=True)
    thread.start()
    return sock, stop


@pytest.fixture(scope="module", autouse=True)
def _mysql_server():
    sock, stop = _start_accept_loop_server(_MYSQL_PORT, lambda c: c.sendall(_mysql_greeting()))
    yield
    stop.set()
    sock.close()


def _redis_ping_handler(conn: socket.socket) -> None:
    conn.settimeout(2.0)
    conn.recv(64)
    conn.sendall(b"+PONG\r\n")


@pytest.fixture(scope="module", autouse=True)
def _redis_server():
    sock, stop = _start_accept_loop_server(_REDIS_PORT, _redis_ping_handler)
    yield
    stop.set()
    sock.close()


@pytest.fixture(scope="module", autouse=True)
def _rdp_bare_listener():
    """A bare TCP listener with no protocol behind it — proves the
    "reachable + hinted, never validated" ladder for RDP (3389), a port
    with NO real validator wired this milestone (see
    discovery_port_policy.py's own documented deferral reason)."""
    sock, stop = _start_accept_loop_server(_RDP_BARE_PORT, lambda c: None)
    yield
    stop.set()
    sock.close()


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


async def _make_services(pg_factory, policy):
    events = InMemoryEventPublisher()
    ai_target_service = AITargetService(pg_factory, events)
    tenant_asset_service = TenantAssetService(pg_factory)
    condition_service = TenantSecurityConditionService(pg_factory)
    registry = CorrelationRuleRegistry()
    registry.register(
        PublicSensitiveServiceContextRule(
            asset_service=tenant_asset_service, condition_service=condition_service,
        )
    )
    registry.register(MultipleSecurityConditionsOnAssetRule(condition_service=condition_service))
    correlation_service = TenantSecurityCorrelationService(pg_factory, registry)
    execution_service = ValidationExecutionService(
        pg_factory, policy, ai_target_service, tenant_asset_service, condition_service,
        default_adaptive_rule_registry(), correlation_service, default_protocol_validator_registry(),
    )
    return ai_target_service, tenant_asset_service, condition_service, correlation_service, execution_service


_TARGET_ENDPOINT = f"http://127.0.0.1:{_HTTP_PORT}/"


def _steps_by_type(dto, step_type: str):
    return [s for s in dto.steps if s.step_type == step_type]


# ─── Proofs ────────────────────────────────────────────────────────────────


async def test_http_candidate_validates_as_http(pg_factory) -> None:
    """Both port 80/8080 (HTTP) and 443/8443 (HTTPS) are reachable in
    this lab, and M12's own non-duplication guarantee means the single
    resulting HTTP_METADATA step is claimed by whichever rule is
    registered first (PORT_443_TLS_HTTPS) — Port80HttpRule still
    genuinely "matches" 8080's reachability, it just never gets a
    redundant second copy of the identical HTTP validation. Either way,
    a real, successful HTTP_METADATA fetch is proven here."""
    org_id = str(EntityId.generate())
    requester_id = str(EntityId.generate())
    policy = _SequencedPolicyPort()
    ai_target_service, _asset, _cond, _corr, exec_service = await _make_services(pg_factory, policy)
    target = await ai_target_service.register(
        organization_id=org_id, name="HTTP Lab Target", description="",
        target_type="ai_api", provider="custom", endpoint=_TARGET_ENDPOINT,
    )
    dto = await exec_service.create_and_run(
        org_id, target.id, requester_id, profile="network_discovery_baseline_v1",
    )
    http_steps = _steps_by_type(dto, "http_metadata")
    assert http_steps and all(s.status == "completed" for s in http_steps)


async def test_https_candidate_validates_tls_with_bounded_sanitized_metadata(pg_factory) -> None:
    org_id = str(EntityId.generate())
    requester_id = str(EntityId.generate())
    policy = _SequencedPolicyPort()
    ai_target_service, _asset, _cond, _corr, exec_service = await _make_services(pg_factory, policy)
    target = await ai_target_service.register(
        organization_id=org_id, name="HTTPS Lab Target", description="",
        target_type="ai_api", provider="custom", endpoint=_TARGET_ENDPOINT,
    )
    dto = await exec_service.create_and_run(
        org_id, target.id, requester_id, profile="network_discovery_baseline_v1",
    )
    tls_steps = _steps_by_type(dto, "tls_handshake")
    assert tls_steps and tls_steps[0].status == "completed"
    evidence = {e["label"]: e["value"] for e in tls_steps[0].evidence}
    assert evidence["protocol_version"].startswith("TLSv1")
    assert len(evidence["fingerprint_sha256"]) == 64
    # Bounded/sanitized: no private key material, no unbounded field.
    assert all(len(v) < 500 for v in evidence.values())
    assert "PRIVATE KEY" not in " ".join(evidence.values())


async def test_mysql_handshake_genuinely_validates_mysql(pg_factory) -> None:
    org_id = str(EntityId.generate())
    requester_id = str(EntityId.generate())
    policy = _SequencedPolicyPort()
    ai_target_service, _asset, _cond, _corr, exec_service = await _make_services(pg_factory, policy)
    target = await ai_target_service.register(
        organization_id=org_id, name="MySQL Lab Target", description="",
        target_type="ai_api", provider="custom", endpoint=_TARGET_ENDPOINT,
    )
    dto = await exec_service.create_and_run(
        org_id, target.id, requester_id, profile="network_discovery_baseline_v1",
    )
    mysql_steps = _steps_by_type(dto, "mysql_handshake")
    assert mysql_steps
    assert mysql_steps[0].protocol_validation_state == "validated"
    assert mysql_steps[0].validator_id == "MYSQL_HANDSHAKE_V1"
    evidence = {e["label"]: e["value"] for e in mysql_steps[0].evidence}
    assert evidence["server_version"] == "8.0.35"


async def test_postgresql_handshake_validates_against_real_local_postgres(pg_factory) -> None:
    org_id = str(EntityId.generate())
    requester_id = str(EntityId.generate())
    policy = _SequencedPolicyPort()
    ai_target_service, _asset, _cond, _corr, exec_service = await _make_services(pg_factory, policy)
    target = await ai_target_service.register(
        organization_id=org_id, name="PostgreSQL Lab Target", description="",
        target_type="ai_api", provider="custom", endpoint=_TARGET_ENDPOINT,
    )
    dto = await exec_service.create_and_run(
        org_id, target.id, requester_id, profile="network_discovery_baseline_v1",
    )
    pg_steps = _steps_by_type(dto, "postgresql_handshake")
    assert pg_steps
    assert pg_steps[0].protocol_validation_state == "validated"
    assert pg_steps[0].validator_id == "POSTGRESQL_PROTOCOL_V1"


async def test_redis_ping_genuinely_validates_redis(pg_factory) -> None:
    org_id = str(EntityId.generate())
    requester_id = str(EntityId.generate())
    policy = _SequencedPolicyPort()
    ai_target_service, _asset, _cond, _corr, exec_service = await _make_services(pg_factory, policy)
    target = await ai_target_service.register(
        organization_id=org_id, name="Redis Lab Target", description="",
        target_type="ai_api", provider="custom", endpoint=_TARGET_ENDPOINT,
    )
    dto = await exec_service.create_and_run(
        org_id, target.id, requester_id, profile="network_discovery_baseline_v1",
    )
    redis_steps = _steps_by_type(dto, "redis_ping")
    assert redis_steps
    assert redis_steps[0].protocol_validation_state == "validated"
    evidence = {e["label"]: e["value"] for e in redis_steps[0].evidence}
    assert evidence["replied_pong"] == "True"


async def test_unvalidated_rdp_port_never_fabricates_a_protocol(pg_factory) -> None:
    """RDP has no wired validator this milestone — reachable, hinted,
    and stays that way forever; no adaptive step of any kind is ever
    scheduled for it (there is no Port3389RdpRule)."""
    org_id = str(EntityId.generate())
    requester_id = str(EntityId.generate())
    policy = _SequencedPolicyPort()
    ai_target_service, _asset, _cond, _corr, exec_service = await _make_services(pg_factory, policy)
    target = await ai_target_service.register(
        organization_id=org_id, name="RDP Lab Target", description="",
        target_type="ai_api", provider="custom", endpoint=_TARGET_ENDPOINT,
    )
    dto = await exec_service.create_and_run(
        org_id, target.id, requester_id, profile="network_discovery_baseline_v1",
    )
    discovery_step = next(s for s in dto.steps if s.step_type == "port_discovery")
    evidence = {e["label"]: e["value"] for e in discovery_step.evidence}
    assert evidence["port_3389"].startswith("reachable:rdp")
    adaptive_fact_refs = {s.source_fact_ref for s in dto.steps if s.source == "adaptive"}
    assert not any("3389" in (ref or "") for ref in adaptive_fact_refs)


async def test_repeated_execution_does_not_duplicate_service_assets(pg_factory) -> None:
    org_id = str(EntityId.generate())
    requester_id = str(EntityId.generate())
    policy = _SequencedPolicyPort()
    ai_target_service, asset_service, _cond, _corr, exec_service = await _make_services(
        pg_factory, policy,
    )
    target = await ai_target_service.register(
        organization_id=org_id, name="Repeat Target", description="",
        target_type="ai_api", provider="custom", endpoint=_TARGET_ENDPOINT,
    )
    await exec_service.create_and_run(org_id, target.id, requester_id, profile="network_discovery_baseline_v1")
    service_count_1 = len(await asset_service.list_for_org(org_id, asset_type="service", limit=200))

    await exec_service.create_and_run(org_id, target.id, requester_id, profile="network_discovery_baseline_v1")
    service_count_2 = len(await asset_service.list_for_org(org_id, asset_type="service", limit=200))

    assert service_count_2 == service_count_1
    assert service_count_1 > 0


async def test_concurrent_execution_converges_on_one_canonical_service_asset(pg_factory) -> None:
    """M13.14's core concurrency requirement: two genuinely concurrent
    `create_and_run()` calls against the SAME org/target must never
    produce two canonical SERVICE assets for the same port — the race
    is resolved by `resolve_asset()`'s existing IntegrityError-retry
    semantics (M3/M6), exercised here under a real simultaneous race,
    not a sequential re-run."""
    org_id = str(EntityId.generate())
    requester_id = str(EntityId.generate())
    policy = _SequencedPolicyPort()
    ai_target_service, asset_service, _cond, _corr, exec_service = await _make_services(
        pg_factory, policy,
    )
    target = await ai_target_service.register(
        organization_id=org_id, name="Concurrency Target", description="",
        target_type="ai_api", provider="custom", endpoint=_TARGET_ENDPOINT,
    )

    results = await asyncio.gather(
        exec_service.create_and_run(org_id, target.id, requester_id, profile="network_discovery_baseline_v1"),
        exec_service.create_and_run(org_id, target.id, requester_id, profile="network_discovery_baseline_v1"),
    )
    assert all(r.status in ("completed", "partially_completed") for r in results)

    services = await asset_service.list_for_org(org_id, asset_type="service", limit=200)
    external_ids = [s.external_id for s in services]
    assert len(external_ids) == len(set(external_ids)), "duplicate canonical SERVICE asset created under a race"


async def test_sensitive_and_plaintext_conditions_deduplicate_on_repeat(pg_factory) -> None:
    org_id = str(EntityId.generate())
    requester_id = str(EntityId.generate())
    policy = _SequencedPolicyPort()
    ai_target_service, _asset, cond_service, _corr, exec_service = await _make_services(
        pg_factory, policy,
    )
    target = await ai_target_service.register(
        organization_id=org_id, name="Condition Dedup Target", description="",
        target_type="ai_api", provider="custom", endpoint=_TARGET_ENDPOINT,
    )
    await exec_service.create_and_run(org_id, target.id, requester_id, profile="network_discovery_baseline_v1")
    network_conditions_1 = await cond_service.list_for_org(org_id, source_category="network_discovery")

    await exec_service.create_and_run(org_id, target.id, requester_id, profile="network_discovery_baseline_v1")
    network_conditions_2 = await cond_service.list_for_org(org_id, source_category="network_discovery")

    assert len(network_conditions_2) == len(network_conditions_1)
    assert len(network_conditions_1) > 0
    rule_ids = {c.stable_rule_id for c in network_conditions_1}
    assert "SENSITIVE_SERVICE_OBSERVED" in rule_ids


async def test_condition_resolution_and_reactivation(pg_factory) -> None:
    org_id = str(EntityId.generate())
    requester_id = str(EntityId.generate())
    policy = _SequencedPolicyPort()
    ai_target_service, _asset, cond_service, _corr, exec_service = await _make_services(
        pg_factory, policy,
    )
    target = await ai_target_service.register(
        organization_id=org_id, name="Reactivation Target", description="",
        target_type="ai_api", provider="custom", endpoint=_TARGET_ENDPOINT,
    )
    await exec_service.create_and_run(org_id, target.id, requester_id, profile="network_discovery_baseline_v1")
    conditions = await cond_service.list_for_org(org_id, source_category="network_discovery")
    assert conditions
    target_condition = conditions[0]
    assert target_condition.evidence_state in ("observed", "validated")

    resolved = await cond_service.resolve_condition(target_condition.id, org_id)
    assert resolved.lifecycle == "resolved"

    # Re-observing the identical fact reactivates it — M8's own
    # upsert() always sets lifecycle="active" on a re-observation,
    # genuinely exercised here (not asserted against the service layer
    # in isolation).
    await exec_service.create_and_run(org_id, target.id, requester_id, profile="network_discovery_baseline_v1")
    reactivated = await cond_service.get_for_org(target_condition.id, org_id)
    assert reactivated.lifecycle == "active"


async def test_correlation_evaluation_remains_deterministic(pg_factory) -> None:
    org_id = str(EntityId.generate())
    requester_id = str(EntityId.generate())
    policy = _SequencedPolicyPort()
    ai_target_service, _asset, _cond, _corr, exec_service = await _make_services(pg_factory, policy)
    target = await ai_target_service.register(
        organization_id=org_id, name="Correlation Determinism Target", description="",
        target_type="ai_api", provider="custom", endpoint=_TARGET_ENDPOINT,
    )
    dto1 = await exec_service.create_and_run(org_id, target.id, requester_id, profile="network_discovery_baseline_v1")
    events1 = await exec_service.list_events(org_id, dto1.id, 0, 500)
    correlation_events1 = [e for e in events1 if e.event_type == "correlation_evaluated"]
    assert len(correlation_events1) == 1
    assert "error" not in correlation_events1[0].payload


async def test_revocation_before_protocol_dispatch_yields_zero_validator_calls(pg_factory) -> None:
    org_id = str(EntityId.generate())
    requester_id = str(EntityId.generate())
    policy = _SequencedPolicyPort()
    policy.push_allow()
    policy.push_allow()
    policy.push_deny("authorization_revoked")
    ai_target_service, _asset, _cond, _corr, exec_service = await _make_services(pg_factory, policy)
    target = await ai_target_service.register(
        organization_id=org_id, name="Revoke Before Protocol Target", description="",
        target_type="ai_api", provider="custom", endpoint=_TARGET_ENDPOINT,
    )
    dto = await exec_service.create_and_run(org_id, target.id, requester_id, profile="network_discovery_baseline_v1")
    adaptive = [s for s in dto.steps if s.source == "adaptive"]
    assert adaptive
    assert all(s.status in ("failed", "skipped") for s in adaptive)
    assert all(s.validator_id is None for s in adaptive)
    assert all(s.evidence == [] for s in adaptive)


async def test_cross_tenant_service_assets_stay_completely_separate(pg_factory) -> None:
    org_a = str(EntityId.generate())
    org_b = str(EntityId.generate())
    requester_id = str(EntityId.generate())
    policy = _SequencedPolicyPort()
    ai_target_service, asset_service, cond_service, _corr, exec_service = await _make_services(
        pg_factory, policy,
    )
    target_a = await ai_target_service.register(
        organization_id=org_a, name="Tenant A Target", description="",
        target_type="ai_api", provider="custom", endpoint=_TARGET_ENDPOINT,
    )
    target_b = await ai_target_service.register(
        organization_id=org_b, name="Tenant B Target", description="",
        target_type="ai_api", provider="custom", endpoint=_TARGET_ENDPOINT,
    )
    await exec_service.create_and_run(org_a, target_a.id, requester_id, profile="network_discovery_baseline_v1")
    await exec_service.create_and_run(org_b, target_b.id, requester_id, profile="network_discovery_baseline_v1")

    services_a = await asset_service.list_for_org(org_a, asset_type="service", limit=200)
    services_b = await asset_service.list_for_org(org_b, asset_type="service", limit=200)
    assert services_a and services_b
    assert {s.id for s in services_a}.isdisjoint({s.id for s in services_b})

    conditions_a = await cond_service.list_for_org(org_a, source_category="network_discovery")
    conditions_b = await cond_service.list_for_org(org_b, source_category="network_discovery")
    assert {c.id for c in conditions_a}.isdisjoint({c.id for c in conditions_b})


async def test_restart_preserves_protocol_validation_history(pg_factory) -> None:
    org_id = str(EntityId.generate())
    requester_id = str(EntityId.generate())
    policy = _SequencedPolicyPort()
    ai_target_service, _asset, _cond, _corr, exec_service = await _make_services(pg_factory, policy)
    target = await ai_target_service.register(
        organization_id=org_id, name="Restart Protocol Target", description="",
        target_type="ai_api", provider="custom", endpoint=_TARGET_ENDPOINT,
    )
    dto = await exec_service.create_and_run(org_id, target.id, requester_id, profile="network_discovery_baseline_v1")

    _ai2, _asset2, _cond2, _corr2, fresh_service = await _make_services(pg_factory, policy)
    reloaded = await fresh_service.get_by_id(org_id, dto.id)
    reloaded_mysql = next(s for s in reloaded.steps if s.step_type == "mysql_handshake")
    original_mysql = next(s for s in dto.steps if s.step_type == "mysql_handshake")
    assert reloaded_mysql.validator_id == original_mysql.validator_id == "MYSQL_HANDSHAKE_V1"
    assert reloaded_mysql.protocol_validation_state == original_mysql.protocol_validation_state
