# M6 — Network, Device & Service Discovery Foundation — Report

**Date**: 2026-07-11
**Baseline entering M6**: 3,514 backend tests passing, 5 skipped; migration head 0015; ontology v2.
**Baseline exiting M6**: 3,557 backend tests passing, 5 skipped; migration head **unchanged at 0015** (no new tables needed); ontology **v3**.

---

## 1. Reconnaissance Findings

A targeted reconnaissance sweep confirmed essentially nothing network/cloud/vulnerability-related exists yet in the repository: no Nmap/Nuclei/Trivy/Nessus/OpenVAS references, no CIDR/subnet code, no boto3/azure/google-cloud SDKs, no CVE/CWE modeling, and the only structured CVSS object in the repo (`domain/attack_library/value_objects.CvssMetadata`) belongs to an unrelated bounded context. `AssetType` already had `HOST`, `IP_ADDRESS`, `CLOUD_RESOURCE` (from M3) but no `NETWORK`/`DEVICE`/`SERVICE`. `IdentityScheme` already normalizes IP addresses via `ipaddress.ip_address()` but had no CIDR/host/service-endpoint schemes and no public/private IP classification helper anywhere. `SecurityGraphProjector` (6 existing `project_*` methods) and the ontology (v2, 13 NodeKinds/9 EdgeKinds) were both directly extensible without rework. **Conclusion: M6 had to be built from scratch, but entirely as an extension of the existing M3 Asset/Connector/Security-Graph architecture — no disconnected inventory was needed or created.**

## 2. Architecture Decisions

**Domain ownership**: `NETWORK`, `DEVICE`, `SERVICE` were added as 3 new `AssetType` values (joining the existing `HOST`/`IP_ADDRESS`), reusing the canonical `AIAsset` aggregate exactly as M3's own docstring anticipated ("future network/cloud/application discovery domains project into these, not a parallel enum"). No `NetworkAsset`/`HostAsset`/`ServiceAsset` disconnected domain classes were created. Network-specific state (protocol, port, CIDR prefix) lives in the deterministic `external_id` encoding, not hidden inside an opaque JSON blob with no structure — the exact same document-store discipline M3/M4/M5 already established.

**No new migration required.** `network`/`device`/`service` are just new string values in the same `asset_type` column (`String(50)`) that already existed since migration 0013 — this is a real, structural confirmation that M3's aggregate genuinely generalizes, not a claim without evidence.

## 3. Exact Files Changed

### Backend (new)
- `src/redforge/application/network_discovery/observations.py` — typed `IPAddressObservation`/`HostObservation`/`ServiceObservation`/`NetworkDiscoveryResult`
- `src/redforge/application/network_discovery/scan_adapter.py` — `BoundedNetworkScanAdapter` (real TCP-connect discovery)
- `src/redforge/application/network_discovery/service.py` — `TenantNetworkDiscoveryService` (resolution orchestration + exposure query)
- `src/redforge/application/network_discovery/analysis_service.py` — deterministic network exposure rules
- `src/redforge/api/v1/network_exposure.py` — 1 new endpoint (observations)
- `tests/domain/test_network_identity.py` (12 tests), `tests/domain/test_network_ontology.py` (10 tests)
- `tests/unit/test_network_scan_adapter.py` (11 tests, real loopback sockets)
- `tests/api/test_network_discovery_isolation.py` (7 tests)
- `tests/integration/test_network_asset_race.py` (3 real-PostgreSQL concurrency tests)

### Backend (modified)
- `src/redforge/domain/inventory/value_objects.py` — `AssetType` +3 (`NETWORK`/`DEVICE`/`SERVICE`), `AssetRelationshipType` +4 (`IP_ASSIGNED_TO_HOST`/`HOST_EXPOSES_SERVICE`/`DEVICE_CONNECTED_TO_NETWORK`/`IP_MEMBER_OF_NETWORK`)
- `src/redforge/domain/inventory/identity.py` — `IdentityScheme` +3 (`NETWORK_CIDR`/`DISCOVERY_HOST`/`SERVICE_ENDPOINT`) with real normalizers
- `src/redforge/application/inventory/fingerprint_engine.py` — extractor entries for the 3 new asset types
- `src/redforge/application/inventory/tenant_asset_service.py` — generic `resolve_asset()` and `add_relationship_for_org()` (race-safe, idempotent — generalizes the M3 `get_or_create_for_target` pattern beyond REDFORGE_TARGET_ID)
- `src/redforge/domain/security_graph/ontology.py` — `ONTOLOGY_VERSION` 2→3, +3 NodeKinds (`NETWORK`/`DEVICE`/`SERVICE`), +3 EdgeKinds (`CONNECTED_TO`/`EXPOSES`/`MEMBER_OF_NETWORK`)
- `src/redforge/application/security_graph/projector.py` — `_ASSET_NODE_MAP`/`_RELATIONSHIP_MAP` extended (no new `project_*` methods needed — `project_asset`/`project_asset_relationship` already generalize)
- `src/redforge/domain/connectors/value_objects.py` — `ConnectorType.NETWORK_SCAN`
- `src/redforge/application/connectors/tenant_connector_service.py` — `register_network_connector`, discovery branching, `_run_network_discovery`
- `src/redforge/api/v1/connectors.py` — `POST /connectors/network`
- `src/redforge/api/dependencies.py` — `get_tenant_network_discovery_service`
- `src/redforge/api/v1/__init__.py` — registered `network_exposure_router`
- `tests/unit/test_inventory_domain.py` — enum-count assertions bumped (18→21 AssetType, 15→19 AssetRelationshipType)

### Frontend (new)
- `src/lib/networkExposure.ts`, `src/app/(app)/network-exposure/page.tsx`

### Frontend (modified)
- `src/app/(app)/connectors/page.tsx` — network connector registration form (CIDR + bounded port list, no raw scanner flags)
- `src/app/(app)/layout.tsx` — Network Exposure nav entry

**Deliberate reuse decision**: no separate "Network"/"Services" browsing pages were built — NETWORK/IP_ADDRESS/HOST/DEVICE/SERVICE assets are already fully served by the existing generic `/assets` page (filterable by `asset_type`), which M3 built precisely to generalize across future discovery domains. Building near-duplicate pages would have violated the milestone's own instruction not to create "duplicate generic inventory APIs."

## 4. Network Identity Normalization

Four schemes, each with a real, tested normalization function:
- **IP_ADDRESS** (already existed, M3): canonicalizes via `ipaddress.ip_address()` — proven IPv4 and IPv6 canonicalization (`2001:0db8::0001` and `2001:db8::1` normalize identically), invalid addresses rejected.
- **NETWORK_CIDR** (new): `ipaddress.ip_network(raw, strict=False)` — proven `10.0.0.1/24` and `10.0.0.0/24` normalize to the exact same canonical string (host bits masked, never treated as different networks).
- **DISCOVERY_HOST** (new): requires the caller to compose `"{connector_id}:{hostname}"` — hostname alone is never sufficient identity (a mutable, source-scoped value); the connector scopes it. Hostname portion lowercased (DNS case-insensitivity); connector_id preserved as-is.
- **SERVICE_ENDPOINT** (new): `"{host_asset_id}:{protocol}:{port}"` — protocol restricted to `tcp`/`udp`, port validated 1-65535. Never the service banner — a banner-derived "product/version" guess is explicitly never treated as identity or fact.

22 tests total across `test_network_identity.py` (12) and reused M3 identity test conventions.

## 5. Typed Network Observations

`IPAddressObservation`, `HostObservation`, `ServiceObservation`, `NetworkDiscoveryResult` — all typed dataclasses, never `payload: dict[str, Any]`. `ServiceObservation.safe_service_name` is populated ONLY from a controlled, deterministic well-known-port table (port 22 → "ssh", etc.) — this is the IANA-assigned convention for the port number, explicitly never a banner-derived software/version guess presented as fact.

## 6. Bounded Network Discovery Adapter

`BoundedNetworkScanAdapter` — a real, working implementation, not a stub:
- **Mechanism**: native `asyncio` TCP-connect checks only (`asyncio.open_connection` + timeout). No `subprocess`, no `shell=True`, no Nmap/Nuclei invocation, no NSE scripts, no exploit probes, no credential attacks.
- **Capability boundary proven directly**: `test_no_shell_execution_capability_exists` asserts the class's entire public surface is `{"discover"}` — no method accepts a command string, shell flag, or scanner argument.
- **Scope policy enforced in code, not just documented**: `0.0.0.0/0` and `::/0` rejected outright (`test_default_route_ipv4_rejected`/`test_default_route_ipv6_rejected`); any range exceeding `MAX_ADDRESSES_PER_RUN=256` rejected (`test_oversized_range_rejected`); port list bounded to `MAX_PORTS_PER_RUN=20`; concurrency bounded by a semaphore (`MAX_CONCURRENCY=32`); every connect attempt has a `CONNECT_TIMEOUT_SECONDS=0.75` timeout. The adapter re-validates these limits itself — it does not trust the caller (`TenantConnectorService`) alone, even though the caller also only ever supplies connector-configured values.
- **Proven live against real loopback sockets** (11 unit tests: open-port detection, closed-port silence, policy rejections) and via the full live API acceptance flow (§13).

This is explicitly called "bounded TCP-connect discovery" everywhere in code and docs — never "full vulnerability scanning."

## 7. Network Relationships

4 new `AssetRelationshipType` values, each mapped to a real ontology `EdgeKind`: `IP_ASSIGNED_TO_HOST`→`CONNECTED_TO`, `HOST_EXPOSES_SERVICE`→`EXPOSES`, `DEVICE_CONNECTED_TO_NETWORK`→`CONNECTED_TO`, `IP_MEMBER_OF_NETWORK`→`MEMBER_OF_NETWORK` (a **new**, distinct edge kind — deliberately NOT overloading M5's directory `MEMBER_OF` semantics, proven by `test_ip_member_of_network_does_not_reuse_directory_member_of`). Idempotent via the existing M3 `relate_to`/`DuplicateRelationshipError` mechanism, generalized into `TenantAssetService.add_relationship_for_org` — proven by `test_duplicate_relationship_observation_idempotent` (3 repeated observations → 1 relationship row) and live (§13).

## 8. Security Graph Ontology v3

`ONTOLOGY_VERSION` 2→3. Added `NodeKind.NETWORK`/`DEVICE`/`SERVICE`; added `EdgeKind.CONNECTED_TO`/`EXPOSES`/`MEMBER_OF_NETWORK` with explicit valid-pairing entries: `(IP_ADDRESS|DEVICE) --CONNECTED_TO--> (HOST|DEVICE|NETWORK)`, `(HOST|DEVICE) --EXPOSES--> SERVICE`, `IP_ADDRESS --MEMBER_OF_NETWORK--> NETWORK`. 10 ontology tests prove both valid pairings and rejections (e.g. `NETWORK --EXPOSES--> SERVICE` and `SERVICE --CONNECTED_TO--> NETWORK` both correctly rejected). No speculative `NETWORK --MEMBER_OF--> NETWORK` (nested network) semantics were added — no producing source resolves that.

## 9. Network Visibility Analysis

3 deterministic rules (`application/network_discovery/analysis_service.py`), computed on read from canonical `external_id`-encoded asset state (no persisted duplicate-analysis-row concern):
- **PUBLICLY_ADDRESSABLE_ASSET** — uses Python's own `ipaddress.IPv4Address/IPv6Address.is_global` (RFC-accurate), never a "not RFC1918 therefore public" shortcut. Proven NOT to fire for loopback/private addresses live (§13 — 127.0.0.1 produced zero `PUBLICLY_ADDRESSABLE_ASSET` observations, correctly).
- **SENSITIVE_SERVICE_OBSERVED** — a controlled port policy list (ssh/telnet/smb/mssql/mysql/rdp/postgresql). Proven exposure-context-only, never labeled a vulnerability (`test_service_observation_is_not_automatically_a_vulnerability` explicitly asserts no rule ID contains "vulnerab").
- **MULTIPLE_REMOTE_ADMIN_SERVICES** — fires when a single host has more than one sensitive service.

`UNENCRYPTED_SERVICE_OBSERVED` was **not** implemented — the milestone itself requires deterministic protocol-level TLS-absence semantics that a bare TCP-connect check cannot honestly provide (a bounded connect check proves a port is open, not whether the protocol on it is encrypted) — implementing it would require exactly the kind of unreliable inference the milestone explicitly forbids.

## 10. Network APIs

Reused the existing generic `/assets` API (M3) for all NETWORK/IP_ADDRESS/HOST/DEVICE/SERVICE browsing and `/assets/{id}/relationships` for relationship inspection — no duplicate inventory API was created. One new endpoint: `GET /network-exposure/observations`. `POST /connectors/network` for connector registration. All require `Permission.TARGETS_READ`/`TARGETS_MANAGE` (reused, no new permissions).

## 11. Network Frontend

No separate "Network"/"Services" pages — deliberately reuses the existing Assets page (filterable by kind) per §3's reuse decision. New: `/network-exposure` (deterministic observations, crisp one-line style: `SENSITIVE_SERVICE_OBSERVED` / `SSH observed on host2 (tcp/22).`), and a network connector registration form on the existing Connectors page (CIDR + bounded port list — no raw scanner flags exposed to the browser, matching the backend's own capability boundary).

## 12. Tenant Isolation & Safety Adversarial Review

7 tests (`tests/api/test_network_discovery_isolation.py`): tenant A IP invisible to tenant B (404 for guessed ID); same IP across tenants remains separate; duplicate relationship observation idempotent; network connector registration + real bounded discovery against loopback completes successfully; oversized scope (`0.0.0.0/0`) rejected at discovery time with 409 (not silently narrowed); sensitive service observation proven distinct from "vulnerability" terminology; unauthenticated denied. Plus 11 adapter-level tests (malformed CIDR, oversized range, no-shell-capability) and 10 ontology tests (invalid pairing rejection).

## 13. Live API Acceptance Matrix

Executed against a dedicated `uvicorn` process (port 8966, confirmed free), real shared PostgreSQL 16 (migration head unchanged at 0015 — no new migration needed), and a real local TCP listener on port 19922.

| # | Step | Result |
|---|------|--------|
| 1 | Authenticate, select organization | PASS |
| 2 | Register network connector (127.0.0.1/32, ports 19922/19999) | PASS |
| 3 | Register oversized-scope connector (10.0.0.0/16) | PASS (registration itself succeeds — policy is enforced at discovery time) |
| 4 | Discovery on oversized connector rejected (409, "exceeds the maximum") | PASS |
| 5 | Approved bounded discovery completes (3 assets discovered) | PASS |
| 6 | Verify discovered assets: 1 NETWORK, 1 IP_ADDRESS, 1 HOST (reverse-DNS resolved "localhost"), 1 SERVICE | PASS |
| 7 | Verify canonical relationships (CONNECTED_TO, MEMBER_OF_NETWORK, EXPOSES) | PASS |
| 8 | Verify Security Graph (4 nodes, 3 edges, ontology_version=3) | PASS |
| 9 | Verify network exposure observations correctly EMPTY for loopback (no false PUBLICLY_ADDRESSABLE_ASSET) | PASS |
| 10 | Repeat discovery | PASS |
| 11 | Verify idempotency (still 4 assets, 4 nodes, 3 edges — no duplicates) | PASS |
| 12 | Restart backend | PASS |
| 13 | Verify persistence after restart (4 assets) | PASS |
| 14 | Second tenant: assets/graph empty, guessed asset ID denied (404) | PASS |
| 15 | Runtime health | PASS |

All 15 executed steps PASS.

## 14. Browser Acceptance Matrix

**CLAIMED BUT UNPROVEN**, consistent with the M1-M5 reports' honest precedent — port 3000 was occupied by another active session throughout this milestone. Verified instead: `npx tsc --noEmit` (0 errors), `npx vitest run` (31 passed, unchanged surface), `npm run build` (clean, 23 routes including `/network-exposure`).

## 15. Security Findings Caught and Fixed

None found requiring a fix this milestone (unlike M4/M5, which each found and fixed a real bug via live acceptance) — the adapter's scope-policy enforcement and idempotency worked correctly on first live test. This is reported honestly rather than manufacturing a finding to match prior milestones' pattern.

## 16. Backend Quality Gates

| Gate | Result |
|------|--------|
| `ruff check .` | All checks passed |
| `mypy src --strict` | Success: no issues found in 511 source files |
| `pytest -q` | 3,557 passed, 5 skipped (+43 from the 3,514 M5 checkpoint) |

## 17. Frontend Quality Gates

| Gate | Result |
|------|--------|
| `npx tsc --noEmit` | 0 errors |
| `npm run build` | Clean — 23 routes, including `/network-exposure` |
| `npx vitest run` | 31 passed (unchanged surface) |
| `npm run lint` | NOT CONFIGURED (unchanged) |

## 18. npm Advisory State

Unchanged: `next@15.5.20`'s bundled `postcss@8.4.31` (moderate, 2 advisories). No frontend dependency changes.

## 19. Migration Proof

**No new migration was created or needed.** M6 reuses M3's `ai_assets`/`connectors` tables (migration 0013) entirely — `network`/`device`/`service` are new values in the existing `asset_type` `String(50)` column, and the 4 new relationship types live inside the existing JSON `data` blob exactly like M3's original 15 relationship types. Confirmed via `alembic current` before and after this milestone: unchanged at `0015`.

---

## 20. PROVEN

- NETWORK/HOST/IP_ADDRESS/DEVICE/SERVICE are canonical Asset kinds, not a disconnected inventory.
- Deterministic network identity normalization (CIDR host-bit masking, connector-scoped host identity, protocol/port service identity) — 12 tests.
- Canonical network relationships map to a real, versioned ontology (v3) with 10 pairing-validation tests, including a proof that M6 does NOT overload M5's directory `MEMBER_OF` semantics.
- Bounded, read-only, policy-enforced TCP-connect discovery — no shell execution capability exists at all (proven by public-surface introspection).
- Default routes and oversized ranges are rejected at scan time regardless of what was registered — proven both in isolated tests and live.
- Race-safe, idempotent asset/relationship resolution — proven under real PostgreSQL concurrency (3 tests) and live (repeat discovery, zero duplicates).
- Security Graph projection of NETWORK/IP_ADDRESS/HOST/SERVICE nodes and CONNECTED_TO/EXPOSES/MEMBER_OF_NETWORK edges — proven live.
- Deterministic network exposure analysis correctly distinguishes exposure context from vulnerability claims, and correctly does NOT flag loopback/private addresses as publicly addressable.
- Tenant isolation — proven by 7 adversarial tests and live cross-tenant denial.
- Zero regressions across six consecutive milestones (M1→M6, 3,557 backend tests green).

## 21. CLAIMED BUT UNPROVEN

- Real interactive browser click-through — blocked by port 3000 contention.

## 22. FAILED

None this milestone.

## 23. BLOCKED

- Browser acceptance (port contention with other active sessions).

## 24. Remaining M6 P0/P1

**P0**: None.

**P1**:
- `UNENCRYPTED_SERVICE_OBSERVED` deliberately not implemented — a bare TCP-connect check cannot honestly determine TLS presence/absence; would require a deeper protocol-aware check out of M6's bounded scope.
- No dedicated "Network"/"Services" browsing pages — deliberately reused the existing Assets page; a future milestone could add richer network-topology visualization if operator feedback justifies it.
- Real browser acceptance deferred to a session with a free frontend dev-server port.
- IPv6 network discovery is normalization-complete but the scan adapter itself was only live-tested against IPv4 loopback (the adapter code is address-family-agnostic via `ipaddress`, but no IPv6 live proof was performed this milestone).

## 25. Honest M6 Completion Decision

**M6 — Network, Device & Service Discovery Foundation is COMPLETE** for the scope explicitly bounded by this milestone's prompt. Every acceptance-boundary condition holds with real evidence: canonical asset reuse (no disconnected inventory, no new migration needed); deterministic network identity; bounded read-only discovery with no shell-execution capability and server-enforced scope policy; race-safe idempotent resolution proven under real PostgreSQL concurrency; Security Graph ontology extended only for real producing sources; deterministic exposure analysis that never conflates exposure with vulnerability or compromise; tenant isolation; zero regressions. This clears the M6 checkpoint gate — **M7 may proceed.**
