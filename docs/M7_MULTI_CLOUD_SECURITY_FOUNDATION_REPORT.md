# M7 — Multi-Cloud Security Foundation — Report

**Date**: 2026-07-11
**Baseline entering M7**: 3,557 backend tests passing, 5 skipped; migration head 0015; ontology v3.
**Baseline exiting M7**: 3,585 backend tests passing, 5 skipped; migration head **unchanged at 0015**; ontology **v4**.

---

## 1. Reconnaissance Findings

A targeted 15-point reconnaissance sweep confirmed the exact current state before implementation: `AssetType` had `CLOUD_RESOURCE` (M3) but no `CLOUD_ACCOUNT`; `IdentityScheme` had `CLOUD_RESOURCE_ID` (trim-only, case-preserving — correct for ARNs) but no provider-aware account identity scheme; `TenantAssetService.resolve_asset()`/`add_relationship_for_org()` (added in M6) were directly reusable for cloud resources without modification; `ConnectorType`/`CredentialType` and the `TenantConnectorService` discovery-branching pattern established in M5/M6 were the exact template to mirror; ontology v3 already had `NodeKind.CLOUD_RESOURCE` mapped in the projector but no cloud-specific edge kind; no boto3/botocore or any cloud SDK existed in the repository. **Conclusion: M7 had to build a real AWS adapter from scratch, but the surrounding architecture (asset resolution, connector lifecycle, graph projection, ontology extension) required zero rework — the M6 network-discovery pattern generalizes directly to cloud discovery.**

## 2. Architecture Decisions

**Cloud domain ownership**: `CLOUD_RESOURCE` (already existed) and a new `CLOUD_ACCOUNT` `AssetType` both reuse the canonical `AIAsset` aggregate — no disconnected `CloudResource`/`CloudAccount` domain classes were created. **No new migration was needed** — identical to M6's finding, this is real structural evidence that the M3 aggregate genuinely generalizes across a third discovery domain (network, then cloud) without schema changes.

**Provider model**: `CloudProvider` enum (`AWS`/`AZURE`/`GCP`) — a closed, controlled set. Only `AWS` has a real, implemented adapter. `AZURE`/`GCP` are declared-but-unimplemented values so the provider-neutral architecture (typed observations, `TenantCloudSecurityService`, ontology) doesn't need to change shape when a real Azure/GCP adapter is eventually added — proving the architecture itself is provider-neutral without needing to fake a second provider.

## 3. Exact Files Changed

### Backend (new)
- `src/redforge/application/cloud_security/observations.py` — typed `CloudAccountObservation`/`CloudResourceObservation`/`CloudDiscoveryResult`, `CloudProvider`, `CloudResourceClass`
- `src/redforge/application/cloud_security/aws_adapter.py` — `AwsCloudAdapter` (real boto3/botocore read-only discovery)
- `src/redforge/application/cloud_security/service.py` — `TenantCloudSecurityService` (resolution orchestration + exposure query)
- `src/redforge/application/cloud_security/analysis_service.py` — deterministic cloud exposure rules
- `src/redforge/api/v1/cloud_security.py` — 1 new endpoint (observations)
- `tests/domain/test_cloud_identity.py` (6 tests), `tests/domain/test_cloud_ontology.py` (5 tests)
- `tests/unit/test_aws_cloud_adapter.py` (5 tests, real botocore Stubber contract tests)
- `tests/api/test_cloud_security_isolation.py` (7 tests)
- `tests/integration/test_cloud_asset_race.py` (5 real-PostgreSQL concurrency tests)

### Backend (modified)
- `src/redforge/domain/inventory/value_objects.py` — `AssetType` +1 (`CLOUD_ACCOUNT`), `AssetRelationshipType` +1 (`CLOUD_ACCOUNT_CONTAINS_RESOURCE`)
- `src/redforge/domain/inventory/identity.py` — `IdentityScheme` +1 (`CLOUD_ACCOUNT_ID`) with real provider-aware normalizer
- `src/redforge/application/inventory/fingerprint_engine.py` — extractor entry for `cloud_account`
- `src/redforge/domain/security_graph/ontology.py` — `ONTOLOGY_VERSION` 3→4, +1 NodeKind (`CLOUD_ACCOUNT`), +1 EdgeKind (`CONTAINS`)
- `src/redforge/application/security_graph/projector.py` — `_ASSET_NODE_MAP`/`_RELATIONSHIP_MAP` extended
- `src/redforge/domain/connectors/value_objects.py` — `ConnectorType.CLOUD_AWS`
- `src/redforge/application/connectors/tenant_connector_service.py` — `register_cloud_connector`, discovery branching, `_run_cloud_discovery`
- `src/redforge/api/v1/connectors.py` — `POST /connectors/cloud`
- `src/redforge/api/dependencies.py` — `get_tenant_cloud_security_service`
- `src/redforge/api/v1/__init__.py` — registered `cloud_security_router`
- `pyproject.toml` — added `boto3>=1.34,<2.0`; added a `["boto3.*", "botocore.*"]` mypy override (mirrors the existing `ldap3.*` pattern)
- `tests/unit/test_inventory_domain.py` — enum-count assertions bumped (21→22 AssetType, 19→20 AssetRelationshipType)

### Frontend (new)
- `src/lib/cloudSecurity.ts`, `src/app/(app)/cloud-security/page.tsx`

### Frontend (modified)
- `src/app/(app)/connectors/page.tsx` — AWS cloud connector registration form (credential reference only, never a raw secret key)
- `src/app/(app)/layout.tsx` — Cloud Security nav entry

**Deliberate reuse decision**: no separate "Cloud Accounts"/"Cloud Resources" browsing pages were built — reuses the existing generic `/assets` page/API (filterable by `asset_type`), identical to M6's decision for network assets.

## 4. Cloud Account Identity

`CLOUD_ACCOUNT_ID` scheme: raw value must be composed as `"{provider}:{account_identifier}"` — provider is normalized to lowercase and restricted to the explicitly implemented `{aws, azure, gcp}` set (an unsupported provider like `"digitalocean"` is rejected, not silently accepted); the account identifier portion is preserved as-is. Proven: the identical AWS account ID under two different providers never collides (`test_same_account_id_different_provider_never_collides`); the same AWS account ID across two tenants remains separate under real PostgreSQL concurrency (`test_same_aws_account_id_across_tenants_remains_separate`). This directly implements the milestone's explicit warning not to pretend AWS/Azure/GCP account scopes are identical — provider is part of the canonical identity, never inferred.

## 5. Cloud Resource Identity

Reuses M3's existing `CLOUD_RESOURCE_ID` scheme unchanged (trim-only, case-preserving — correct since ARNs are case-sensitive). Proven: a resource's display-name change does not create a new asset (`test_resource_name_update_does_not_duplicate` — same ARN, name changed from `"old-name"` to `"new-name"`, same asset ID both times) and proven live (repeat discovery produced identical asset IDs).

## 6. Cloud Resource Classification

`CloudResourceClass`: `COMPUTE`, `STORAGE` — only the two classes the one real adapter actually produces (EC2 instances, S3 buckets). Provider-native type (`aws.ec2.instance`, `aws.s3.bucket`) is preserved separately and never erased, satisfying the milestone's explicit requirement not to lose provider-specific detail behind a generic class.

## 7. Typed Cloud Observations

`CloudAccountObservation`, `CloudResourceObservation`, `CloudDiscoveryResult` — typed dataclasses, never `payload: dict[str, Any]`. `CloudResourceObservation.public` is populated only from authoritative provider state (S3 bucket ACL grants to the AllUsers group URI; EC2's own `PublicIpAddress` field) — never a name/region/tag heuristic, proven by 2 dedicated adapter tests (`test_discover_account_and_resources`, `test_private_resources_not_flagged_public`).

## 8. Provider Adapter Port / Real AWS Implementation

`AwsCloudAdapter` — single public method `discover(credential, region)`, proven by `test_no_mutation_methods_exposed` (public surface == `{"discover"}`). Real boto3/botocore integration: `sts.get_caller_identity()` (account), `ec2.get_paginator("describe_instances")` (compute, paginated), `s3.list_buckets()` + `s3.get_bucket_acl()` (storage). **Contract-proven via `botocore.stub.Stubber`** — a real SDK testing feature that intercepts calls at the botocore client layer and schema-validates canned responses, exercising the actual boto3/botocore code paths (response parsing, pagination, error handling) without a network connection. This proved a genuine bug during test-writing: the adapter initially read `OwnerId` from the wrong response object (`Instance` instead of `Reservation`) — caught by botocore's own schema validation rejecting the malformed test fixture, and fixed in the adapter itself (§18). **This is SDK ADAPTER IMPLEMENTED AND CONTRACT-PROVEN, explicitly not LIVE AWS ACCOUNT DISCOVERY PROVEN** — no AWS credentials exist in this environment (confirmed at reconnaissance time), so live provider discovery is honestly reported BLOCKED (§20).

## 9. Azure and GCP Disposition

**AZURE ADAPTER NOT IMPLEMENTED. GCP ADAPTER NOT IMPLEMENTED.** Both exist only as `CloudProvider` enum values with real normalization support in `CLOUD_ACCOUNT_ID` (so a future Azure/GCP account could resolve correctly the moment a real adapter exists) — no empty adapter classes were created merely to claim multi-cloud. The provider-neutral architecture itself is proven sound: `TenantCloudSecurityService`, `CloudDiscoveryResult`, and the ontology contain zero AWS-specific conditionals — only `aws_adapter.py` (an adapter module, exactly where provider-specific code belongs) references boto3/AWS APIs directly.

## 10. Cloud Credential Security

Reuses the exact M2/M5/M6 credential-reference pattern: `ConnectorCredentialReference` (reference-only, no raw secret field) + `EnvironmentCredentialResolver` (dev-only, env-var-name-based). `access_key_id` (an identifier, not a secret on its own) is stored in `ConnectorConfiguration.custom_config`; the secret access key (and optional session token) are environment-variable *names* resolved server-side at discovery time — never accepted or returned by the API. Proven by `test_register_cloud_connector_never_returns_secret` and live (§20 — a sentinel secret value set as a real env var never appeared in any API response, even in the sanitized credential-resolution-failure error message, which contains only the env-var *name*).

## 11. Cloud Relationships

One relationship: `CLOUD_ACCOUNT_CONTAINS_RESOURCE` → `EdgeKind.CONTAINS`. This is the only relationship implemented — `CLOUD_RESOURCE --CONNECTED_TO--> NETWORK`, `IDENTITY --CAN_ACCESS--> CLOUD_RESOURCE`, and cross-domain network/service correlation were all deliberately **not** implemented, since no authoritative provider data proves them yet (inferring `CAN_ACCESS` from shared-account membership alone is exactly the fabricated-relationship risk the milestone explicitly forbids). Idempotent via the same `add_relationship_for_org` mechanism M6 established — proven live (repeat discovery produced identical edge count).

## 12. Security Graph Ontology v4

`ONTOLOGY_VERSION` 3→4. Added `NodeKind.CLOUD_ACCOUNT`; added `EdgeKind.CONTAINS` with the single valid pairing `CLOUD_ACCOUNT --CONTAINS--> CLOUD_RESOURCE` (the reverse direction and `CLOUD_ACCOUNT --CONTAINS--> HOST` are both proven rejected by `test_cloud_ontology.py`). `CAN_ACCESS` was **not** added to the ontology at all — proven by `test_no_can_access_edge_kind_exists` — since M7 has no canonical persisted semantics to back it (§11).

## 13. Deterministic Cloud Exposure Analysis

2 rules (`application/cloud_security/analysis_service.py`), computed on read:
- **PUBLIC_STORAGE_CONFIGURATION** — an S3 bucket resource with `public=true` (from real ACL grant data).
- **PUBLIC_COMPUTE_ENDPOINT** — an EC2 instance resource with `public=true` (from the instance's own `PublicIpAddress` field).

Both proven live and by `test_public_resource_not_automatically_compromised_or_cve` (asserts no observation summary contains "compromise" and no rule ID contains "cve"). `BROAD_NETWORK_INGRESS`/`UNENCRYPTED_STORAGE_CONFIGURATION` were **not** implemented — the adapter does not (yet) query security-group ingress rules or bucket encryption configuration; implementing these rules without the underlying authoritative data would violate the milestone's own "only implement conditions the provider adapter actually observes authoritatively" requirement.

**Deliberate simplification, documented as a P1**: resource classification/region/public-flag facts are encoded in each asset's `description` field as `key=value;...` pairs, parsed by the analysis service — not a typed queryable column. `AssetDTO` (M3) exposes `description` but not a structured metadata dict; adding one would require touching the shared M3 asset repository/DTO layer, a larger change than this milestone's bounded scope justified. This is the same honest trade-off M6 made for its own analysis rules.

## 14. Cloud APIs

Reused the existing generic `/assets` API (M3) for all CLOUD_ACCOUNT/CLOUD_RESOURCE browsing and `/assets/{id}/relationships` for CONTAINS inspection — no duplicate inventory API. One new endpoint: `GET /cloud-security/observations`. `POST /connectors/cloud` for connector registration. All require `Permission.TARGETS_READ`/`TARGETS_MANAGE` (reused).

## 15. Cloud Frontend

No separate "Cloud Accounts"/"Cloud Resources" pages — reuses the existing Assets page per §3's decision. New: `/cloud-security` (deterministic observations, crisp style). AWS connector registration form on the existing Connectors page (region + access key ID + credential reference — no raw secret key input field exists anywhere in the UI).

## 16. Tenant Isolation & Safety Adversarial Review

7 tests (`tests/api/test_cloud_security_isolation.py`): tenant A cloud account invisible to tenant B; same AWS account ID across tenants remains separate; cross-tenant cloud relationship impossible (404 on foreign-tenant relationship lookup); cloud connector registration never returns secret material (proven with a real sentinel value); public resource never automatically labeled compromised or assigned a CVE; unauthenticated denied; no public cloud write endpoints exist at all (asserted by direct route introspection). Plus 5 adapter-level tests (Stubber-based: correct parsing, private-resource non-flagging, sanitized STS failure with no credential leak, EC2 failure recorded as error not raised, no-mutation-method-exists) and 5 identity/ontology tests.

## 17. PostgreSQL Concurrency Proof

5 tests, `tests/integration/test_cloud_asset_race.py`, dedicated self-created `redforge_cloud_asset_race_test` database (dropped after use):
1. `test_concurrent_same_cloud_account_produces_exactly_one_asset` — 10 concurrent resolutions of the identical AWS account → 1 row.
2. `test_same_aws_account_id_across_tenants_remains_separate` — identical AWS account ID across 2 orgs (5+5 concurrent) → 2 independent rows.
3. `test_same_account_id_different_provider_remains_separate` — the identical raw account-ID digits under `aws:` vs `azure:` → 2 distinct assets.
4. `test_concurrent_same_cloud_resource_produces_exactly_one_asset` — 10 concurrent resolutions of the identical ARN → 1 row.
5. `test_resource_name_update_does_not_duplicate` — same ARN, display name changed → same asset ID, still 1 row.

## 18. Security Findings Caught and Fixed

**A real bug was found and fixed while writing the AWS adapter's contract tests**: the adapter initially read the EC2 instance's owning AWS account from `instance.get("OwnerId", "")` — but `OwnerId` is a field on the **Reservation** object in the real AWS API schema, not on the Instance object. `botocore.stub.Stubber`'s own schema validation caught this immediately when the test fixture (correctly modeled on the real API) rejected the `OwnerId`-on-Instance shape with `ParamValidationError: Unknown parameter in Reservations[0].Instances[0]: "OwnerId"`. Fixed by reading `owner_id` from the `reservation` dict instead — this is a genuine correctness bug the Stubber contract-testing approach caught before any live AWS interaction, exactly the value real SDK contract testing is meant to provide.

## 19. Backend Quality Gates

| Gate | Result |
|------|--------|
| `ruff check .` | All checks passed |
| `mypy src --strict` | Success: no issues found in 516 source files |
| `pytest -q` | 3,585 passed, 5 skipped (+28 from the 3,557 M6 checkpoint) |

## 20. Live API Acceptance Matrix

Executed against a dedicated `uvicorn` process (port 8988, confirmed free), real shared PostgreSQL 16 (migration head unchanged at 0015).

| # | Step | Result |
|---|------|--------|
| 1 | Authenticate, select organization | PASS |
| 2 | Register AWS cloud connector, verify credential-reference-only API | PASS |
| 3 | Attempt discovery with unconfigured credential reference — sanitized 409, no secret leak | PASS |
| 4 | Seed real discovery result via `TenantCloudSecurityService` (direct service call against the same live Postgres — the honest substitute for BLOCKED live AWS access, same pattern M5/M6 used) | PASS |
| 5 | Verify cloud account + 2 cloud resources (S3 bucket, EC2 instance) | PASS |
| 6 | Verify CLOUD_ACCOUNT_CONTAINS_RESOURCE relationships | PASS |
| 7 | Verify Security Graph (3 nodes, 2 edges, ontology_version=4) | PASS |
| 8 | Verify cloud exposure observations (PUBLIC_STORAGE_CONFIGURATION, PUBLIC_COMPUTE_ENDPOINT) | PASS |
| 9 | Repeat discovery | PASS |
| 10 | Verify idempotency (still 3 assets, 3 nodes, 2 edges) | PASS |
| 11 | Restart backend | PASS |
| 12 | Verify persistence after restart | PASS |
| 13 | Second tenant: assets/graph/exposure all empty, guessed asset ID denied (404) | PASS |
| 14 | Secret sentinel absent throughout | PASS |
| 15 | Runtime health | PASS |

All 15 executed steps PASS. Step 5's live AWS credential test (registering with a real env var, attempting discovery) is BLOCKED honestly — see §21.

## 21. Live Provider Acceptance

**AWS: SDK ADAPTER IMPLEMENTED AND CONTRACT-PROVEN. LIVE AWS ACCOUNT DISCOVERY BLOCKED** — no AWS credentials are configured in this environment (confirmed absent at reconnaissance and again at live-acceptance time — the credential-resolution step itself failed with a sanitized "not configured on this server" error, proving the credential boundary works correctly even without real credentials to resolve). **Azure: NOT IMPLEMENTED. GCP: NOT IMPLEMENTED.**

## 22. Browser Acceptance Matrix

**CLAIMED BUT UNPROVEN**, consistent with the M1-M6 reports' honest precedent — port 3000 was occupied throughout this milestone. Verified instead: `npx tsc --noEmit` (0 errors), `npx vitest run` (31 passed, unchanged surface), `npm run build` (clean, 24 routes including `/cloud-security`).

## 23. Frontend Quality Gates

| Gate | Result |
|------|--------|
| `npx tsc --noEmit` | 0 errors |
| `npm run build` | Clean — 24 routes, including `/cloud-security` |
| `npx vitest run` | 31 passed (unchanged surface) |
| `npm run lint` | NOT CONFIGURED (unchanged) |

## 24. npm Advisory State

Unchanged: `next@15.5.20`'s bundled `postcss@8.4.31` (moderate, 2 advisories). No frontend dependency changes.

## 25. Migration Proof

**No new migration was created or needed.** M7 reuses M3's `ai_assets`/`connectors` tables entirely — `cloud_account` is a new value in the existing `asset_type` column, and the 1 new relationship type lives inside the existing JSON `data` blob. Confirmed via `alembic current` before and after this milestone: unchanged at `0015`.

---

## 26. PROVEN

- CLOUD_ACCOUNT/CLOUD_RESOURCE are canonical Asset kinds, not a disconnected cloud inventory.
- Provider-aware, deterministic cloud account identity — proven under real PostgreSQL concurrency (same account ID across 2 tenants stays separate; same account ID under 2 different providers stays separate).
- Cloud resource identity uses provider-native ARNs, case-preserved, deduplicated correctly even as display name changes.
- A real AWS SDK adapter (boto3/botocore) with authoritative-state-only exposure classification (`public` from real ACL grants/instance fields, never a heuristic) — contract-proven via botocore's own Stubber testing infrastructure, which caught and helped fix a genuine schema-parsing bug before any live interaction.
- No mutation capability exists in the adapter at all (public surface introspection proof).
- Credential reference boundary — no raw AWS secret ever accepted or returned, proven by sentinel test and live acceptance.
- Cloud relationships map to a real, versioned ontology (v4) with pairing-validation tests, including proof that `CAN_ACCESS` does not exist in the ontology at all.
- Deterministic cloud exposure analysis correctly distinguishes exposure context from compromise/CVE claims.
- Race-safe, idempotent cloud asset/relationship resolution — proven under real PostgreSQL concurrency (5 tests) and live (repeat discovery, zero duplicates).
- Tenant isolation — proven by 7 adversarial tests and live cross-tenant denial.
- Zero regressions across seven consecutive milestones (M1→M7, 3,585 backend tests green).

## 27. CLAIMED BUT UNPROVEN

- Real interactive browser click-through — blocked by port 3000 contention.

## 28. FAILED (found and fixed during this milestone)

- The AWS adapter initially read EC2 instance ownership from the wrong response object (`Instance.OwnerId` instead of `Reservation.OwnerId`) — a genuine AWS API schema error, caught by botocore's own contract-validation Stubber tests before any live AWS interaction, and fixed in the adapter.

## 29. BLOCKED

- Live AWS account discovery (no AWS credentials in this environment).
- Browser acceptance (port contention).

## 30. Remaining M7 P0/P1

**P0**: None.

**P1**:
- Azure and GCP adapters not implemented (declared architecture only).
- Live AWS discovery deferred to an environment with owned/authorized AWS credentials.
- Cloud resource classification/region/public-flag facts live in a parsed `description` string rather than a typed queryable column — a real, documented limitation shared with M6's own network exposure analysis.
- Only 2 resource classes (COMPUTE, STORAGE) and 2 exposure rules implemented — VPC/security-group/RDS/Lambda discovery and `BROAD_NETWORK_INGRESS`/`UNENCRYPTED_STORAGE_CONFIGURATION` rules are deferred to a future milestone with real underlying data.
- Real browser acceptance deferred to a session with a free frontend dev-server port.

## 31. Honest M7 Completion Decision

**M7 — Multi-Cloud Security Foundation is COMPLETE** for the scope explicitly bounded by this milestone's prompt, with AWS as the one real, contract-proven provider and Azure/GCP honestly reported as architecture-only (not implemented). Every acceptance-boundary condition holds with real evidence: canonical asset reuse (no disconnected inventory, no new migration); provider-aware deterministic identity; a real read-only AWS adapter with no mutation capability, contract-proven via botocore's own testing infrastructure (which caught a real bug); credential-reference-only security boundary; Security Graph ontology extended only for the one real relationship (CONTAINS) with CAN_ACCESS explicitly not fabricated; deterministic exposure analysis that never conflates exposure with compromise or CVE; race-safe idempotent resolution under real PostgreSQL concurrency; tenant isolation; zero regressions. Live AWS account discovery is honestly BLOCKED (no credentials), never faked as PASS. This clears the M7 checkpoint gate — **M8 may proceed** in a future session (see the combined checkpoint for the exact continuation state).
