# ADR — M48E: risk_engine repository sync/async convention deviation

## Status
**RESOLVED.** The user explicitly authorized reopening the frozen
M48C contracts to close this deviation. `i_risk_profile_repository.py`
and `i_risk_correlation_repository.py` were converted from sync
`Protocol`s to async `ABC`s (matching every mature context exactly);
every M48C/M48D application-service call site was updated to `await`
the now-async repository calls; `PgEnterpriseRiskProfileRepository`/
`PgRiskCorrelationRepository` were converted to genuinely async
classes over `AsyncSession`/`asyncpg` (matching
`operation.infrastructure.persistence.repositories.
pg_operation_repository.PgOperationRepository` exactly); `psycopg` was
removed as a dependency (no longer needed — `asyncpg` via SQLAlchemy's
async engine, already the platform's only DB driver, now covers
risk_engine too). All 168 risk_engine tests pass, `ruff`/`mypy` are
clean, and the full regression suite shows zero risk_engine-caused
failures. The sections below are preserved as the historical record
of the original finding and are no longer the current state of the
code — see the "Resolution" section at the end for what changed.

The remainder of this document is left as originally written, as the
historical record of the deviation this resolves.

## Context
A follow-up audit of `src/risk_engine/infrastructure/` was requested,
re-verifying (rather than assuming) whether the M48E repositories'
synchronous implementation is consistent with mature-context
convention. The audit read the actual infrastructure source of five
mature bounded contexts directly (not from memory): `credential_vault`,
`exposure`, `operation`, `detection`, `ai_posture`.

## Finding
**The synchronous repository implementation in risk_engine IS a
deviation from mature-context convention.** This is unambiguous, not
a judgment call:

- `grep -rn "^\s*def save\b" src/{credential_vault,exposure,operation,detection,ai_posture}/infrastructure/`
  returns **zero** matches — every repository method in every mature
  context is `async def`, with zero exceptions.
- Every mature domain/application repository port is an `async def`
  `ABC` (e.g. `src/ai_posture/domain/repositories/i_ai_compliance_mapping_repository.py:16-31`,
  `IAIComplianceMappingRepository(ABC)` with `async def save`/`find_by_id`/
  `find_by_asset`/`find_gaps_by_framework`).
- Every mature repository is constructed over `AsyncSession`
  (`src/operation/infrastructure/persistence/repositories/pg_operation_repository.py:54,58`;
  `src/detection/infrastructure/persistence/repositories/pg_detection_rule_repository.py:251-255`;
  `src/ai_posture/infrastructure/persistence/repositories/pg_compliance_repository.py:32,36,39`).
- Every mature `UnitOfWork.commit`/`rollback` awaits real I/O — e.g.
  `src/operation/infrastructure/persistence/unit_of_work.py:36`:
  `await self._session.commit()` — not a no-op await.
- Every mature application-service call site awaits every repository
  call, e.g. `src/operation/application/services/operation_application_service.py:221,265,287,...`:
  `await uow.operations.save(operation)`, `await uow.operations.find_by_id(...)`.

risk_engine's `PgEnterpriseRiskProfileRepository`/
`PgRiskCorrelationRepository` (`src/risk_engine/infrastructure/persistence/repositories/`)
are plain `def`, not `async def`, and are backed by a synchronous
`sqlalchemy.orm.Session` over the `psycopg` driver rather than
`AsyncSession` over `asyncpg` (the platform's only DB driver
everywhere else). This is a genuine deviation on every one of the
audit's ten points, not merely a stylistic difference.

## Root cause
The deviation is not a free implementation choice made during M48E —
it is forced by the **already-frozen M48C application/port layer**:

- `src/risk_engine/application/ports/i_risk_profile_repository.py` and
  `i_risk_correlation_repository.py` declare `save`/`get`/`list`/
  `score_history` as a plain `Protocol` (not `ABC`) with non-`async`
  methods — itself already a deviation from every mature context's
  `async def ABC` port convention, introduced at M48C, before M48E.
- The frozen M48C application services call these ports **without
  `await`** inside `async with self._uow:` blocks (e.g.
  `EnterpriseRiskProfileApplicationService.create_profile`:
  `self._repository.save(profile)`, no `await`).

Given this, an `async def save(...)` repository method would return
an un-awaited coroutine object to that frozen call site. Since a
coroutine object is always truthy, code such as
`profile = self._repository.get(tenant_id, profile_id); if profile is
None: raise NotFoundError()` would silently stop raising
`NotFoundError` for missing profiles (the coroutine is never `None`),
and no exception marks the mistake — this is a correctness regression
introduced by superficially matching mature repository convention
while ignoring what actually calls it. Making the repositories truly
async, as mature convention requires, is therefore not implementable
without also editing the frozen M48C call sites to `await` every
repository call.

## Options considered
1. **Leave the current synchronous `Session`/`psycopg` implementation
   (status quo).** Functionally correct against the frozen contract,
   fully tested (30 integration tests against real Postgres), but
   structurally divergent from mature convention on session type,
   driver, method signature, and (necessarily) UoW method bodies
   staying `async def` wrapping zero real awaited I/O at the
   *outermost* method (though see below — the deviation is narrower
   than originally reported).
2. **Bridge sync method signatures to real `AsyncSession`/`asyncpg` I/O
   via a dedicated background event-loop thread**
   (`asyncio.run_coroutine_threadsafe` + blocking `.result()`), so the
   repository *body* uses the platform-standard driver and the UoW's
   `commit`/`rollback` await genuine I/O, while the *public method
   signatures* stay synchronous (satisfying the frozen Protocol).
   Rejected for M48E: this pattern exists in **zero** mature contexts
   either — it would replace one documented, low-risk deviation with
   a second, unprecedented, higher-risk one (thread/event-loop
   lifecycle management, potential deadlock/starvation under load,
   harder to reason about and test), while still not achieving true
   `async def` signatures — the actual convention-defining property.
   It does not resolve the deviation; it disguises part of it.
3. **Make the M48C ports `async def ABC`s and update the frozen
   application call sites to `await` every repository/UoW call.**
   This is the only change that would make risk_engine's
   infrastructure fully consistent with every mature context on all
   ten audited points. It is explicitly out of M48E's authorized
   scope (`application/` may only be touched for "interface
   compatibility," not "call-site rewrites of frozen orchestration
   code" — the exact phrase used in this milestone's own repository
   docstrings) and constitutes reopening a frozen M48C architectural
   decision, which per the M48E spec's own automatic-correction rules
   requires this ADR and an explicit decision before proceeding, not
   a unilateral fix inside an infrastructure-only milestone.

## Decision
Keep the current synchronous `Session`-over-`psycopg` implementation
for M48E. It is the only option that is (a) provably correct against
the frozen contract, (b) fully tested, and (c) does not introduce an
undocumented, unprecedented pattern (thread/event-loop bridging) that
would itself fail this same convention audit. Option 3 (converting
M48C's ports to `async def ABC`s and threading `await` through the
frozen application call sites) is the recommended path to fully close
this deviation, and is flagged as an M48F-or-later decision requiring
explicit authorization to reopen M48C, not an M48E infrastructure
task.

## Consequence
risk_engine's infrastructure layer is **confirmed, with direct file
evidence, to deviate from the mature-context sync/async convention**.
The deviation is scoped, understood, root-caused to frozen M48C (not
to an M48E implementation error), does not affect correctness
(verified by 30 passing integration tests against real Postgres), and
is not silently accepted — it is recorded here for whoever owns the
M48C/M48F decision to act on.

---

## Resolution (M48C contract correction, post-authorization)

The user explicitly authorized reopening M48C's frozen contracts to
implement Option 3 above. Changes made:

1. **`src/risk_engine/application/ports/i_risk_profile_repository.py`**
   and **`i_risk_correlation_repository.py`**: `Protocol` → `ABC`,
   every method `def` → `@abstractmethod async def`. Matches
   `operation.domain.repositories.i_operation_repository.
   IOperationRepository`, `ai_posture.domain.repositories.
   i_ai_compliance_mapping_repository.IAIComplianceMappingRepository`,
   and every other mature repository port exactly.

2. **Frozen M48C/M48D application services** — every call site on
   `self._repository`/`self._profiles`/`self._correlations` across
   `enterprise_risk_profile_service.py`, `risk_query_service.py`,
   `risk_timeline_service.py`, and
   `risk_correlation_application_service.py` now `await`s the
   repository call. Methods that previously had no reason to be
   `async def` (`RiskQueryService.get_profile`/`list_profiles`/
   `get_correlation_set`, `RiskTimelineApplicationService.
   get_timeline`, `RiskCorrelationApplicationService.
   generate_timeline`/`evaluate_escalation`) became `async def`, and
   every private helper that calls the repository
   (`_require_profile` in both `EnterpriseRiskProfileApplicationService`
   and `RiskCorrelationApplicationService`) became `async def` and is
   now `await`ed by its own callers. Verified exhaustively by grep —
   zero remaining unawaited calls on any repository attribute — and by
   the test suite itself, which caught three call sites during the
   correction (`evaluate_escalation` x2, `generate_timeline` x1 in
   `test_risk_correlation_application_service.py`) via exactly the
   `AttributeError: 'coroutine' object has no attribute '...'` failure
   mode this ADR predicted as the risk of a partial fix.

3. **`PgEnterpriseRiskProfileRepository`/`PgRiskCorrelationRepository`**:
   rewritten over `AsyncSession` (from `sqlalchemy.ext.asyncio`), every
   `self._session` call `await`ed, matching `PgOperationRepository`'s
   shape exactly. Both now subclass their respective `ABC` port
   directly (`class PgEnterpriseRiskProfileRepository
   (EnterpriseRiskProfileRepository):`) instead of relying on
   structural (duck) typing against a `Protocol`.

4. **`SqlAlchemyUnitOfWork`**: `commit`/`rollback` now `await
   self._session.commit()`/`rollback()` — genuine awaited I/O, not a
   no-op `async def` wrapper around a sync call. Matches
   `OperationUnitOfWork` exactly.

5. **ORM models** (`risk_profile_model.py`, `risk_correlation_model.py`):
   added `lazy="selectin"` to every one-to-many `relationship()`. This
   was not anticipated by the original sync implementation — under a
   genuinely async `AsyncSession`, the SQLAlchemy ORM's default
   `lazy="select"` strategy attempts an implicit lazy-load query the
   first time a relationship attribute (`row.contributions`,
   `row.signal_references`, `row.score_history`) is accessed outside
   of an `await`ed context, raising `sqlalchemy.exc.MissingGreenlet`.
   `selectin` eager-loads via a second `await`ed `SELECT` issued
   alongside the parent query, which is the standard, officially
   documented SQLAlchemy 2.0 pattern for async ORM relationship
   loading. This was caught by the test suite, not anticipated in
   advance — recorded here so the pattern is understood, not just
   applied.

6. **`psycopg[binary]` dependency removed** from `pyproject.toml` — no
   longer needed now that risk_engine uses the platform's standard
   `asyncpg` driver via SQLAlchemy's async engine, same as every other
   bounded context.

7. **Tests**: `tests/risk_engine/application/conftest.py`'s fake
   repositories converted to `async def` methods (matching
   `tests/detection/application/test_rule_application_service.py`'s
   `FakeDetectionRuleRepository` convention exactly); all application
   and infrastructure test call sites updated to `await`/`async def`/
   `@pytest.mark.asyncio`; `tests/risk_engine/infrastructure/conftest.py`
   rewritten to use `AsyncEngine`/`AsyncSession`/`async_sessionmaker`
   with `pytest_asyncio.fixture`, matching
   `tests/credential_vault/infrastructure/conftest.py` exactly.

**Verification**: `ruff check` clean, `ruff format --check` clean on
every file touched, `mypy src/risk_engine` clean (69 files), `mypy src`
clean (3875 files, full project scope), `pytest tests/risk_engine -q`
→ 168/168 passed, full regression suite shows zero risk_engine-related
failures (confirmed by grepping the full run's failure log for
`risk_engine` — the only match is an unrelated alembic downgrade log
line from a different context's migration fixture).

**No remaining deviation.** All ten convention-audit points now match
mature-context convention with no exceptions.
