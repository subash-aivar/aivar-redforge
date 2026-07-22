# Runbook: Provisioning the First Platform Super Administrator

Operational, step-by-step companion to the architecture documented in
[`M1_PLATFORM_IDENTITY_SUPER_ADMIN_REPORT.md`](./M1_PLATFORM_IDENTITY_SUPER_ADMIN_REPORT.md).
That report explains *why* the bootstrap mechanism is designed this way and
proves its security properties; this document tells an operator exactly
*what to type* to use it. Read this before you deploy to a new environment
that has never had a platform Super Admin.

No credentials are printed or embedded in this document. Every value below
is something you choose and supply yourself at deploy time.

---

## 1. Prerequisites

- The backend is deployed and its database is migrated to head (`alembic
  upgrade head`). Migration `0011` is what creates the `platform_assignments`,
  `platform_bootstrap_state`, and `platform_audit_log` tables this flow
  depends on — bootstrap will fail if the schema isn't current.
- You control the backend process's environment variables and can restart
  it (see Step 2 — the setting is read once at process startup, not
  re-read per request).
- You have decided which real person's email address will become the first
  Super Admin. That person does not need an account yet — they will
  register one in Step 3.

## 2. Required environment variables

Set these on the **backend** process before starting/restarting it:

| Variable | Required value | Notes |
|---|---|---|
| `REDFORGE_PLATFORM_BOOTSTRAP_ENABLED` | `true` | Default is `false`. Must be explicitly enabled. |
| `REDFORGE_PLATFORM_BOOTSTRAP_PRINCIPAL_EMAIL` | the exact email address of the intended first Super Admin | Compared case-insensitively against the authenticated caller's email at bootstrap time. Not a password or secret — it's an allowlist of *who may claim* the bootstrap, not a credential. |

Both variables use the app's standard `REDFORGE_` env prefix
(`redforge/core/config.py`), so they can be set the same way you already
set `REDFORGE_DATABASE_URL` / `REDFORGE_JWT_SECRET` — `.env` file,
container environment, secrets manager injection, etc.

**Restart required.** `Settings` is constructed once when `create_app()`
runs (no caching decorator, but also no re-read after startup) — changing
these env vars on a already-running process has no effect until the
process restarts.

## 3. Registration flow

The intended Super Admin registers a **normal** account — bootstrap does
not create users or set passwords itself, it only elevates an existing one.

```
POST /api/v1/auth/register
Content-Type: application/json

{
  "email": "<the exact email from REDFORGE_PLATFORM_BOOTSTRAP_PRINCIPAL_EMAIL>",
  "display_name": "<their name>",
  "password": "<a real password they choose, 8-128 chars>"
}
```

Response (`201`): `{ user_id, email, display_name, access_token,
refresh_token, expires_in, token_type: "Bearer" }`. The password is
Argon2id-hashed server-side before storage (`Argon2PasswordHasher`,
OWASP-recommended parameters) — the plaintext value is never persisted or
logged.

Via the UI: the registration page at `/register` (or wherever your
frontend deployment serves it) posts to this same endpoint.

**If the account already exists** (e.g. they registered before you enabled
bootstrap), skip to Step 4 — do not re-register.

## 4. Login flow

```
POST /api/v1/auth/login
Content-Type: application/json

{
  "email": "<same email>",
  "password": "<the password from Step 3>"
}
```

Response (`200`): same `AuthResponse` shape as register, with a fresh
`access_token`. Registration already returns a valid access token too, so
if you just registered in Step 3 you can reuse that token and skip this
step — login is only needed if the session from Step 3 has expired or
you're doing this in a separate session/browser.

Via the UI: the `/login` page. On success, the frontend stores the token
and (per its normal flow) will prompt for organization selection — that
step is unrelated to platform bootstrap and can be skipped or completed
either way; platform access is independent of organization membership.

## 5. Bootstrap action

With a valid access token for the matching-email account:

```
POST /api/v1/platform/bootstrap
Authorization: Bearer <access_token>
```

No request body. The target of the grant is always the authenticated
caller — there is no field to specify a different user, by design (see
architecture report §5: this is what makes "bootstrap someone else"
structurally impossible, not just a policy choice).

Success response (`201`):
```json
{ "assignment_id": "...", "role": "super_admin", "status": "active" }
```

Via the UI: once logged in, the dashboard shows a bootstrap call-to-action
banner automatically whenever `GET /api/v1/platform/bootstrap/status`
returns `{"available": true}` — click it rather than calling the API
directly if you prefer.

## 6. Verification

Confirm the grant took effect:

```
GET /api/v1/platform/me
Authorization: Bearer <access_token>
```

Expect:
```json
{
  "user_id": "...",
  "platform_roles": ["super_admin"],
  "permissions": ["platform:users:read", "platform:organizations:read",
                   "platform:access:read", "platform:access:grant",
                   "platform:access:revoke", "platform:audit:read"],
  "has_platform_access": true
}
```

Also confirm the audit trail recorded it:

```
GET /api/v1/platform/audit
Authorization: Bearer <access_token>
```

Look for an entry with `action: "platform.bootstrap_succeeded"`,
`actor_id` matching your `user_id`, `outcome: "success"`.

In the UI: the sidebar's "Platform Control Plane" link now appears
(gated on `has_platform_access`, not on email/name), and
`/platform/overview`, `/platform/users`, `/platform/organizations`,
`/platform/access`, `/platform/audit` are all reachable.

## 7. Disabling bootstrap afterward

Two independent layers, both worth doing:

1. **It's already self-disabling.** The atomic `platform_bootstrap_state`
   singleton row is consumed on first success — any subsequent
   `POST /api/v1/platform/bootstrap` call, by anyone, returns `409
   BootstrapAlreadyConsumedError` regardless of the env vars. You do not
   strictly need to do anything further for safety.
2. **Recommended anyway:** set `REDFORGE_PLATFORM_BOOTSTRAP_ENABLED=false`
   (or unset it — `false` is the default) and restart the backend. This
   removes the bootstrap call-to-action from the UI (`GET
   /bootstrap/status` will report `available: false`) and is one less
   thing to reason about during a future security review — belt-and-braces,
   not because the atomic claim is insufficient on its own.

There is no need to remove `REDFORGE_PLATFORM_BOOTSTRAP_PRINCIPAL_EMAIL` —
it's inert once bootstrap is disabled or consumed, and removing it doesn't
un-grant the assignment that already exists.

## 8. Security best practices

- **Enable bootstrap for the shortest practical window.** Set the two env
  vars, perform Steps 3–6 immediately, then do Step 7. Don't leave
  `REDFORGE_PLATFORM_BOOTSTRAP_ENABLED=true` set indefinitely in a
  production environment.
- **Use a real, controlled mailbox** for the principal email — anyone who
  can register an account with that exact email address and then
  authenticate as it can claim the bootstrap. This is why the window in
  the previous bullet matters: a long-open window widens the race to
  register that email first.
- **MFA is not yet implemented for platform accounts** (see architecture
  report §12 — `PRODUCTION PRIVILEGED ACCESS READINESS: BLOCKED — STRONG
  MFA REQUIRED`). Treat this as a real, tracked gap, not a formality:
  until platform-level MFA ships, protect the Super Admin account's
  password with the same rigor you'd give any credential with no second
  factor (password manager, unique password, restricted knowledge of who
  holds it).
- **Least-privilege after bootstrap**: use `POST /api/v1/platform/access`
  (grant) for any additional Super Admins rather than re-running bootstrap
  workarounds — there are none, bootstrap is single-use by design, which
  is correct; subsequent admins are provisioned via the normal grant flow,
  itself requiring an existing Super Admin's authorization.
- **Do not share the bootstrap principal email across environments.**
  Using the same value in staging and production doesn't leak credentials,
  but it does mean the same person's account is the bootstrap target in
  both — consider distinct principals per environment if your org
  requires separation of duties.
- **Audit log review**: after bootstrap, periodically check `GET
  /api/v1/platform/audit` for `platform.bootstrap_denied` entries — these
  indicate someone attempted (and failed) to claim bootstrap, which is
  worth investigating even though the attempt was rejected.

## 9. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `403 Bootstrap is not enabled` | `REDFORGE_PLATFORM_BOOTSTRAP_ENABLED` is `false`/unset, or the backend process hasn't restarted since you set it | Set the var, **restart the backend process** (not just re-deploy config), retry |
| `403` on bootstrap with a message about principal mismatch | The authenticated account's email doesn't exactly match `REDFORGE_PLATFORM_BOOTSTRAP_PRINCIPAL_EMAIL` (case-insensitive, but otherwise exact) | Check for typos, extra whitespace, or a different email than the one you registered with; re-register/login with the exact matching email if needed |
| `409 Bootstrap already consumed` | Someone (possibly you, in an earlier attempt) already completed bootstrap successfully | Check `GET /api/v1/platform/audit` for the existing `platform.bootstrap_succeeded` entry to find out who; if that's wrong, the fix is a `grant`/`revoke` cycle by that existing Super Admin, not another bootstrap attempt |
| `POST /auth/register` returns a validation error | Password under 8 chars, display name under 2 chars, or email under 5 chars | Adjust the request body to satisfy `RegisterRequest`'s field constraints (`redforge/api/v1/auth.py`) |
| Bootstrap succeeds but `GET /platform/me` still shows `has_platform_access: false` | Checking with a *different* account's token than the one that bootstrapped | Re-check with the access token from the same login session that called `POST /bootstrap` |
| Everything above looks right but bootstrap still 403s | The backend process serving your request is a different instance/replica than the one that has the env vars set (e.g. inconsistent rollout across replicas) | Confirm the env vars are set identically across every backend replica, and that all replicas have been restarted |
| `alembic upgrade head` hasn't been run / bootstrap endpoint 500s | Database missing the `platform_bootstrap_state`/`platform_assignments`/`platform_audit_log` tables (migration `0011`) | Run migrations to head before attempting bootstrap |

## 10. Production recommendations

- **Automate Steps 2–7 as a documented, auditable one-time deploy task**
  (e.g. a runbook checklist item in your deploy playbook, or a scripted
  smoke-test that a human still triggers manually) rather than leaving it
  as tribal knowledge — this document is that automation's spec.
- **Block on MFA before granting Super Admin to a production account** if
  your organization's security policy requires a second factor for
  privileged access — the architecture report is explicit that this
  platform does not yet enforce it, so the responsibility currently sits
  with your operational process, not the software.
- **Treat `REDFORGE_PLATFORM_BOOTSTRAP_PRINCIPAL_EMAIL` as configuration,
  not a secret**, but still manage it through the same config-management
  path as your other environment variables (not a manually-typed value
  that drifts between deploys) so Step 2 is reproducible.
- **Verify via Step 6 as part of your deploy verification**, not just
  once — if you ever rebuild an environment from scratch (disaster
  recovery, new region), this entire runbook is what re-establishes
  platform administration there, and it should be exercised, not assumed.
- **Do not attempt to script Step 3–5 with a hardcoded password** for
  automation convenience. If you need unattended provisioning, generate a
  strong random password at run time, store it in your secrets manager
  immediately after registration succeeds, and never write it to logs or
  version control — the existing registration/login flow doesn't require
  anything less secure than this.
