/**
 * Platform control-plane API client — wraps GET /api/v1/platform/*.
 *
 * Deliberately does NOT infer platform access from email/username/org
 * role anywhere in this file. `getPlatformAccess()` is the single source
 * of truth for whether the current user has any platform standing; the
 * backend remains authoritative regardless of what this returns.
 *
 * Step-up (M2): high-impact mutations (grant/revoke access, suspend/
 * reactivate users/orgs) require an `X-Assurance-Token` header, obtained
 * via `stepUp()`. The token is held only in memory by the caller for the
 * duration of one action — this module never persists it to
 * sessionStorage/localStorage.
 */
import { ApiError, api } from "./api";

export interface PlatformAccess {
  user_id: string;
  platform_roles: string[];
  permissions: string[];
  has_platform_access: boolean;
}

export interface PlatformUser {
  id: string;
  email: string;
  display_name: string;
  status: string;
  created_at: string;
}

export interface PlatformOrganization {
  id: string;
  name: string;
  slug: string;
  status: string;
  plan: string;
  created_at: string;
}

export interface PlatformAssignment {
  id: string;
  user_id: string;
  role: string;
  status: string;
  granted_by: string;
  granted_at: string;
  revoked_by: string | null;
  revoked_at: string | null;
}

export interface PlatformAuditEntry {
  action: string;
  actor_id: string;
  target_id: string;
  role: string | null;
  outcome: string;
  timestamp: string;
}

export interface MFAStatus {
  active: boolean;
  pending_enrollment: boolean;
}

export interface MFAEnrollBegin {
  enrollment_id: string;
  secret: string;
  provisioning_uri: string;
}

export const PLATFORM_ROLES = [
  "platform_super_admin",
  "platform_security_admin",
  "platform_support",
  "platform_auditor",
] as const;

/** True when an ApiError indicates the caller needs to complete MFA
 * step-up before retrying — the frontend should show the step-up
 * dialog rather than a generic error. */
export function isAssuranceRequiredError(err: unknown): boolean {
  return err instanceof ApiError && err.code === "MFA_ASSURANCE_REQUIRED";
}

export async function getPlatformAccess(): Promise<PlatformAccess> {
  return api.get<PlatformAccess>("/api/v1/platform/me");
}

export async function getBootstrapStatus(): Promise<{ available: boolean }> {
  return api.get<{ available: boolean }>("/api/v1/platform/bootstrap/status");
}

export async function bootstrapSuperAdmin(): Promise<{
  assignment_id: string;
  role: string;
  status: string;
}> {
  return api.post("/api/v1/platform/bootstrap");
}

export async function listPlatformUsers(): Promise<PlatformUser[]> {
  return api.get<PlatformUser[]>("/api/v1/platform/users?limit=100");
}

export async function listPlatformOrganizations(): Promise<PlatformOrganization[]> {
  return api.get<PlatformOrganization[]>("/api/v1/platform/organizations?limit=100");
}

export async function listPlatformAccess(): Promise<PlatformAssignment[]> {
  return api.get<PlatformAssignment[]>("/api/v1/platform/access?limit=100");
}

export async function getPlatformAudit(): Promise<PlatformAuditEntry[]> {
  return api.get<PlatformAuditEntry[]>("/api/v1/platform/audit?limit=100");
}

// ─── MFA ────────────────────────────────────────────────────────────────────

export async function getMfaStatus(): Promise<MFAStatus> {
  return api.get<MFAStatus>("/api/v1/platform/mfa/status");
}

export async function beginMfaEnrollment(): Promise<MFAEnrollBegin> {
  return api.post<MFAEnrollBegin>("/api/v1/platform/mfa/enroll/begin");
}

export async function verifyMfaEnrollment(enrollmentId: string, code: string): Promise<void> {
  await api.post("/api/v1/platform/mfa/enroll/verify", {
    enrollment_id: enrollmentId,
    code,
  });
}

export async function revokeMfa(): Promise<void> {
  await api.post("/api/v1/platform/mfa/revoke");
}

// ─── Privileged assurance (step-up) ─────────────────────────────────────────

export async function stepUp(code: string): Promise<{ assurance_token: string; expires_at: string }> {
  return api.post("/api/v1/platform/assurance/step-up", { code });
}

// ─── Access governance (requires X-Assurance-Token) ─────────────────────────

export async function grantPlatformAccess(
  targetUserId: string,
  role: string,
  assuranceToken: string
): Promise<PlatformAssignment> {
  return api.post<PlatformAssignment>(
    "/api/v1/platform/access",
    { target_user_id: targetUserId, role },
    { "X-Assurance-Token": assuranceToken }
  );
}

export async function revokePlatformAccess(
  assignmentId: string,
  assuranceToken: string
): Promise<PlatformAssignment> {
  return api.post<PlatformAssignment>(
    `/api/v1/platform/access/${assignmentId}/revoke`,
    undefined,
    { "X-Assurance-Token": assuranceToken }
  );
}

// ─── User governance (requires X-Assurance-Token) ───────────────────────────

export async function suspendPlatformUser(
  userId: string,
  reason: string,
  assuranceToken: string
): Promise<PlatformUser> {
  return api.post<PlatformUser>(
    `/api/v1/platform/users/${userId}/suspend`,
    { reason },
    { "X-Assurance-Token": assuranceToken }
  );
}

export async function reactivatePlatformUser(
  userId: string,
  assuranceToken: string
): Promise<PlatformUser> {
  return api.post<PlatformUser>(
    `/api/v1/platform/users/${userId}/reactivate`,
    undefined,
    { "X-Assurance-Token": assuranceToken }
  );
}

// ─── Organization governance (requires X-Assurance-Token) ───────────────────

export async function suspendPlatformOrganization(
  organizationId: string,
  reason: string,
  assuranceToken: string
): Promise<void> {
  await api.post(
    `/api/v1/platform/organizations/${organizationId}/suspend`,
    { reason },
    { "X-Assurance-Token": assuranceToken }
  );
}

export async function reactivatePlatformOrganization(
  organizationId: string,
  assuranceToken: string
): Promise<void> {
  await api.post(
    `/api/v1/platform/organizations/${organizationId}/reactivate`,
    undefined,
    { "X-Assurance-Token": assuranceToken }
  );
}
