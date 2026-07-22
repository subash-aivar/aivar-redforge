import { api } from "@/lib/api";

// ─── Types ───────────────────────────────────────────────────────────────────

export interface CredentialResponse {
  credential_id: string;
  tenant_id: string;
  name: string;
  category: string;
  subtype: string;
  schema_id: string | null;
  state: string;
  owner_principal_id: string;
  active_version_id: string | null;
  rotation_policy_id: string | null;
  expiration_policy_id: string | null;
  vault_backend_id: string;
  description: string | null;
  tags: Record<string, string>;
  created_at: string;
  updated_at: string;
  version: number;
}

export interface ListCredentialsResponse {
  items: CredentialResponse[];
  total: number;
  limit: number;
  offset: number;
}

export interface VersionResponse {
  version_id: string;
  credential_id: string;
  tenant_id: string;
  version_number: number;
  version_state: string;
  created_by: string;
  created_at: string;
  expires_at: string | null;
  rotation_trigger: string | null;
  rotation_policy_id: string | null;
}

export interface ResolveCredentialResponse {
  credential_id: string;
  version_id: string;
  secret_b64: string;
  resolved_at: string;
}

export interface RotationPolicyResponse {
  policy_id: string;
  tenant_id: string;
  name: string;
  interval_days: number | null;
  max_versions_kept: number;
  notify_days_before: number;
  auto_rotate: boolean;
  auto_commit: boolean;
  commit_window_hours: number;
  created_at: string;
  updated_at: string;
  version: number;
}

export interface ExpirationPolicyResponse {
  policy_id: string;
  tenant_id: string;
  name: string;
  ttl_days: number;
  warn_days_before: number;
  hard_expire: boolean;
  created_at: string;
  updated_at: string;
  version: number;
}

export interface VaultBackendResponse {
  backend_id: string;
  tenant_id: string;
  name: string;
  backend_type: string;
  is_default: boolean;
  created_at: string;
  updated_at: string;
  version: number;
}

export interface AuditEntryResponse {
  entry_id: string;
  audit_log_id: string;
  credential_id: string;
  tenant_id: string;
  operation: string;
  outcome: string;
  principal_id: string;
  occurred_at: string;
  detail: string;
  client_ip: string | null;
  request_id: string | null;
}

// ─── Credentials ─────────────────────────────────────────────────────────────

export function createCredential(body: {
  name: string;
  category: string;
  subtype: string;
  schema_id?: string;
  vault_backend_id: string;
  plaintext_secret: string;
  description?: string;
  tags?: Record<string, string>;
  expires_at?: string;
}): Promise<CredentialResponse> {
  return api.post<CredentialResponse>("/api/v1/credentials", body);
}

export function getCredential(id: string): Promise<CredentialResponse> {
  return api.get<CredentialResponse>(`/api/v1/credentials/${id}`);
}

export function listCredentials(params?: {
  states?: string[];
  limit?: number;
  offset?: number;
}): Promise<ListCredentialsResponse> {
  const q = new URLSearchParams();
  if (params?.states) params.states.forEach((s) => q.append("states", s));
  if (params?.limit != null) q.set("limit", String(params.limit));
  if (params?.offset != null) q.set("offset", String(params.offset));
  const qs = q.toString();
  return api.get<ListCredentialsResponse>(`/api/v1/credentials${qs ? `?${qs}` : ""}`);
}

export function resolveCredential(
  id: string,
  body: { purpose: string; break_glass?: boolean; justification?: string }
): Promise<ResolveCredentialResponse> {
  return api.post<ResolveCredentialResponse>(`/api/v1/credentials/${id}/resolve`, body);
}

export function updateCredentialMetadata(
  id: string,
  body: { description?: string; tags?: Record<string, string> }
): Promise<CredentialResponse> {
  return api.patch<CredentialResponse>(`/api/v1/credentials/${id}/metadata`, body);
}

export function disableCredential(id: string, reason: string): Promise<CredentialResponse> {
  return api.post<CredentialResponse>(`/api/v1/credentials/${id}/disable`, { reason });
}

export function enableCredential(id: string): Promise<CredentialResponse> {
  return api.post<CredentialResponse>(`/api/v1/credentials/${id}/enable`, {});
}

export function revokeCredential(id: string, reason: string): Promise<CredentialResponse> {
  return api.post<CredentialResponse>(`/api/v1/credentials/${id}/revoke`, { reason });
}

export function emergencyRevokeCredential(id: string, justification: string): Promise<CredentialResponse> {
  return api.post<CredentialResponse>(`/api/v1/credentials/${id}/emergency-revoke`, { justification });
}

export function rotateCredential(
  id: string,
  body: { new_plaintext_secret: string; trigger?: string; policy_id?: string; notes?: string }
): Promise<CredentialResponse> {
  return api.post<CredentialResponse>(`/api/v1/credentials/${id}/rotate`, body);
}

export function commitRotation(id: string): Promise<CredentialResponse> {
  return api.post<CredentialResponse>(`/api/v1/credentials/${id}/commit-rotation`, {});
}

export function abortRotation(id: string): Promise<CredentialResponse> {
  return api.post<CredentialResponse>(`/api/v1/credentials/${id}/abort-rotation`, {});
}

export function recoverCredential(
  id: string,
  targetVersionId: string,
  justification: string
): Promise<CredentialResponse> {
  return api.post<CredentialResponse>(`/api/v1/credentials/${id}/recover`, {
    target_version_id: targetVersionId,
    justification,
  });
}

export function rollbackVersion(id: string, targetVersionId: string): Promise<CredentialResponse> {
  return api.post<CredentialResponse>(`/api/v1/credentials/${id}/rollback-version`, {
    target_version_id: targetVersionId,
  });
}

export function hardDeleteCredential(id: string): Promise<void> {
  return api.delete<void>(`/api/v1/credentials/${id}`);
}

export function listVersions(id: string, states?: string[]): Promise<{ items: VersionResponse[] }> {
  const q = new URLSearchParams();
  if (states) states.forEach((s) => q.append("states", s));
  const qs = q.toString();
  return api.get<{ items: VersionResponse[] }>(`/api/v1/credentials/${id}/versions${qs ? `?${qs}` : ""}`);
}

export function getVersion(id: string, versionId: string): Promise<VersionResponse> {
  return api.get<VersionResponse>(`/api/v1/credentials/${id}/versions/${versionId}`);
}

export function attachRotationPolicy(id: string, policyId: string): Promise<CredentialResponse> {
  return api.post<CredentialResponse>(`/api/v1/credentials/${id}/attach-rotation-policy`, {
    policy_id: policyId,
  });
}

export function detachRotationPolicy(id: string, reason?: string): Promise<CredentialResponse> {
  return api.post<CredentialResponse>(`/api/v1/credentials/${id}/detach-rotation-policy`, { reason });
}

export function attachExpirationPolicy(id: string, policyId: string): Promise<CredentialResponse> {
  return api.post<CredentialResponse>(`/api/v1/credentials/${id}/attach-expiration-policy`, {
    policy_id: policyId,
  });
}

export function detachExpirationPolicy(id: string, reason?: string): Promise<CredentialResponse> {
  return api.post<CredentialResponse>(`/api/v1/credentials/${id}/detach-expiration-policy`, { reason });
}

// ─── Rotation Policies ───────────────────────────────────────────────────────

export function createRotationPolicy(body: {
  name: string;
  interval_days: number | null;
  max_versions_kept: number;
  notify_days_before: number;
  auto_rotate: boolean;
  auto_commit?: boolean;
  commit_window_hours?: number;
}): Promise<RotationPolicyResponse> {
  return api.post<RotationPolicyResponse>("/api/v1/credential-policies/rotation", body);
}

export function listRotationPolicies(): Promise<RotationPolicyResponse[]> {
  return api.get<RotationPolicyResponse[]>("/api/v1/credential-policies/rotation");
}

export function getRotationPolicy(id: string): Promise<RotationPolicyResponse> {
  return api.get<RotationPolicyResponse>(`/api/v1/credential-policies/rotation/${id}`);
}

export function updateRotationPolicy(
  id: string,
  body: {
    interval_days: number | null;
    max_versions_kept: number;
    notify_days_before: number;
    auto_rotate: boolean;
    auto_commit?: boolean;
    commit_window_hours?: number;
  }
): Promise<RotationPolicyResponse> {
  return api.patch<RotationPolicyResponse>(`/api/v1/credential-policies/rotation/${id}`, body);
}

export function deleteRotationPolicy(id: string): Promise<void> {
  return api.delete<void>(`/api/v1/credential-policies/rotation/${id}`);
}

// ─── Expiration Policies ─────────────────────────────────────────────────────

export function createExpirationPolicy(body: {
  name: string;
  ttl_days: number;
  warn_days_before: number;
  hard_expire: boolean;
}): Promise<ExpirationPolicyResponse> {
  return api.post<ExpirationPolicyResponse>("/api/v1/credential-policies/expiration", body);
}

export function listExpirationPolicies(): Promise<ExpirationPolicyResponse[]> {
  return api.get<ExpirationPolicyResponse[]>("/api/v1/credential-policies/expiration");
}

export function getExpirationPolicy(id: string): Promise<ExpirationPolicyResponse> {
  return api.get<ExpirationPolicyResponse>(`/api/v1/credential-policies/expiration/${id}`);
}

export function updateExpirationPolicy(
  id: string,
  body: { ttl_days: number; warn_days_before: number; hard_expire: boolean }
): Promise<ExpirationPolicyResponse> {
  return api.patch<ExpirationPolicyResponse>(`/api/v1/credential-policies/expiration/${id}`, body);
}

export function deleteExpirationPolicy(id: string): Promise<void> {
  return api.delete<void>(`/api/v1/credential-policies/expiration/${id}`);
}

// ─── Vault Backends ──────────────────────────────────────────────────────────

export function registerVaultBackend(body: {
  name: string;
  backend_type: string;
  config?: Record<string, string>;
  is_default?: boolean;
}): Promise<VaultBackendResponse> {
  return api.post<VaultBackendResponse>("/api/v1/vault-backends", body);
}

export function listVaultBackends(): Promise<VaultBackendResponse[]> {
  return api.get<VaultBackendResponse[]>("/api/v1/vault-backends");
}

export function getVaultBackend(id: string): Promise<VaultBackendResponse> {
  return api.get<VaultBackendResponse>(`/api/v1/vault-backends/${id}`);
}

export function deleteVaultBackend(id: string): Promise<void> {
  return api.delete<void>(`/api/v1/vault-backends/${id}`);
}

// ─── Audit Logs ──────────────────────────────────────────────────────────────

export function listAuditEntries(
  credentialId: string,
  params?: { operations?: string[]; limit?: number; offset?: number }
): Promise<{ items: AuditEntryResponse[] }> {
  const q = new URLSearchParams();
  if (params?.operations) params.operations.forEach((o) => q.append("operations", o));
  if (params?.limit != null) q.set("limit", String(params.limit));
  if (params?.offset != null) q.set("offset", String(params.offset));
  const qs = q.toString();
  return api.get<{ items: AuditEntryResponse[] }>(`/api/v1/audit-logs/credentials/${credentialId}${qs ? `?${qs}` : ""}`);
}
