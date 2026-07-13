/**
 * Authentication service — wraps the real RedForge auth API.
 */
import { api, setToken, clearToken, clearOrganizationId, setOrganizationId } from "./api";

export interface AuthResult {
  user_id: string;
  email: string;
  display_name: string;
  access_token: string;
  refresh_token: string;
  expires_in: number;
  token_type: string;
}

export interface UserProfile {
  user_id: string;
  email: string;
  display_name: string;
  status: string;
}

export interface AccessibleOrganization {
  id: string;
  name: string;
  slug: string;
  status: string;
  plan: string;
}

export async function login(email: string, password: string): Promise<AuthResult> {
  const result = await api.post<AuthResult>("/api/v1/auth/login", { email, password });
  setToken(result.access_token);
  return result;
}

export async function register(
  email: string,
  displayName: string,
  password: string
): Promise<AuthResult> {
  const result = await api.post<AuthResult>("/api/v1/auth/register", {
    email,
    display_name: displayName,
    password,
  });
  setToken(result.access_token);
  return result;
}

export async function getMe(): Promise<UserProfile> {
  return api.get<UserProfile>("/api/v1/auth/me");
}

export async function getAccessibleOrganizations(): Promise<AccessibleOrganization[]> {
  return api.get<AccessibleOrganization[]>("/api/v1/auth/organizations");
}

export async function selectOrganization(orgId: string): Promise<AuthResult> {
  const result = await api.post<AuthResult>(
    `/api/v1/auth/organizations/${orgId}/select`,
  );
  // Atomically replace the unscoped token with the org-scoped one.
  setToken(result.access_token);
  setOrganizationId(orgId);
  return result;
}

export async function createOrganization(name: string, slug: string): Promise<{ id: string; name: string }> {
  return api.post<{ id: string; name: string }>("/api/v1/organizations", { name, slug });
}

export function logout(): void {
  clearToken();
  clearOrganizationId();
  window.location.href = "/login";
}
