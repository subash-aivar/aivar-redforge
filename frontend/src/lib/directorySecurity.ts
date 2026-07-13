/**
 * Directory & Identity Security Visibility API client — M5.
 *
 * Read-only: there is no create/update/delete method here on purpose —
 * identities/groups/memberships are written exclusively by the backend
 * discovery pipeline from a real directory connector, never by the
 * browser directly.
 */
import { api } from "./api";

export interface DirectoryIdentity {
  id: string;
  organization_id: string;
  connector_id: string;
  external_id: string;
  principal_category: string;
  display_name: string;
  principal_name: string;
  source_enabled: boolean;
  privilege_classification: string;
  privilege_reason: string;
  observation_lifecycle: string;
  first_observed_at: string;
  last_observed_at: string;
}

export interface DirectoryGroup {
  id: string;
  organization_id: string;
  connector_id: string;
  external_id: string;
  display_name: string;
  is_recognized_privileged: boolean;
  first_observed_at: string;
  last_observed_at: string;
}

export interface Membership {
  id: string;
  identity_id: string;
  group_id: string;
}

export interface SecurityObservation {
  rule_id: string;
  title: string;
  summary: string;
  affected_identity_id: string;
  affected_group_id: string | null;
}

export async function listIdentities(
  principalCategory?: string,
  privilegeClassification?: string
): Promise<DirectoryIdentity[]> {
  const params = new URLSearchParams();
  if (principalCategory) params.set("principal_category", principalCategory);
  if (privilegeClassification) params.set("privilege_classification", privilegeClassification);
  const qs = params.toString() ? `?${params.toString()}` : "";
  return api.get<DirectoryIdentity[]>(`/api/v1/identities${qs}`);
}

export async function getIdentity(identityId: string): Promise<DirectoryIdentity> {
  return api.get<DirectoryIdentity>(`/api/v1/identities/${identityId}`);
}

export async function getIdentityMemberships(identityId: string): Promise<Membership[]> {
  return api.get<Membership[]>(`/api/v1/identities/${identityId}/memberships`);
}

export async function listGroups(): Promise<DirectoryGroup[]> {
  return api.get<DirectoryGroup[]>("/api/v1/directory-groups");
}

export async function getGroup(groupId: string): Promise<DirectoryGroup> {
  return api.get<DirectoryGroup>(`/api/v1/directory-groups/${groupId}`);
}

export async function getGroupMembers(groupId: string): Promise<Membership[]> {
  return api.get<Membership[]>(`/api/v1/directory-groups/${groupId}/members`);
}

export async function listSecurityObservations(): Promise<SecurityObservation[]> {
  return api.get<SecurityObservation[]>("/api/v1/identity-security/observations");
}

export interface RegisterDirectoryConnectorRequest {
  name: string;
  server_uri: string;
  base_dn: string;
  bind_dn: string;
  credential_reference_id: string;
  use_start_tls: boolean;
  allow_insecure_plaintext: boolean;
  privileged_group_dns: string[];
  description?: string;
}

export async function registerDirectoryConnector(
  body: RegisterDirectoryConnectorRequest
): Promise<{ id: string }> {
  return api.post<{ id: string }>("/api/v1/connectors/directory", body);
}
