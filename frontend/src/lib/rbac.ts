/**
 * Organization RBAC control-plane API client — wraps GET/POST/PATCH/DELETE
 * /api/v1/admin/* (roles, groups, effective access, admin audit) plus the
 * one existing organization members endpoint used as the user picker
 * source for role/group assignment.
 *
 * organization_id is never sent by the client on any admin_rbac route —
 * it is derived server-side from the caller's token. The one exception,
 * listOrganizationMembers, targets the pre-existing
 * /organizations/{organization_id}/members route, which is itself
 * tenant-scoped by TenantContext; the organization_id path segment here
 * is only ever the caller's own (from getOrganizationId()).
 */
import { api, getOrganizationId } from "./api";

export interface PermissionCatalogItem {
  key: string;
  domain: string;
  description: string;
}

export interface Role {
  id: string;
  organization_id: string;
  name: string;
  description: string;
  permissions: string[];
  is_system: boolean;
  assignment_count: number;
  created_at: string | null;
  updated_at: string | null;
  version: number;
}

export interface Group {
  id: string;
  organization_id: string;
  name: string;
  description: string;
  member_count: number;
  role_count: number;
  created_at: string;
  updated_at: string;
  version: number;
}

export interface EffectiveAccess {
  user_id: string;
  organization_id: string;
  membership_role: string;
  membership_permissions: string[];
  direct_role_ids: string[];
  direct_role_names: string[];
  direct_role_permissions: string[];
  groups: Record<string, unknown>[];
  effective_permissions: string[];
}

export interface AdminAuditEvent {
  actor_id: string;
  action: string;
  target_type: string;
  target_id: string;
  organization_id: string;
  metadata: Record<string, unknown>;
  occurred_at: string;
}

export interface OrganizationMember {
  id: string;
  user_id: string;
  organization_id: string;
  role: string;
  status: string;
  created_at: string;
  updated_at: string;
}

export async function listPermissionCatalog(): Promise<PermissionCatalogItem[]> {
  return api.get<PermissionCatalogItem[]>("/api/v1/admin/permissions");
}

export async function listRoles(): Promise<Role[]> {
  return api.get<Role[]>("/api/v1/admin/roles");
}

export async function createRole(
  name: string,
  description: string,
  permissions: string[]
): Promise<Role> {
  return api.post<Role>("/api/v1/admin/roles", { name, description, permissions });
}

export async function getRole(roleId: string): Promise<Role> {
  return api.get<Role>(`/api/v1/admin/roles/${roleId}`);
}

export async function updateRole(
  roleId: string,
  name: string,
  description: string
): Promise<Role> {
  return api.patch<Role>(`/api/v1/admin/roles/${roleId}`, { name, description });
}

export async function setRolePermissions(roleId: string, permissions: string[]): Promise<Role> {
  return api.post<Role>(`/api/v1/admin/roles/${roleId}/permissions`, { permissions });
}

export async function deleteRole(roleId: string): Promise<void> {
  await api.delete(`/api/v1/admin/roles/${roleId}`);
}

export async function assignUserRole(userId: string, roleId: string): Promise<void> {
  await api.post(`/api/v1/admin/users/${userId}/roles`, { role_id: roleId });
}

export async function revokeUserRole(userId: string, roleId: string): Promise<void> {
  await api.delete(`/api/v1/admin/users/${userId}/roles/${roleId}`);
}

export async function getEffectiveAccess(userId: string): Promise<EffectiveAccess> {
  return api.get<EffectiveAccess>(`/api/v1/admin/users/${userId}/effective-access`);
}

export async function listGroups(): Promise<Group[]> {
  return api.get<Group[]>("/api/v1/admin/groups");
}

export async function createGroup(name: string, description: string): Promise<Group> {
  return api.post<Group>("/api/v1/admin/groups", { name, description });
}

export async function getGroup(groupId: string): Promise<Group> {
  return api.get<Group>(`/api/v1/admin/groups/${groupId}`);
}

export async function updateGroup(
  groupId: string,
  name: string,
  description: string
): Promise<Group> {
  return api.patch<Group>(`/api/v1/admin/groups/${groupId}`, { name, description });
}

export async function deleteGroup(groupId: string): Promise<void> {
  await api.delete(`/api/v1/admin/groups/${groupId}`);
}

export async function listGroupMembers(groupId: string): Promise<string[]> {
  return api.get<string[]>(`/api/v1/admin/groups/${groupId}/members`);
}

export async function addGroupMember(groupId: string, userId: string): Promise<void> {
  await api.post(`/api/v1/admin/groups/${groupId}/members`, { user_id: userId });
}

export async function removeGroupMember(groupId: string, userId: string): Promise<void> {
  await api.delete(`/api/v1/admin/groups/${groupId}/members/${userId}`);
}

export async function listGroupRoles(groupId: string): Promise<string[]> {
  return api.get<string[]>(`/api/v1/admin/groups/${groupId}/roles`);
}

export async function assignGroupRole(groupId: string, roleId: string): Promise<void> {
  await api.post(`/api/v1/admin/groups/${groupId}/roles`, { role_id: roleId });
}

export async function revokeGroupRole(groupId: string, roleId: string): Promise<void> {
  await api.delete(`/api/v1/admin/groups/${groupId}/roles/${roleId}`);
}

export async function listAdminAuditEvents(
  limit = 50,
  offset = 0
): Promise<AdminAuditEvent[]> {
  return api.get<AdminAuditEvent[]>(
    `/api/v1/admin/audit-events?limit=${limit}&offset=${offset}`
  );
}

/** Reuses the pre-existing organization membership list as the user
 * picker source for role/group assignment — no second members endpoint
 * is introduced. Returns [] if no organization is selected. */
export async function listOrganizationMembers(): Promise<OrganizationMember[]> {
  const orgId = getOrganizationId();
  if (!orgId) return [];
  return api.get<OrganizationMember[]>(`/api/v1/organizations/${orgId}/members`);
}
