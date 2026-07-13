"use client";

import { useEffect, useMemo, useState } from "react";
import { ApiError } from "@/lib/api";
import {
  addGroupMember,
  assignGroupRole,
  createGroup,
  deleteGroup,
  listGroupMembers,
  listGroupRoles,
  listGroups,
  listOrganizationMembers,
  listRoles,
  removeGroupMember,
  revokeGroupRole,
  updateGroup,
  type Group,
  type OrganizationMember,
  type Role,
} from "@/lib/rbac";

export default function GroupsRbacPage() {
  const [groups, setGroups] = useState<Group[] | null>(null);
  const [roles, setRoles] = useState<Role[]>([]);
  const [members, setMembers] = useState<OrganizationMember[]>([]);
  const [error, setError] = useState("");
  const [forbidden, setForbidden] = useState(false);

  const [newName, setNewName] = useState("");
  const [newDescription, setNewDescription] = useState("");
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState("");

  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [editName, setEditName] = useState("");
  const [editDescription, setEditDescription] = useState("");
  const [groupMembers, setGroupMembers] = useState<string[] | null>(null);
  const [groupRoleIds, setGroupRoleIds] = useState<string[] | null>(null);
  const [pickMemberId, setPickMemberId] = useState("");
  const [pickRoleId, setPickRoleId] = useState("");
  const [detailError, setDetailError] = useState("");
  const [saving, setSaving] = useState(false);

  function load() {
    setForbidden(false);
    setError("");
    Promise.all([listGroups(), listRoles(), listOrganizationMembers()])
      .then(([g, r, m]) => {
        setGroups(g);
        setRoles(r);
        setMembers(m);
      })
      .catch((err) => {
        if (err instanceof ApiError && err.status === 403) {
          setForbidden(true);
        } else {
          setError("UNAVAILABLE — failed to load groups.");
        }
      });
  }

  useEffect(load, []);

  const rolesById = useMemo(() => Object.fromEntries(roles.map((r) => [r.id, r])), [roles]);
  const membersById = useMemo(
    () => Object.fromEntries(members.map((m) => [m.user_id, m])),
    [members]
  );
  const selected = groups?.find((g) => g.id === selectedId) ?? null;

  async function openDetail(group: Group) {
    setSelectedId(group.id);
    setEditName(group.name);
    setEditDescription(group.description);
    setGroupMembers(null);
    setGroupRoleIds(null);
    setDetailError("");
    try {
      const [m, r] = await Promise.all([listGroupMembers(group.id), listGroupRoles(group.id)]);
      setGroupMembers(m);
      setGroupRoleIds(r);
    } catch {
      setDetailError("UNAVAILABLE — failed to load group detail.");
    }
  }

  async function create() {
    setCreating(true);
    setCreateError("");
    try {
      const group = await createGroup(newName, newDescription);
      setGroups((prev) => [...(prev ?? []), group]);
      setNewName("");
      setNewDescription("");
    } catch (err) {
      setCreateError(err instanceof ApiError ? err.message : "Failed to create group.");
    } finally {
      setCreating(false);
    }
  }

  async function saveMetadata() {
    if (!selected) return;
    setSaving(true);
    setDetailError("");
    try {
      const updated = await updateGroup(selected.id, editName, editDescription);
      setGroups((prev) => (prev ?? []).map((g) => (g.id === updated.id ? updated : g)));
    } catch (err) {
      setDetailError(err instanceof ApiError ? err.message : "Failed to update group.");
    } finally {
      setSaving(false);
    }
  }

  async function remove(group: Group) {
    if (!window.confirm(`Delete group "${group.name}"? This cannot be undone.`)) return;
    try {
      await deleteGroup(group.id);
      setGroups((prev) => (prev ?? []).filter((g) => g.id !== group.id));
      if (selectedId === group.id) setSelectedId(null);
    } catch (err) {
      setDetailError(err instanceof ApiError ? err.message : "Failed to delete group.");
    }
  }

  async function addMember() {
    if (!selected || !pickMemberId) return;
    setDetailError("");
    try {
      await addGroupMember(selected.id, pickMemberId);
      setGroupMembers((prev) => [...(prev ?? []), pickMemberId]);
      setPickMemberId("");
      setGroups((prev) =>
        (prev ?? []).map((g) =>
          g.id === selected.id ? { ...g, member_count: g.member_count + 1 } : g
        )
      );
    } catch (err) {
      setDetailError(err instanceof ApiError ? err.message : "Failed to add member.");
    }
  }

  async function removeMember(userId: string) {
    if (!selected) return;
    setDetailError("");
    try {
      await removeGroupMember(selected.id, userId);
      setGroupMembers((prev) => (prev ?? []).filter((id) => id !== userId));
      setGroups((prev) =>
        (prev ?? []).map((g) =>
          g.id === selected.id ? { ...g, member_count: Math.max(0, g.member_count - 1) } : g
        )
      );
    } catch (err) {
      setDetailError(err instanceof ApiError ? err.message : "Failed to remove member.");
    }
  }

  async function addRole() {
    if (!selected || !pickRoleId) return;
    setDetailError("");
    try {
      await assignGroupRole(selected.id, pickRoleId);
      setGroupRoleIds((prev) => [...(prev ?? []), pickRoleId]);
      setPickRoleId("");
      setGroups((prev) =>
        (prev ?? []).map((g) =>
          g.id === selected.id ? { ...g, role_count: g.role_count + 1 } : g
        )
      );
    } catch (err) {
      setDetailError(err instanceof ApiError ? err.message : "Failed to assign role.");
    }
  }

  async function removeRole(roleId: string) {
    if (!selected) return;
    setDetailError("");
    try {
      await revokeGroupRole(selected.id, roleId);
      setGroupRoleIds((prev) => (prev ?? []).filter((id) => id !== roleId));
      setGroups((prev) =>
        (prev ?? []).map((g) =>
          g.id === selected.id ? { ...g, role_count: Math.max(0, g.role_count - 1) } : g
        )
      );
    } catch (err) {
      setDetailError(err instanceof ApiError ? err.message : "Failed to revoke role.");
    }
  }

  if (forbidden) {
    return (
      <div>
        <h1 className="text-2xl font-bold text-white">Groups</h1>
        <div className="mt-6 rounded-lg border border-red-800 bg-red-950 px-4 py-3 text-sm text-red-300">
          You don&apos;t have access to manage groups.
        </div>
      </div>
    );
  }

  const availableMembers = members.filter((m) => !(groupMembers ?? []).includes(m.user_id));
  const availableRoles = roles.filter((r) => !(groupRoleIds ?? []).includes(r.id));

  return (
    <div>
      <h1 className="text-2xl font-bold text-white">Groups</h1>
      <p className="mt-1 text-sm text-gray-400">
        Security groups grant roles to all their members at once.
      </p>

      <div className="mt-6 rounded-xl border border-gray-800 bg-gray-900 p-4">
        <div className="text-sm font-medium text-gray-300">Create group</div>
        <div className="mt-3 flex flex-wrap gap-2">
          <input
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            placeholder="Group name"
            className="rounded-lg border border-gray-700 bg-gray-800 px-3 py-1.5 text-sm text-white"
          />
          <input
            value={newDescription}
            onChange={(e) => setNewDescription(e.target.value)}
            placeholder="Description"
            className="flex-1 rounded-lg border border-gray-700 bg-gray-800 px-3 py-1.5 text-sm text-white"
          />
          <button
            onClick={create}
            disabled={creating || !newName}
            className="rounded-lg bg-red-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-red-700 disabled:opacity-50"
          >
            {creating ? "Creating…" : "Create"}
          </button>
        </div>
        {createError && <div className="mt-2 text-xs text-red-400">{createError}</div>}
      </div>

      {error ? (
        <div className="mt-6 rounded-lg border border-red-800 bg-red-950 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      ) : groups === null ? (
        <div className="mt-6 text-gray-400">Loading…</div>
      ) : groups.length === 0 ? (
        <div className="mt-6 rounded-xl border border-gray-800 bg-gray-900 p-8 text-center text-sm text-gray-500">
          No groups yet.
        </div>
      ) : (
        <div className="mt-6 overflow-x-auto rounded-xl border border-gray-800">
          <table className="w-full text-sm">
            <thead className="bg-gray-900 text-left text-xs text-gray-500">
              <tr>
                <th className="px-4 py-2">Name</th>
                <th className="px-4 py-2">Description</th>
                <th className="px-4 py-2">Members</th>
                <th className="px-4 py-2">Roles</th>
                <th className="px-4 py-2">Actions</th>
              </tr>
            </thead>
            <tbody>
              {groups.map((g) => (
                <tr
                  key={g.id}
                  onClick={() => openDetail(g)}
                  className="cursor-pointer border-t border-gray-800 hover:bg-gray-900"
                >
                  <td className="px-4 py-2 text-gray-200">{g.name}</td>
                  <td className="px-4 py-2 text-gray-500">{g.description}</td>
                  <td className="px-4 py-2 text-gray-500">{g.member_count}</td>
                  <td className="px-4 py-2 text-gray-500">{g.role_count}</td>
                  <td className="px-4 py-2" onClick={(e) => e.stopPropagation()}>
                    <button
                      onClick={() => remove(g)}
                      className="text-xs text-gray-500 hover:text-red-400"
                    >
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {selected && (
        <div className="mt-6 rounded-xl border border-gray-700 bg-gray-900 p-6">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-white">{selected.name}</h2>
            <button
              onClick={() => setSelectedId(null)}
              className="text-xs text-gray-500 hover:text-gray-300"
            >
              Close
            </button>
          </div>

          <div className="mt-4 flex flex-wrap gap-2">
            <input
              value={editName}
              onChange={(e) => setEditName(e.target.value)}
              className="rounded-lg border border-gray-700 bg-gray-800 px-3 py-1.5 text-sm text-white"
            />
            <input
              value={editDescription}
              onChange={(e) => setEditDescription(e.target.value)}
              className="flex-1 rounded-lg border border-gray-700 bg-gray-800 px-3 py-1.5 text-sm text-white"
            />
            <button
              onClick={saveMetadata}
              disabled={saving}
              className="rounded-lg bg-gray-700 px-4 py-1.5 text-sm font-medium text-white hover:bg-gray-600 disabled:opacity-50"
            >
              Save
            </button>
          </div>

          {detailError && <div className="mt-3 text-xs text-red-400">{detailError}</div>}

          <div className="mt-6 grid gap-6 sm:grid-cols-2">
            <div>
              <div className="text-sm font-medium text-gray-300">
                Members ({groupMembers?.length ?? 0})
              </div>
              {groupMembers === null ? (
                <div className="mt-2 text-xs text-gray-500">Loading…</div>
              ) : (
                <>
                  <div className="mt-2 space-y-1">
                    {groupMembers.length === 0 ? (
                      <div className="text-xs text-gray-600">No members.</div>
                    ) : (
                      groupMembers.map((userId) => (
                        <div
                          key={userId}
                          className="flex items-center justify-between rounded-lg border border-gray-800 bg-gray-950 px-3 py-2 text-xs text-gray-300"
                        >
                          <span>{membersById[userId]?.role ? `${userId} (${membersById[userId].role})` : userId}</span>
                          <button
                            onClick={() => removeMember(userId)}
                            className="text-gray-500 hover:text-red-400"
                          >
                            Remove
                          </button>
                        </div>
                      ))
                    )}
                  </div>
                  <div className="mt-3 flex gap-2">
                    <select
                      value={pickMemberId}
                      onChange={(e) => setPickMemberId(e.target.value)}
                      className="flex-1 rounded-lg border border-gray-700 bg-gray-800 px-3 py-1.5 text-xs text-white"
                    >
                      <option value="">Select member…</option>
                      {availableMembers.map((m) => (
                        <option key={m.user_id} value={m.user_id}>
                          {m.user_id} ({m.role})
                        </option>
                      ))}
                    </select>
                    <button
                      onClick={addMember}
                      disabled={!pickMemberId}
                      className="rounded-lg bg-red-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-red-700 disabled:opacity-50"
                    >
                      Add
                    </button>
                  </div>
                </>
              )}
            </div>

            <div>
              <div className="text-sm font-medium text-gray-300">
                Roles ({groupRoleIds?.length ?? 0})
              </div>
              {groupRoleIds === null ? (
                <div className="mt-2 text-xs text-gray-500">Loading…</div>
              ) : (
                <>
                  <div className="mt-2 space-y-1">
                    {groupRoleIds.length === 0 ? (
                      <div className="text-xs text-gray-600">No roles assigned.</div>
                    ) : (
                      groupRoleIds.map((roleId) => (
                        <div
                          key={roleId}
                          className="flex items-center justify-between rounded-lg border border-gray-800 bg-gray-950 px-3 py-2 text-xs text-gray-300"
                        >
                          <span>{rolesById[roleId]?.name ?? roleId}</span>
                          <button
                            onClick={() => removeRole(roleId)}
                            className="text-gray-500 hover:text-red-400"
                          >
                            Revoke
                          </button>
                        </div>
                      ))
                    )}
                  </div>
                  <div className="mt-3 flex gap-2">
                    <select
                      value={pickRoleId}
                      onChange={(e) => setPickRoleId(e.target.value)}
                      className="flex-1 rounded-lg border border-gray-700 bg-gray-800 px-3 py-1.5 text-xs text-white"
                    >
                      <option value="">Select role…</option>
                      {availableRoles.map((r) => (
                        <option key={r.id} value={r.id}>
                          {r.name}
                        </option>
                      ))}
                    </select>
                    <button
                      onClick={addRole}
                      disabled={!pickRoleId}
                      className="rounded-lg bg-red-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-red-700 disabled:opacity-50"
                    >
                      Assign
                    </button>
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
