"use client";

import { useEffect, useMemo, useState } from "react";
import { ApiError } from "@/lib/api";
import {
  createRole,
  deleteRole,
  listPermissionCatalog,
  listRoles,
  setRolePermissions,
  updateRole,
  type PermissionCatalogItem,
  type Role,
} from "@/lib/rbac";

export default function RolesPage() {
  const [roles, setRoles] = useState<Role[] | null>(null);
  const [catalog, setCatalog] = useState<PermissionCatalogItem[] | null>(null);
  const [error, setError] = useState("");
  const [forbidden, setForbidden] = useState(false);

  const [creating, setCreating] = useState(false);
  const [newName, setNewName] = useState("");
  const [newDescription, setNewDescription] = useState("");
  const [createError, setCreateError] = useState("");

  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [editName, setEditName] = useState("");
  const [editDescription, setEditDescription] = useState("");
  const [editPermissions, setEditPermissions] = useState<Set<string>>(new Set());
  const [detailError, setDetailError] = useState("");
  const [saving, setSaving] = useState(false);
  const [deleteError, setDeleteError] = useState("");

  function load() {
    setForbidden(false);
    setError("");
    Promise.all([listRoles(), listPermissionCatalog()])
      .then(([r, c]) => {
        setRoles(r);
        setCatalog(c);
      })
      .catch((err) => {
        if (err instanceof ApiError && err.status === 403) {
          setForbidden(true);
        } else {
          setError("UNAVAILABLE — failed to load roles.");
        }
      });
  }

  useEffect(load, []);

  const domains = useMemo(() => {
    const grouped = new Map<string, PermissionCatalogItem[]>();
    for (const item of catalog ?? []) {
      const bucket = grouped.get(item.domain) ?? [];
      bucket.push(item);
      grouped.set(item.domain, bucket);
    }
    return grouped;
  }, [catalog]);

  const selected = roles?.find((r) => r.id === selectedId) ?? null;

  function openDetail(role: Role) {
    setSelectedId(role.id);
    setEditName(role.name);
    setEditDescription(role.description);
    setEditPermissions(new Set(role.permissions));
    setDetailError("");
    setDeleteError("");
  }

  async function create() {
    setCreating(true);
    setCreateError("");
    try {
      const role = await createRole(newName, newDescription, []);
      setRoles((prev) => [...(prev ?? []), role]);
      setNewName("");
      setNewDescription("");
    } catch (err) {
      setCreateError(err instanceof ApiError ? err.message : "Failed to create role.");
    } finally {
      setCreating(false);
    }
  }

  async function saveMetadata() {
    if (!selected) return;
    setSaving(true);
    setDetailError("");
    try {
      const updated = await updateRole(selected.id, editName, editDescription);
      setRoles((prev) => (prev ?? []).map((r) => (r.id === updated.id ? updated : r)));
    } catch (err) {
      setDetailError(err instanceof ApiError ? err.message : "Failed to update role.");
    } finally {
      setSaving(false);
    }
  }

  async function savePermissions() {
    if (!selected) return;
    setSaving(true);
    setDetailError("");
    try {
      const updated = await setRolePermissions(selected.id, Array.from(editPermissions));
      setRoles((prev) => (prev ?? []).map((r) => (r.id === updated.id ? updated : r)));
    } catch (err) {
      setDetailError(err instanceof ApiError ? err.message : "Failed to update permissions.");
    } finally {
      setSaving(false);
    }
  }

  async function remove(role: Role) {
    if (!window.confirm(`Delete role "${role.name}"? This cannot be undone.`)) return;
    setDeleteError("");
    try {
      await deleteRole(role.id);
      setRoles((prev) => (prev ?? []).filter((r) => r.id !== role.id));
      if (selectedId === role.id) setSelectedId(null);
    } catch (err) {
      setDeleteError(err instanceof ApiError ? err.message : "Failed to delete role.");
    }
  }

  function togglePermission(key: string) {
    setEditPermissions((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  if (forbidden) {
    return (
      <div>
        <h1 className="text-2xl font-bold text-white">Roles &amp; Permissions</h1>
        <div className="mt-6 rounded-lg border border-red-800 bg-red-950 px-4 py-3 text-sm text-red-300">
          You don&apos;t have access to manage roles.
        </div>
      </div>
    );
  }

  return (
    <div>
      <h1 className="text-2xl font-bold text-white">Roles &amp; Permissions</h1>
      <p className="mt-1 text-sm text-gray-400">
        Custom organization roles and the backend-authoritative permission
        catalog. System roles cannot be edited or deleted.
      </p>

      <div className="mt-6 rounded-xl border border-gray-800 bg-gray-900 p-4">
        <div className="text-sm font-medium text-gray-300">Create custom role</div>
        <div className="mt-3 flex flex-wrap gap-2">
          <input
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            placeholder="Role name"
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
      ) : roles === null ? (
        <div className="mt-6 text-gray-400">Loading…</div>
      ) : roles.length === 0 ? (
        <div className="mt-6 rounded-xl border border-gray-800 bg-gray-900 p-8 text-center text-sm text-gray-500">
          No roles yet.
        </div>
      ) : (
        <div className="mt-6 overflow-x-auto rounded-xl border border-gray-800">
          <table className="w-full text-sm">
            <thead className="bg-gray-900 text-left text-xs text-gray-500">
              <tr>
                <th className="px-4 py-2">Name</th>
                <th className="px-4 py-2">Type</th>
                <th className="px-4 py-2">Permissions</th>
                <th className="px-4 py-2">Assignments</th>
                <th className="px-4 py-2">Actions</th>
              </tr>
            </thead>
            <tbody>
              {roles.map((r) => (
                <tr
                  key={r.id}
                  onClick={() => openDetail(r)}
                  className="cursor-pointer border-t border-gray-800 hover:bg-gray-900"
                >
                  <td className="px-4 py-2 text-gray-200">{r.name}</td>
                  <td className="px-4 py-2">
                    {r.is_system ? (
                      <span className="rounded bg-blue-950 px-2 py-0.5 text-xs text-blue-400">
                        System
                      </span>
                    ) : (
                      <span className="text-xs text-gray-500">Custom</span>
                    )}
                  </td>
                  <td className="px-4 py-2 text-gray-500">{r.permissions.length}</td>
                  <td className="px-4 py-2 text-gray-500">{r.assignment_count}</td>
                  <td className="px-4 py-2" onClick={(e) => e.stopPropagation()}>
                    <button
                      disabled={r.is_system}
                      title={r.is_system ? "System roles cannot be deleted" : "Delete role"}
                      onClick={() => remove(r)}
                      className="text-xs text-gray-500 hover:text-red-400 disabled:cursor-not-allowed disabled:opacity-40"
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
      {deleteError && <div className="mt-2 text-xs text-red-400">{deleteError}</div>}

      {selected && (
        <div className="mt-6 rounded-xl border border-gray-700 bg-gray-900 p-6">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-white">
              {selected.name}
              {selected.is_system && (
                <span className="ml-2 rounded bg-blue-950 px-2 py-0.5 text-xs text-blue-400">
                  System
                </span>
              )}
            </h2>
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
              disabled={selected.is_system}
              onChange={(e) => setEditName(e.target.value)}
              title={selected.is_system ? "System roles cannot be renamed" : undefined}
              className="rounded-lg border border-gray-700 bg-gray-800 px-3 py-1.5 text-sm text-white disabled:opacity-50"
            />
            <input
              value={editDescription}
              disabled={selected.is_system}
              onChange={(e) => setEditDescription(e.target.value)}
              title={selected.is_system ? "System roles cannot be edited" : undefined}
              className="flex-1 rounded-lg border border-gray-700 bg-gray-800 px-3 py-1.5 text-sm text-white disabled:opacity-50"
            />
            <button
              onClick={saveMetadata}
              disabled={saving || selected.is_system}
              title={selected.is_system ? "System roles cannot be edited" : undefined}
              className="rounded-lg bg-gray-700 px-4 py-1.5 text-sm font-medium text-white hover:bg-gray-600 disabled:opacity-50"
            >
              Save name
            </button>
          </div>

          <div className="mt-6">
            <div className="text-sm font-medium text-gray-300">Permissions</div>
            {catalog === null ? (
              <div className="mt-2 text-xs text-gray-500">Loading catalog…</div>
            ) : (
              <div className="mt-3 grid gap-4 sm:grid-cols-2">
                {Array.from(domains.entries()).map(([domain, items]) => (
                  <div key={domain} className="rounded-lg border border-gray-800 bg-gray-950 p-3">
                    <div className="text-xs font-semibold uppercase text-gray-500">{domain}</div>
                    <div className="mt-2 space-y-1.5">
                      {items.map((item) => (
                        <label
                          key={item.key}
                          title={item.description}
                          className="flex items-center gap-2 text-xs text-gray-300"
                        >
                          <input
                            type="checkbox"
                            checked={editPermissions.has(item.key)}
                            disabled={selected.is_system}
                            onChange={() => togglePermission(item.key)}
                          />
                          {item.key}
                        </label>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
            <button
              onClick={savePermissions}
              disabled={saving || selected.is_system}
              title={selected.is_system ? "System roles cannot be edited" : undefined}
              className="mt-4 rounded-lg bg-red-600 px-4 py-1.5 text-sm font-medium text-white hover:bg-red-700 disabled:opacity-50"
            >
              {saving ? "Saving…" : "Save permissions"}
            </button>
          </div>

          {detailError && <div className="mt-3 text-xs text-red-400">{detailError}</div>}
        </div>
      )}
    </div>
  );
}
