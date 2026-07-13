"use client";

import { useEffect, useState } from "react";
import { ApiError } from "@/lib/api";
import { getMe } from "@/lib/auth";
import { getEffectiveAccess, listOrganizationMembers, type EffectiveAccess, type OrganizationMember } from "@/lib/rbac";

export default function AccessExplorerPage() {
  const [members, setMembers] = useState<OrganizationMember[]>([]);
  const [selfUserId, setSelfUserId] = useState<string | null>(null);
  const [userId, setUserId] = useState("");
  const [access, setAccess] = useState<EffectiveAccess | null>(null);
  const [error, setError] = useState("");
  const [forbidden, setForbidden] = useState(false);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    getMe()
      .then((me) => {
        setSelfUserId(me.user_id);
        setUserId(me.user_id);
      })
      .catch(() => undefined);
    listOrganizationMembers().then(setMembers).catch(() => setMembers([]));
  }, []);

  useEffect(() => {
    if (!userId) return;
    setLoading(true);
    setError("");
    setForbidden(false);
    getEffectiveAccess(userId)
      .then(setAccess)
      .catch((err) => {
        setAccess(null);
        if (err instanceof ApiError && err.status === 403) {
          setForbidden(true);
        } else {
          setError("UNAVAILABLE — failed to load effective access.");
        }
      })
      .finally(() => setLoading(false));
  }, [userId]);

  return (
    <div>
      <h1 className="text-2xl font-bold text-white">Access Explorer</h1>
      <p className="mt-1 text-sm text-gray-400">
        Explains exactly why a user has the access they have — membership
        role, direct roles, group-derived roles, and the resulting union of
        effective permissions.
      </p>

      <div className="mt-4 flex flex-wrap gap-2">
        <select
          value={userId}
          onChange={(e) => setUserId(e.target.value)}
          className="rounded-lg border border-gray-700 bg-gray-800 px-3 py-1.5 text-sm text-white"
        >
          {selfUserId && (
            <option value={selfUserId}>{selfUserId} (me)</option>
          )}
          {members
            .filter((m) => m.user_id !== selfUserId)
            .map((m) => (
              <option key={m.user_id} value={m.user_id}>
                {m.user_id} ({m.role})
              </option>
            ))}
        </select>
        <input
          value={userId}
          onChange={(e) => setUserId(e.target.value)}
          placeholder="Or enter a user id"
          className="flex-1 rounded-lg border border-gray-700 bg-gray-800 px-3 py-1.5 text-sm text-white"
        />
      </div>

      {forbidden ? (
        <div className="mt-6 rounded-lg border border-red-800 bg-red-950 px-4 py-3 text-sm text-red-300">
          You don&apos;t have access to view this user&apos;s effective access.
        </div>
      ) : error ? (
        <div className="mt-6 rounded-lg border border-red-800 bg-red-950 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      ) : loading || access === null ? (
        <div className="mt-6 text-gray-400">Loading…</div>
      ) : (
        <div className="mt-6 space-y-6">
          <div className="rounded-xl border border-red-800 bg-red-950/30 p-4">
            <div className="text-xs uppercase text-red-400">Effective (union) permissions</div>
            <div className="mt-2 flex flex-wrap gap-1.5">
              {access.effective_permissions.length === 0 ? (
                <span className="text-xs text-gray-500">None.</span>
              ) : (
                access.effective_permissions.map((p) => (
                  <span key={p} className="rounded bg-red-900/50 px-2 py-0.5 text-xs text-red-200">
                    {p}
                  </span>
                ))
              )}
            </div>
          </div>

          <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
            <div className="text-xs uppercase text-gray-500">Membership grant</div>
            <div className="mt-2 text-sm text-gray-200">Role: {access.membership_role}</div>
            <div className="mt-2 flex flex-wrap gap-1.5">
              {access.membership_permissions.map((p) => (
                <span key={p} className="rounded bg-gray-800 px-2 py-0.5 text-xs text-gray-400">
                  {p}
                </span>
              ))}
            </div>
          </div>

          <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
            <div className="text-xs uppercase text-gray-500">Direct role permissions</div>
            {access.direct_role_names.length === 0 ? (
              <div className="mt-2 text-xs text-gray-600">No direct roles assigned.</div>
            ) : (
              <div className="mt-2 flex flex-wrap gap-1.5">
                {access.direct_role_names.map((name) => (
                  <span key={name} className="rounded bg-blue-950 px-2 py-0.5 text-xs text-blue-300">
                    {name}
                  </span>
                ))}
              </div>
            )}
            <div className="mt-3 flex flex-wrap gap-1.5">
              {access.direct_role_permissions.map((p) => (
                <span key={p} className="rounded bg-gray-800 px-2 py-0.5 text-xs text-gray-400">
                  {p}
                </span>
              ))}
            </div>
          </div>

          <div className="rounded-xl border border-gray-800 bg-gray-900 p-4">
            <div className="text-xs uppercase text-gray-500">Group-derived permissions</div>
            {access.groups.length === 0 ? (
              <div className="mt-2 text-xs text-gray-600">Not a member of any group.</div>
            ) : (
              <div className="mt-2 space-y-3">
                {access.groups.map((g, idx) => (
                  <div key={(g.id as string) ?? idx} className="rounded-lg border border-gray-800 bg-gray-950 p-3">
                    <div className="text-sm text-gray-200">
                      {(g.name as string) ?? (g.id as string) ?? `Group ${idx + 1}`}
                    </div>
                    <pre className="mt-1 overflow-x-auto text-xs text-gray-500">
                      {JSON.stringify(g, null, 2)}
                    </pre>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
