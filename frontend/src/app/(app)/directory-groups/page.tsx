"use client";

import { useEffect, useState } from "react";
import {
  getGroup,
  getGroupMembers,
  listGroups,
  type DirectoryGroup,
  type Membership,
} from "@/lib/directorySecurity";

export default function DirectoryGroupsPage() {
  const [groups, setGroups] = useState<DirectoryGroup[] | null>(null);
  const [error, setError] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<DirectoryGroup | null>(null);
  const [members, setMembers] = useState<Membership[] | null>(null);
  const [detailError, setDetailError] = useState("");

  useEffect(() => {
    listGroups()
      .then(setGroups)
      .catch(() => setError("UNAVAILABLE — failed to load directory groups."));
  }, []);

  async function openDetail(id: string) {
    setSelectedId(id);
    setDetail(null);
    setMembers(null);
    setDetailError("");
    try {
      const [d, m] = await Promise.all([getGroup(id), getGroupMembers(id)]);
      setDetail(d);
      setMembers(m);
    } catch {
      setDetailError("UNAVAILABLE — failed to load group detail.");
    }
  }

  return (
    <div>
      <h1 className="text-2xl font-bold text-white">Directory Groups</h1>
      <p className="mt-1 text-sm text-gray-400">
        Groups observed via a read-only directory connector. Direct membership
        only — nested/effective group traversal is not implemented yet.
      </p>

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
                <th className="px-4 py-2">Privilege</th>
                <th className="px-4 py-2">Last Observed</th>
              </tr>
            </thead>
            <tbody>
              {groups.map((g) => (
                <tr
                  key={g.id}
                  onClick={() => openDetail(g.id)}
                  className="cursor-pointer border-t border-gray-800 hover:bg-gray-900"
                >
                  <td className="px-4 py-2 text-gray-200">{g.display_name}</td>
                  <td className="px-4 py-2">
                    {g.is_recognized_privileged ? (
                      <span className="rounded bg-amber-950 px-2 py-0.5 text-xs text-amber-400">
                        recognized privileged
                      </span>
                    ) : (
                      <span className="text-xs text-gray-500">standard</span>
                    )}
                  </td>
                  <td className="px-4 py-2 text-gray-600">
                    {new Date(g.last_observed_at).toLocaleString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {selectedId && (
        <div className="mt-6 rounded-xl border border-gray-700 bg-gray-900 p-6">
          <div className="flex items-center justify-between">
            <h2 className="text-lg font-semibold text-white">Group Detail</h2>
            <button
              onClick={() => setSelectedId(null)}
              className="text-xs text-gray-500 hover:text-gray-300"
            >
              Close
            </button>
          </div>
          {detailError ? (
            <div className="mt-3 text-sm text-red-400">{detailError}</div>
          ) : detail === null ? (
            <div className="mt-3 text-sm text-gray-500">Loading…</div>
          ) : (
            <div className="mt-3">
              <div className="text-xs text-gray-500">
                Direct members ({members?.length ?? 0})
              </div>
              {members === null ? (
                <div className="mt-2 text-xs text-gray-500">Loading…</div>
              ) : members.length === 0 ? (
                <div className="mt-2 text-xs text-gray-600">No direct members.</div>
              ) : (
                <div className="mt-2 space-y-1">
                  {members.map((m) => (
                    <div key={m.id} className="font-mono text-xs text-gray-400">
                      {m.identity_id}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
