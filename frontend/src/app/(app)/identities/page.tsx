"use client";

import { useEffect, useState } from "react";
import {
  getIdentity,
  getIdentityMemberships,
  listGroups,
  listIdentities,
  type DirectoryGroup,
  type DirectoryIdentity,
  type Membership,
} from "@/lib/directorySecurity";

const KNOWN_CATEGORIES = new Set(["human", "service"]);
const KNOWN_PRIVILEGE = new Set(["standard", "privileged"]);

function canonical(value: string, known: Set<string>): string {
  return known.has(value) ? value : "UNKNOWN";
}

export default function IdentitiesPage() {
  const [identities, setIdentities] = useState<DirectoryIdentity[] | null>(null);
  const [error, setError] = useState("");
  const [categoryFilter, setCategoryFilter] = useState("");
  const [privilegeFilter, setPrivilegeFilter] = useState("");

  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<DirectoryIdentity | null>(null);
  const [memberships, setMemberships] = useState<Membership[] | null>(null);
  const [groups, setGroups] = useState<DirectoryGroup[]>([]);
  const [detailError, setDetailError] = useState("");

  function load() {
    listIdentities(categoryFilter || undefined, privilegeFilter || undefined)
      .then(setIdentities)
      .catch(() => setError("UNAVAILABLE — failed to load identities."));
  }

  useEffect(load, [categoryFilter, privilegeFilter]);
  useEffect(() => {
    listGroups().then(setGroups).catch(() => setGroups([]));
  }, []);

  async function openDetail(id: string) {
    setSelectedId(id);
    setDetail(null);
    setMemberships(null);
    setDetailError("");
    try {
      const [d, m] = await Promise.all([getIdentity(id), getIdentityMemberships(id)]);
      setDetail(d);
      setMemberships(m);
    } catch {
      setDetailError("UNAVAILABLE — failed to load identity detail.");
    }
  }

  const groupsById = Object.fromEntries(groups.map((g) => [g.id, g]));

  return (
    <div>
      <h1 className="text-2xl font-bold text-white">Identities</h1>
      <p className="mt-1 text-sm text-gray-400">
        Enterprise directory identities discovered via a read-only directory
        connector — distinct from RedForge application users.
      </p>

      <div className="mt-4 flex gap-2">
        <select
          value={categoryFilter}
          onChange={(e) => setCategoryFilter(e.target.value)}
          className="rounded-lg border border-gray-700 bg-gray-800 px-3 py-1.5 text-sm text-white"
        >
          <option value="">All categories</option>
          <option value="human">Human</option>
          <option value="service">Service</option>
        </select>
        <select
          value={privilegeFilter}
          onChange={(e) => setPrivilegeFilter(e.target.value)}
          className="rounded-lg border border-gray-700 bg-gray-800 px-3 py-1.5 text-sm text-white"
        >
          <option value="">All privilege levels</option>
          <option value="standard">Standard</option>
          <option value="privileged">Privileged</option>
        </select>
      </div>

      {error ? (
        <div className="mt-6 rounded-lg border border-red-800 bg-red-950 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      ) : identities === null ? (
        <div className="mt-6 text-gray-400">Loading…</div>
      ) : identities.length === 0 ? (
        <div className="mt-6 rounded-xl border border-gray-800 bg-gray-900 p-8 text-center text-sm text-gray-500">
          No identities yet. Register a directory connector and run discovery.
        </div>
      ) : (
        <div className="mt-6 overflow-x-auto rounded-xl border border-gray-800">
          <table className="w-full text-sm">
            <thead className="bg-gray-900 text-left text-xs text-gray-500">
              <tr>
                <th className="px-4 py-2">Display Name</th>
                <th className="px-4 py-2">Category</th>
                <th className="px-4 py-2">Source</th>
                <th className="px-4 py-2">Enabled</th>
                <th className="px-4 py-2">Privilege</th>
                <th className="px-4 py-2">Last Observed</th>
              </tr>
            </thead>
            <tbody>
              {identities.map((i) => (
                <tr
                  key={i.id}
                  onClick={() => openDetail(i.id)}
                  className="cursor-pointer border-t border-gray-800 hover:bg-gray-900"
                >
                  <td className="px-4 py-2 text-gray-200">{i.display_name}</td>
                  <td className="px-4 py-2 font-mono text-xs text-blue-400">
                    {canonical(i.principal_category, KNOWN_CATEGORIES)}
                  </td>
                  <td className="px-4 py-2 text-gray-500">directory</td>
                  <td className="px-4 py-2">
                    <span
                      className={`rounded px-2 py-0.5 text-xs ${
                        i.source_enabled
                          ? "bg-green-950 text-green-400"
                          : "bg-gray-800 text-gray-500"
                      }`}
                    >
                      {i.source_enabled ? "enabled" : "disabled"}
                    </span>
                  </td>
                  <td className="px-4 py-2">
                    <span
                      className={`rounded px-2 py-0.5 text-xs ${
                        i.privilege_classification === "privileged"
                          ? "bg-amber-950 text-amber-400"
                          : "bg-gray-800 text-gray-500"
                      }`}
                    >
                      {canonical(i.privilege_classification, KNOWN_PRIVILEGE)}
                    </span>
                  </td>
                  <td className="px-4 py-2 text-gray-600">
                    {new Date(i.last_observed_at).toLocaleString()}
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
            <h2 className="text-lg font-semibold text-white">Identity Detail</h2>
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
              <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                <Stat label="Category" value={canonical(detail.principal_category, KNOWN_CATEGORIES)} />
                <Stat label="Enabled" value={detail.source_enabled ? "yes" : "no"} />
                <Stat
                  label="Privilege"
                  value={canonical(detail.privilege_classification, KNOWN_PRIVILEGE)}
                />
                <Stat label="Lifecycle" value={detail.observation_lifecycle} />
              </div>
              {detail.privilege_reason && (
                <div className="mt-2 text-xs text-gray-500">
                  Privilege reason: {detail.privilege_reason}
                </div>
              )}
              <div className="mt-4">
                <div className="mb-2 text-sm font-medium text-gray-400">
                  Direct Group Memberships ({memberships?.length ?? 0})
                </div>
                {memberships === null ? (
                  <div className="text-xs text-gray-500">Loading…</div>
                ) : memberships.length === 0 ? (
                  <div className="text-xs text-gray-600">No group memberships recorded.</div>
                ) : (
                  <div className="space-y-2">
                    {memberships.map((m) => (
                      <div
                        key={m.id}
                        className="rounded-lg border border-gray-800 bg-gray-950 px-3 py-2 text-xs text-gray-300"
                      >
                        {groupsById[m.group_id]?.display_name ?? m.group_id}
                        {groupsById[m.group_id]?.is_recognized_privileged && (
                          <span className="ml-2 rounded bg-amber-950 px-1.5 py-0.5 text-amber-400">
                            privileged group
                          </span>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-gray-800 bg-gray-950 px-3 py-2">
      <div className="text-sm font-bold text-white truncate">{value}</div>
      <div className="text-xs text-gray-500">{label}</div>
    </div>
  );
}
