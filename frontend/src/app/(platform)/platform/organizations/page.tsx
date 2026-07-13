"use client";

import { useEffect, useState } from "react";
import {
  listPlatformOrganizations,
  reactivatePlatformOrganization,
  suspendPlatformOrganization,
  type PlatformOrganization,
} from "@/lib/platform";
import { useStepUp } from "../useStepUp";

export default function PlatformOrganizationsPage() {
  const [orgs, setOrgs] = useState<PlatformOrganization[] | null>(null);
  const [error, setError] = useState("");
  const [actionError, setActionError] = useState("");
  const [busyId, setBusyId] = useState<string | null>(null);
  const [confirmSuspendId, setConfirmSuspendId] = useState<string | null>(null);
  const [reason, setReason] = useState("");
  const { requestStepUp, stepUpModal } = useStepUp();

  function load() {
    listPlatformOrganizations()
      .then(setOrgs)
      .catch(() => setError("UNAVAILABLE — failed to load organizations."));
  }

  useEffect(load, []);

  async function suspend(orgId: string) {
    setBusyId(orgId);
    setActionError("");
    try {
      const token = await requestStepUp();
      if (!token) {
        setBusyId(null);
        return;
      }
      await suspendPlatformOrganization(orgId, reason, token);
      setConfirmSuspendId(null);
      setReason("");
      load();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Suspend failed";
      setActionError(msg);
    } finally {
      setBusyId(null);
    }
  }

  async function reactivate(orgId: string) {
    setBusyId(orgId);
    setActionError("");
    try {
      const token = await requestStepUp();
      if (!token) {
        setBusyId(null);
        return;
      }
      await reactivatePlatformOrganization(orgId, token);
      load();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Reactivate failed";
      setActionError(msg);
    } finally {
      setBusyId(null);
    }
  }

  return (
    <div>
      {stepUpModal}
      <h1 className="text-2xl font-bold text-white">Organizations</h1>
      <p className="mt-1 text-sm text-gray-400">
        Platform-wide organization list — governance metadata only. This is
        platform governance, not tenant impersonation: viewing or suspending an
        organization here does not log you into it or expose its security data
        (findings, evidence, credentials).
      </p>

      {actionError && (
        <div className="mt-4 rounded-lg border border-red-800 bg-red-950 px-4 py-3 text-sm text-red-300">
          {actionError}
        </div>
      )}

      {error ? (
        <div className="mt-6 rounded-lg border border-red-800 bg-red-950 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      ) : orgs === null ? (
        <div className="mt-6 text-gray-400">Loading…</div>
      ) : (
        <div className="mt-6 overflow-x-auto rounded-xl border border-gray-800">
          <table className="w-full text-sm">
            <thead className="bg-gray-900 text-left text-xs text-gray-500">
              <tr>
                <th className="px-4 py-2">Name</th>
                <th className="px-4 py-2">Slug</th>
                <th className="px-4 py-2">Status</th>
                <th className="px-4 py-2">Plan</th>
                <th className="px-4 py-2">Created</th>
                <th className="px-4 py-2"></th>
              </tr>
            </thead>
            <tbody>
              {orgs.map((o) => (
                <tr key={o.id} className="border-t border-gray-800">
                  <td className="px-4 py-2 text-gray-300">{o.name}</td>
                  <td className="px-4 py-2 font-mono text-gray-500">{o.slug}</td>
                  <td className="px-4 py-2">
                    <span
                      className={`rounded px-2 py-0.5 text-xs font-medium ${
                        o.status === "active"
                          ? "bg-green-950 text-green-400"
                          : o.status === "suspended"
                            ? "bg-red-950 text-red-400"
                            : "bg-gray-800 text-gray-500"
                      }`}
                    >
                      {o.status}
                    </span>
                  </td>
                  <td className="px-4 py-2 text-gray-500">{o.plan}</td>
                  <td className="px-4 py-2 text-gray-600">
                    {new Date(o.created_at).toLocaleDateString()}
                  </td>
                  <td className="px-4 py-2 text-right">
                    {o.status === "suspended" ? (
                      <button
                        onClick={() => reactivate(o.id)}
                        disabled={busyId === o.id}
                        className="text-xs text-green-400 hover:text-green-300 disabled:opacity-50"
                      >
                        {busyId === o.id ? "Reactivating…" : "Reactivate"}
                      </button>
                    ) : confirmSuspendId === o.id ? (
                      <span className="inline-flex items-center gap-2">
                        <input
                          value={reason}
                          onChange={(e) => setReason(e.target.value)}
                          placeholder="Reason"
                          className="w-28 rounded border border-gray-700 bg-gray-800 px-2 py-1 text-xs text-white"
                        />
                        <button
                          onClick={() => suspend(o.id)}
                          disabled={busyId === o.id}
                          className="rounded bg-red-600 px-2 py-1 text-xs font-medium text-white hover:bg-red-500 disabled:opacity-50"
                        >
                          {busyId === o.id ? "Suspending…" : "Confirm"}
                        </button>
                        <button
                          onClick={() => setConfirmSuspendId(null)}
                          className="text-xs text-gray-500 hover:text-white"
                        >
                          Cancel
                        </button>
                      </span>
                    ) : (
                      <button
                        onClick={() => setConfirmSuspendId(o.id)}
                        className="text-xs text-red-400 hover:text-red-300"
                      >
                        Suspend
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {orgs.length === 0 && (
            <div className="px-4 py-6 text-center text-sm text-gray-500">
              No organizations found.
            </div>
          )}
        </div>
      )}
    </div>
  );
}
