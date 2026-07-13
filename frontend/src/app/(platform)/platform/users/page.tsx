"use client";

import { useEffect, useState } from "react";
import {
  listPlatformUsers,
  reactivatePlatformUser,
  suspendPlatformUser,
  type PlatformUser,
} from "@/lib/platform";
import { useStepUp } from "../useStepUp";

export default function PlatformUsersPage() {
  const [users, setUsers] = useState<PlatformUser[] | null>(null);
  const [error, setError] = useState("");
  const [actionError, setActionError] = useState("");
  const [busyId, setBusyId] = useState<string | null>(null);
  const [confirmSuspendId, setConfirmSuspendId] = useState<string | null>(null);
  const [reason, setReason] = useState("");
  const { requestStepUp, stepUpModal } = useStepUp();

  function load() {
    listPlatformUsers()
      .then(setUsers)
      .catch(() => setError("UNAVAILABLE — failed to load platform users."));
  }

  useEffect(load, []);

  async function suspend(userId: string) {
    setBusyId(userId);
    setActionError("");
    try {
      const token = await requestStepUp();
      if (!token) {
        setBusyId(null);
        return;
      }
      const updated = await suspendPlatformUser(userId, reason, token);
      setUsers((prev) => prev?.map((u) => (u.id === userId ? updated : u)) ?? null);
      setConfirmSuspendId(null);
      setReason("");
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Suspend failed";
      setActionError(msg);
    } finally {
      setBusyId(null);
    }
  }

  async function reactivate(userId: string) {
    setBusyId(userId);
    setActionError("");
    try {
      const token = await requestStepUp();
      if (!token) {
        setBusyId(null);
        return;
      }
      const updated = await reactivatePlatformUser(userId, token);
      setUsers((prev) => prev?.map((u) => (u.id === userId ? updated : u)) ?? null);
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
      <h1 className="text-2xl font-bold text-white">Platform Users</h1>
      <p className="mt-1 text-sm text-gray-400">
        All registered users across the platform. Suspend/reactivate require
        MFA step-up. Suspending immediately denies effective access, even for
        an already-issued, unexpired session token.
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
      ) : users === null ? (
        <div className="mt-6 text-gray-400">Loading…</div>
      ) : (
        <div className="mt-6 overflow-x-auto rounded-xl border border-gray-800">
          <table className="w-full text-sm">
            <thead className="bg-gray-900 text-left text-xs text-gray-500">
              <tr>
                <th className="px-4 py-2">Email</th>
                <th className="px-4 py-2">Display Name</th>
                <th className="px-4 py-2">Status</th>
                <th className="px-4 py-2">Registered</th>
                <th className="px-4 py-2"></th>
              </tr>
            </thead>
            <tbody>
              {users.map((u) => (
                <tr key={u.id} className="border-t border-gray-800">
                  <td className="px-4 py-2 text-gray-300">{u.email}</td>
                  <td className="px-4 py-2 text-gray-400">{u.display_name}</td>
                  <td className="px-4 py-2">
                    <span
                      className={`rounded px-2 py-0.5 text-xs font-medium ${
                        u.status === "active"
                          ? "bg-green-950 text-green-400"
                          : u.status === "suspended"
                            ? "bg-red-950 text-red-400"
                            : "bg-gray-800 text-gray-500"
                      }`}
                    >
                      {u.status}
                    </span>
                  </td>
                  <td className="px-4 py-2 text-gray-600">
                    {new Date(u.created_at).toLocaleDateString()}
                  </td>
                  <td className="px-4 py-2 text-right">
                    {u.status === "suspended" ? (
                      <button
                        onClick={() => reactivate(u.id)}
                        disabled={busyId === u.id}
                        className="text-xs text-green-400 hover:text-green-300 disabled:opacity-50"
                      >
                        {busyId === u.id ? "Reactivating…" : "Reactivate"}
                      </button>
                    ) : confirmSuspendId === u.id ? (
                      <span className="inline-flex items-center gap-2">
                        <input
                          value={reason}
                          onChange={(e) => setReason(e.target.value)}
                          placeholder="Reason"
                          className="w-28 rounded border border-gray-700 bg-gray-800 px-2 py-1 text-xs text-white"
                        />
                        <button
                          onClick={() => suspend(u.id)}
                          disabled={busyId === u.id}
                          className="rounded bg-red-600 px-2 py-1 text-xs font-medium text-white hover:bg-red-500 disabled:opacity-50"
                        >
                          {busyId === u.id ? "Suspending…" : "Confirm"}
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
                        onClick={() => setConfirmSuspendId(u.id)}
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
          {users.length === 0 && (
            <div className="px-4 py-6 text-center text-sm text-gray-500">No users found.</div>
          )}
        </div>
      )}
    </div>
  );
}
