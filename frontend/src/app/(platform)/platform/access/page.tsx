"use client";

import { useEffect, useState } from "react";
import {
  PLATFORM_ROLES,
  grantPlatformAccess,
  isAssuranceRequiredError,
  listPlatformAccess,
  revokePlatformAccess,
  type PlatformAssignment,
} from "@/lib/platform";
import { useStepUp } from "../useStepUp";

export default function PlatformAccessPage() {
  const [assignments, setAssignments] = useState<PlatformAssignment[] | null>(null);
  const [error, setError] = useState("");
  const [revokingId, setRevokingId] = useState<string | null>(null);
  const [actionError, setActionError] = useState("");
  const [confirmId, setConfirmId] = useState<string | null>(null);
  const { requestStepUp, stepUpModal } = useStepUp();

  const [grantUserId, setGrantUserId] = useState("");
  const [grantRole, setGrantRole] = useState<string>(PLATFORM_ROLES[0]);
  const [granting, setGranting] = useState(false);

  function load() {
    listPlatformAccess()
      .then(setAssignments)
      .catch(() => setError("UNAVAILABLE — failed to load platform access assignments."));
  }

  useEffect(load, []);

  async function grant() {
    setGranting(true);
    setActionError("");
    try {
      const token = await requestStepUp();
      if (!token) {
        setGranting(false);
        return;
      }
      await grantPlatformAccess(grantUserId, grantRole, token);
      setGrantUserId("");
      load();
    } catch (err: unknown) {
      const msg = isAssuranceRequiredError(err)
        ? "Step-up verification failed or was not completed."
        : err instanceof Error
          ? err.message
          : "Grant failed";
      setActionError(msg);
    } finally {
      setGranting(false);
    }
  }

  async function revoke(assignmentId: string) {
    setRevokingId(assignmentId);
    setActionError("");
    try {
      const token = await requestStepUp();
      if (!token) {
        setRevokingId(null);
        return;
      }
      const updated = await revokePlatformAccess(assignmentId, token);
      setAssignments(
        (prev) => prev?.map((a) => (a.id === assignmentId ? updated : a)) ?? null
      );
      setConfirmId(null);
    } catch (err: unknown) {
      // Backend enforces last-Super-Admin protection — surface its
      // message truthfully rather than assuming success.
      const msg = err instanceof Error ? err.message : "Revoke failed";
      setActionError(msg);
    } finally {
      setRevokingId(null);
    }
  }

  return (
    <div>
      {stepUpModal}
      <h1 className="text-2xl font-bold text-white">Platform Access</h1>
      <p className="mt-1 text-sm text-gray-400">
        Active and revoked platform role assignments. Grant/revoke require MFA
        step-up. The final active PLATFORM_SUPER_ADMIN cannot be revoked — the
        backend enforces this even if this confirmation is bypassed.
      </p>

      <div className="mt-4 rounded-xl border border-gray-800 bg-gray-900 p-4">
        <div className="text-sm font-medium text-gray-300">Grant platform access</div>
        <div className="mt-2 flex flex-wrap gap-2">
          <input
            value={grantUserId}
            onChange={(e) => setGrantUserId(e.target.value)}
            placeholder="Target user ID"
            className="flex-1 min-w-[200px] rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white placeholder-gray-500"
          />
          <select
            value={grantRole}
            onChange={(e) => setGrantRole(e.target.value)}
            className="rounded-lg border border-gray-700 bg-gray-800 px-3 py-2 text-sm text-white"
          >
            {PLATFORM_ROLES.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </select>
          <button
            onClick={grant}
            disabled={granting || !grantUserId}
            className="rounded-lg bg-purple-600 px-4 py-2 text-sm font-medium text-white hover:bg-purple-500 disabled:opacity-50"
          >
            {granting ? "Granting…" : "Grant"}
          </button>
        </div>
      </div>

      {actionError && (
        <div className="mt-4 rounded-lg border border-red-800 bg-red-950 px-4 py-3 text-sm text-red-300">
          {actionError}
        </div>
      )}

      {error ? (
        <div className="mt-6 rounded-lg border border-red-800 bg-red-950 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      ) : assignments === null ? (
        <div className="mt-6 text-gray-400">Loading…</div>
      ) : (
        <div className="mt-6 space-y-2">
          {assignments.map((a) => (
            <div
              key={a.id}
              className="rounded-lg border border-gray-800 bg-gray-900 px-4 py-3"
            >
              <div className="flex items-center justify-between">
                <div>
                  <span className="font-mono text-sm text-purple-300">{a.role}</span>
                  <span className="ml-2 text-xs text-gray-600">
                    user={a.user_id.slice(0, 10)}…
                  </span>
                </div>
                <div className="flex items-center gap-3">
                  <span
                    className={`text-xs font-medium ${
                      a.status === "active" ? "text-green-400" : "text-gray-500"
                    }`}
                  >
                    {a.status}
                  </span>
                  {a.status === "active" &&
                    (confirmId === a.id ? (
                      <span className="inline-flex items-center gap-2">
                        <span className="text-xs text-yellow-400">Revoke?</span>
                        <button
                          onClick={() => revoke(a.id)}
                          disabled={revokingId === a.id}
                          className="rounded bg-red-600 px-2 py-1 text-xs font-medium text-white hover:bg-red-500 disabled:opacity-50"
                        >
                          {revokingId === a.id ? "Revoking…" : "Confirm"}
                        </button>
                        <button
                          onClick={() => setConfirmId(null)}
                          className="text-xs text-gray-500 hover:text-white"
                        >
                          Cancel
                        </button>
                      </span>
                    ) : (
                      <button
                        onClick={() => setConfirmId(a.id)}
                        className="text-xs text-red-400 hover:text-red-300"
                      >
                        Revoke
                      </button>
                    ))}
                </div>
              </div>
              <div className="mt-1 text-xs text-gray-600">
                Granted by {a.granted_by.slice(0, 10)}… at{" "}
                {new Date(a.granted_at).toLocaleString()}
                {a.revoked_at && (
                  <>
                    {" "}
                    · Revoked by {a.revoked_by?.slice(0, 10)}… at{" "}
                    {new Date(a.revoked_at).toLocaleString()}
                  </>
                )}
              </div>
            </div>
          ))}
          {assignments.length === 0 && (
            <div className="rounded-xl border border-gray-800 bg-gray-900 px-4 py-6 text-center text-sm text-gray-500">
              No platform access assignments yet.
            </div>
          )}
        </div>
      )}
    </div>
  );
}
