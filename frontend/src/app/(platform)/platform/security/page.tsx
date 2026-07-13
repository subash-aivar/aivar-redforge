"use client";

import { useEffect, useState } from "react";
import {
  beginMfaEnrollment,
  getMfaStatus,
  revokeMfa,
  verifyMfaEnrollment,
  type MFAEnrollBegin,
  type MFAStatus,
} from "@/lib/platform";

export default function PlatformSecurityPage() {
  const [status, setStatus] = useState<MFAStatus | null>(null);
  const [error, setError] = useState("");

  const [enrollment, setEnrollment] = useState<MFAEnrollBegin | null>(null);
  const [code, setCode] = useState("");
  const [verifyError, setVerifyError] = useState("");
  const [busy, setBusy] = useState(false);
  const [revokeConfirm, setRevokeConfirm] = useState(false);

  function load() {
    getMfaStatus()
      .then(setStatus)
      .catch(() => setError("UNAVAILABLE — failed to load MFA status."));
  }

  useEffect(load, []);

  async function startEnrollment() {
    setBusy(true);
    setVerifyError("");
    try {
      const result = await beginMfaEnrollment();
      setEnrollment(result);
      setCode("");
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Failed to begin enrollment";
      setVerifyError(msg);
    } finally {
      setBusy(false);
    }
  }

  async function confirmEnrollment() {
    if (!enrollment) return;
    setBusy(true);
    setVerifyError("");
    try {
      await verifyMfaEnrollment(enrollment.enrollment_id, code);
      setEnrollment(null);
      setCode("");
      load();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Verification failed";
      setVerifyError(msg);
    } finally {
      setBusy(false);
    }
  }

  function cancelEnrollment() {
    // Discards the enrollment state client-side. The pending factor
    // itself is superseded server-side the next time enrollment begins
    // (MFAService.begin_enrollment replaces any existing pending row) —
    // this page never persists the secret/URI beyond this component's
    // in-memory state, and clears both here.
    setEnrollment(null);
    setCode("");
    setVerifyError("");
  }

  async function doRevoke() {
    setBusy(true);
    try {
      await revokeMfa();
      setRevokeConfirm(false);
      load();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Revoke failed";
      setVerifyError(msg);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <h1 className="text-2xl font-bold text-white">Security — Multi-Factor Authentication</h1>
      <p className="mt-1 text-sm text-gray-400">
        Platform Super Admin actions (grant/revoke access, suspend/reactivate
        users and organizations) require a current MFA step-up verification,
        independent of this enrollment status.
      </p>

      {error ? (
        <div className="mt-6 rounded-lg border border-red-800 bg-red-950 px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      ) : status === null ? (
        <div className="mt-6 text-gray-400">Loading…</div>
      ) : (
        <div className="mt-6 rounded-xl border border-gray-800 bg-gray-900 p-6">
          <div className="flex items-center justify-between">
            <div>
              <div className="text-sm font-medium text-gray-300">TOTP Authenticator</div>
              <div className="mt-1 text-xs text-gray-500">
                {status.active
                  ? "An active factor is enrolled."
                  : status.pending_enrollment
                    ? "An enrollment is in progress — complete verification below."
                    : "No factor enrolled yet."}
              </div>
            </div>
            <span
              className={`rounded px-2 py-1 text-xs font-medium ${
                status.active
                  ? "bg-green-950 text-green-400"
                  : "bg-gray-800 text-gray-500"
              }`}
            >
              {status.active ? "ACTIVE" : status.pending_enrollment ? "PENDING" : "NOT ENROLLED"}
            </span>
          </div>

          {!status.active && !enrollment && (
            <button
              onClick={startEnrollment}
              disabled={busy}
              className="mt-4 rounded-lg bg-purple-600 px-4 py-2 text-sm font-medium text-white hover:bg-purple-500 disabled:opacity-50"
            >
              {busy ? "Starting…" : "Begin enrollment"}
            </button>
          )}

          {enrollment && (
            <div className="mt-4 rounded-lg border border-purple-800 bg-purple-950/30 p-4">
              <p className="text-sm text-purple-300">
                Scan this with your authenticator app, or enter the secret manually.
                This secret is shown only once — it will not be shown again after
                verification.
              </p>
              <div className="mt-3 rounded-lg bg-gray-950 p-3 font-mono text-xs text-gray-300 break-all">
                {enrollment.provisioning_uri}
              </div>
              <div className="mt-2 rounded-lg bg-gray-950 p-3 font-mono text-sm text-white">
                {enrollment.secret}
              </div>
              <input
                value={code}
                onChange={(e) => setCode(e.target.value)}
                placeholder="Enter 6-digit code to verify"
                className="mt-3 w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-2 text-white placeholder-gray-500 focus:border-purple-500 focus:outline-none"
              />
              {verifyError && <div className="mt-2 text-sm text-red-400">{verifyError}</div>}
              <div className="mt-3 flex gap-3">
                <button
                  onClick={confirmEnrollment}
                  disabled={busy || code.length < 6}
                  className="rounded-lg bg-purple-600 px-4 py-2 text-sm font-medium text-white hover:bg-purple-500 disabled:opacity-50"
                >
                  {busy ? "Verifying…" : "Verify and activate"}
                </button>
                <button
                  onClick={cancelEnrollment}
                  className="rounded-lg border border-gray-700 px-4 py-2 text-sm text-gray-400 hover:text-white"
                >
                  Cancel
                </button>
              </div>
            </div>
          )}

          {status.active && (
            <div className="mt-4">
              {revokeConfirm ? (
                <div className="flex items-center gap-3">
                  <span className="text-sm text-yellow-400">
                    Revoke your MFA factor? You will need to re-enroll to use
                    step-up-gated actions again.
                  </span>
                  <button
                    onClick={doRevoke}
                    disabled={busy}
                    className="rounded-lg bg-red-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-red-500 disabled:opacity-50"
                  >
                    {busy ? "Revoking…" : "Confirm revoke"}
                  </button>
                  <button
                    onClick={() => setRevokeConfirm(false)}
                    className="text-xs text-gray-500 hover:text-white"
                  >
                    Cancel
                  </button>
                </div>
              ) : (
                <button
                  onClick={() => setRevokeConfirm(true)}
                  className="text-sm text-red-400 hover:text-red-300"
                >
                  Revoke MFA factor
                </button>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
