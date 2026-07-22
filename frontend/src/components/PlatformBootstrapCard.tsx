"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { bootstrapSuperAdmin, getBootstrapStatus } from "@/lib/platform";
import { getMe, type UserProfile } from "@/lib/auth";

/**
 * Enterprise bootstrap wizard for the first Platform Super Administrator.
 *
 * The backend never discloses the *configured* bootstrap principal email
 * (redforge/api/v1/platform.py has no endpoint that returns it — by
 * design, so an unrelated authenticated user can't probe who the
 * intended admin is). This card only shows what the API actually
 * returns: whether bootstrap is available, and the caller's own
 * authenticated identity — never a fabricated "configured email" value.
 *
 * Renders nothing once bootstrap is unavailable and not just-completed,
 * so it's safe to mount unconditionally on the dashboard.
 */
export function PlatformBootstrapCard() {
  const router = useRouter();
  const [status, setStatus] = useState<"checking" | "available" | "unavailable">(
    "checking"
  );
  const [me, setMe] = useState<UserProfile | null>(null);
  const [confirming, setConfirming] = useState(false);
  const [bootstrapping, setBootstrapping] = useState(false);
  const [error, setError] = useState("");
  const [done, setDone] = useState(false);

  useEffect(() => {
    getBootstrapStatus()
      .then((s) => setStatus(s.available ? "available" : "unavailable"))
      .catch(() => setStatus("unavailable"));
    getMe()
      .then(setMe)
      .catch(() => {});
  }, []);

  async function handleInitialize() {
    setBootstrapping(true);
    setError("");
    try {
      await bootstrapSuperAdmin();
      setDone(true);
      setConfirming(false);
      window.setTimeout(() => router.push("/platform/overview"), 1600);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Bootstrap failed");
    } finally {
      setBootstrapping(false);
    }
  }

  if (status === "checking") return null;
  if (status === "unavailable" && !done) return null;

  return (
    <div className="relative overflow-hidden rounded-2xl border border-purple-800/50 bg-gradient-to-br from-purple-950/60 via-gray-900/80 to-gray-950/80 p-6 shadow-xl shadow-purple-950/20 backdrop-blur-xl animate-fade-in-up">
      <div
        aria-hidden="true"
        className="absolute -right-10 -top-10 h-40 w-40 rounded-full bg-purple-600/10 blur-3xl animate-pulse-glow"
      />

      {done ? (
        <div className="relative flex flex-col items-center py-4 text-center">
          <SuccessRing />
          <h3 className="mt-4 text-lg font-semibold text-white">
            Platform Super Administrator Initialized
          </h3>
          <p className="mt-1 max-w-sm text-sm text-purple-200/80">
            Redirecting to the Platform Control Plane…
          </p>
        </div>
      ) : (
        <div className="relative">
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-widest text-purple-300">
            <ShieldIcon />
            Platform Initialization
          </div>
          <h3 className="mt-2 text-lg font-semibold text-white">
            No Platform Super Administrator exists yet
          </h3>
          <p className="mt-1 text-sm text-gray-400">
            This server is configured to allow a one-time bootstrap. Once
            initialized, this action cannot be repeated.
          </p>

          <dl className="mt-4 grid grid-cols-1 gap-2.5 sm:grid-cols-2">
            <ChecklistRow label="Bootstrap enabled" ok />
            <ChecklistRow label="Bootstrap available" ok />
            <InfoRow label="Configured principal">
              <span className="text-gray-500">
                Not disclosed by the server (security by design)
              </span>
            </InfoRow>
            <InfoRow label="Authenticated as">
              {me ? (
                <span className="font-mono text-gray-300">{me.email}</span>
              ) : (
                <span className="text-gray-600">Loading…</span>
              )}
            </InfoRow>
          </dl>

          {error && (
            <div
              role="alert"
              className="mt-4 rounded-lg border border-red-900/60 bg-red-950/50 px-3 py-2 text-xs text-red-300"
            >
              {error}
            </div>
          )}

          {!confirming ? (
            <button
              type="button"
              onClick={() => setConfirming(true)}
              className="mt-5 rounded-lg bg-purple-600 px-4 py-2 text-sm font-semibold text-white transition hover:bg-purple-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-purple-500"
            >
              Initialize Platform Super Administrator
            </button>
          ) : (
            <div className="mt-5 rounded-xl border border-purple-800/60 bg-gray-950/60 p-4 animate-fade-in-up">
              <p className="text-sm text-gray-200">
                Grant <span className="font-mono text-purple-300">{me?.email}</span>{" "}
                permanent Platform Super Administrator access?
              </p>
              <p className="mt-1 text-xs text-gray-500">
                This is a one-time, irreversible initialization. It can only
                be undone by another Super Administrator revoking access
                afterward.
              </p>
              <div className="mt-3 flex gap-2">
                <button
                  type="button"
                  onClick={handleInitialize}
                  disabled={bootstrapping}
                  className="inline-flex items-center gap-2 rounded-lg bg-purple-600 px-3.5 py-1.5 text-xs font-semibold text-white transition hover:bg-purple-500 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {bootstrapping && <MiniSpinner />}
                  {bootstrapping ? "Initializing…" : "Confirm & Initialize"}
                </button>
                <button
                  type="button"
                  onClick={() => setConfirming(false)}
                  disabled={bootstrapping}
                  className="rounded-lg border border-gray-700 px-3.5 py-1.5 text-xs font-medium text-gray-400 hover:text-gray-200 disabled:opacity-60"
                >
                  Cancel
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function ChecklistRow({ label, ok }: { label: string; ok: boolean }) {
  return (
    <div className="flex items-center gap-2 rounded-lg border border-gray-800/80 bg-gray-950/40 px-3 py-2 text-xs">
      <span
        className={`flex h-4 w-4 items-center justify-center rounded-full ${
          ok ? "bg-emerald-500/20 text-emerald-400" : "bg-gray-800 text-gray-500"
        }`}
      >
        {ok ? "✓" : "–"}
      </span>
      <span className="text-gray-300">{label}</span>
    </div>
  );
}

function InfoRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-gray-800/80 bg-gray-950/40 px-3 py-2 text-xs">
      <dt className="text-gray-500">{label}</dt>
      <dd className="mt-0.5">{children}</dd>
    </div>
  );
}

function ShieldIcon() {
  return (
    <svg viewBox="0 0 24 24" className="h-3.5 w-3.5" fill="none" aria-hidden="true">
      <path
        d="M12 2 3 6v6c0 5 3.8 8.7 9 10 5.2-1.3 9-5 9-10V6l-9-4Z"
        stroke="currentColor"
        strokeWidth="1.8"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function SuccessRing() {
  return (
    <div className="animate-ring-pop flex h-14 w-14 items-center justify-center rounded-full border-2 border-emerald-500 bg-emerald-500/10">
      <svg viewBox="0 0 24 24" className="h-7 w-7 text-emerald-400" fill="none" aria-hidden="true">
        <path
          d="M5 12.5 10 17l9-10"
          stroke="currentColor"
          strokeWidth="2.5"
          strokeLinecap="round"
          strokeLinejoin="round"
          className="animate-check-draw"
        />
      </svg>
    </div>
  );
}

function MiniSpinner() {
  return (
    <svg className="h-3.5 w-3.5 animate-spin" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="3" opacity="0.25" />
      <path d="M21 12a9 9 0 0 0-9-9" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
    </svg>
  );
}
