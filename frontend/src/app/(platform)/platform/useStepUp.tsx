"use client";

import { useCallback, useRef, useState } from "react";
import { stepUp } from "@/lib/platform";

/**
 * Shared step-up hook: `requestStepUp()` opens a modal prompting for a
 * current TOTP code, exchanges it for a short-lived assurance token via
 * the backend, and resolves with that token. The token is held only in
 * a local variable by the caller for the single action it authorizes —
 * never written to sessionStorage/localStorage, never logged.
 */
export function useStepUp() {
  const [open, setOpen] = useState(false);
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const [pending, setPending] = useState(false);
  const resolverRef = useRef<((token: string | null) => void) | null>(null);

  const requestStepUp = useCallback((): Promise<string | null> => {
    setOpen(true);
    setCode("");
    setError("");
    return new Promise((resolve) => {
      resolverRef.current = resolve;
    });
  }, []);

  async function confirm() {
    setPending(true);
    setError("");
    try {
      const result = await stepUp(code);
      setOpen(false);
      resolverRef.current?.(result.assurance_token);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Step-up verification failed";
      setError(msg);
    } finally {
      setPending(false);
    }
  }

  function cancel() {
    setOpen(false);
    resolverRef.current?.(null);
  }

  const modal = open ? (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="w-full max-w-sm rounded-xl border border-purple-800 bg-gray-900 p-6">
        <h3 className="text-lg font-semibold text-white">Step-up verification required</h3>
        <p className="mt-1 text-sm text-gray-400">
          This is a high-impact action. Enter your current MFA code to continue.
        </p>
        <input
          value={code}
          onChange={(e) => setCode(e.target.value)}
          placeholder="6-digit code"
          autoFocus
          className="mt-4 w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-2 text-white placeholder-gray-500 focus:border-purple-500 focus:outline-none"
        />
        {error && <div className="mt-2 text-sm text-red-400">{error}</div>}
        <div className="mt-4 flex gap-3">
          <button
            onClick={confirm}
            disabled={pending || code.length < 6}
            className="rounded-lg bg-purple-600 px-4 py-2 text-sm font-medium text-white hover:bg-purple-500 disabled:opacity-50"
          >
            {pending ? "Verifying…" : "Verify"}
          </button>
          <button
            onClick={cancel}
            className="rounded-lg border border-gray-700 px-4 py-2 text-sm text-gray-400 hover:text-white"
          >
            Cancel
          </button>
        </div>
      </div>
    </div>
  ) : null;

  return { requestStepUp, stepUpModal: modal };
}
