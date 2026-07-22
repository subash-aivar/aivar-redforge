"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { login, register } from "@/lib/auth";
import { ApiError } from "@/lib/api";
import { getPlatformAccess } from "@/lib/platform";
import { AuthVisual } from "@/components/AuthVisual";

const REMEMBERED_EMAIL_KEY = "redforge_remembered_email";

// Defensive localStorage access: some test/embedded environments (and
// Safari private mode) don't expose a working localStorage — never let
// the "remember my email" convenience feature break the login flow.
function readRememberedEmail(): string | null {
  try {
    return window.localStorage.getItem(REMEMBERED_EMAIL_KEY);
  } catch {
    return null;
  }
}

function writeRememberedEmail(email: string | null): void {
  try {
    if (email) {
      window.localStorage.setItem(REMEMBERED_EMAIL_KEY, email);
    } else {
      window.localStorage.removeItem(REMEMBERED_EMAIL_KEY);
    }
  } catch {
    /* best-effort convenience feature only */
  }
}

export default function LoginPage() {
  const router = useRouter();
  const [mode, setMode] = useState<"login" | "register">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [rememberMe, setRememberMe] = useState(false);
  const [showForgotHint, setShowForgotHint] = useState(false);

  useEffect(() => {
    const remembered = readRememberedEmail();
    if (remembered) {
      setEmail(remembered);
      setRememberMe(true);
    }
  }, []);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      if (mode === "register") {
        await register(email, displayName, password);
      } else {
        await login(email, password);
      }

      writeRememberedEmail(rememberMe ? email : null);

      // Platform Super Admins land directly on the Platform Control Plane.
      // Everyone else keeps the existing org-select flow, which itself
      // handles auto-select (1 org) and the no-org setup case. Any
      // failure to resolve platform access (network, no access, etc.)
      // falls back to org-select — never blocks login on this check.
      try {
        const access = await getPlatformAccess();
        if (access.has_platform_access) {
          router.push("/platform/overview");
          return;
        }
      } catch {
        /* fall through to org-select */
      }
      router.push("/org-select");
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError("An unexpected error occurred");
      }
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="relative flex min-h-screen bg-gray-950">
      {/* Brand / visual panel — hidden on small screens */}
      <div className="relative hidden w-1/2 flex-col justify-between overflow-hidden border-r border-gray-800/80 p-12 lg:flex">
        <AuthVisual />
        <div className="relative z-10">
          <div className="flex items-center gap-3">
            <LogoMark />
            <span className="text-xl font-bold tracking-tight text-white">
              AIVAR RedForge
            </span>
          </div>
        </div>
        <div className="relative z-10 max-w-md">
          <h2 className="text-3xl font-bold leading-tight text-white">
            Continuous AI Security Validation
          </h2>
          <p className="mt-3 text-sm leading-relaxed text-gray-400">
            Automated red-teaming, exposure management, and threat validation
            for LLM applications, AI agents, and MCP servers — one control
            plane for your entire AI attack surface.
          </p>
        </div>
        <div className="relative z-10 flex items-center gap-6 text-xs font-medium uppercase tracking-widest text-gray-600">
          <span>SOC 2-aligned</span>
          <span className="h-1 w-1 rounded-full bg-gray-700" />
          <span>Tenant-isolated</span>
          <span className="h-1 w-1 rounded-full bg-gray-700" />
          <span>Audit-logged</span>
        </div>
      </div>

      {/* Form panel */}
      <div className="flex w-full flex-1 items-center justify-center px-6 py-12 lg:w-1/2">
        <div className="w-full max-w-md animate-fade-in-up">
          <div className="mb-8 flex flex-col items-center text-center lg:hidden">
            <LogoMark />
            <h1 className="mt-3 text-xl font-bold text-white">AIVAR RedForge</h1>
            <p className="mt-1 text-sm text-gray-500">
              AI Security Validation Platform
            </p>
          </div>

          <div className="rounded-2xl border border-gray-800/80 bg-gray-900/60 p-8 shadow-2xl shadow-black/40 backdrop-blur-xl">
            <div className="mb-7 hidden lg:block">
              <h1 className="text-xl font-bold text-white">
                {mode === "login" ? "Welcome back" : "Create your account"}
              </h1>
              <p className="mt-1 text-sm text-gray-500">
                {mode === "login"
                  ? "Sign in to your security operations console."
                  : "Register a new account to get started."}
              </p>
            </div>

            <form onSubmit={handleSubmit} className="space-y-4" noValidate>
              {mode === "register" && (
                <Field label="Display Name" htmlFor="display_name">
                  <input
                    id="display_name"
                    type="text"
                    value={displayName}
                    onChange={(e) => setDisplayName(e.target.value)}
                    className={inputClass}
                    placeholder="Your name"
                    required
                    minLength={2}
                    autoComplete="name"
                  />
                </Field>
              )}

              <Field label="Email" htmlFor="email">
                <input
                  id="email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className={inputClass}
                  placeholder="you@company.com"
                  required
                  autoComplete="email"
                  inputMode="email"
                />
              </Field>

              <Field label="Password" htmlFor="password">
                <div className="relative">
                  <input
                    id="password"
                    type={showPassword ? "text" : "password"}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className={`${inputClass} pr-11`}
                    placeholder="••••••••"
                    required
                    minLength={8}
                    autoComplete={mode === "login" ? "current-password" : "new-password"}
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword((v) => !v)}
                    aria-label={showPassword ? "Hide password" : "Show password"}
                    aria-pressed={showPassword}
                    className="absolute inset-y-0 right-0 flex items-center px-3 text-gray-500 transition hover:text-gray-300 focus-visible:text-gray-200 focus-visible:outline-none"
                  >
                    {showPassword ? <EyeOffIcon /> : <EyeIcon />}
                  </button>
                </div>
              </Field>

              {mode === "login" && (
                <div className="flex items-center justify-between pt-0.5 text-xs">
                  <label className="flex select-none items-center gap-2 text-gray-400">
                    <input
                      type="checkbox"
                      checked={rememberMe}
                      onChange={(e) => setRememberMe(e.target.checked)}
                      className="h-3.5 w-3.5 rounded border-gray-700 bg-gray-800 text-red-600 focus:ring-1 focus:ring-red-600 focus:ring-offset-0"
                    />
                    Remember my email
                  </label>
                  <div className="relative">
                    <button
                      type="button"
                      onClick={() => setShowForgotHint((v) => !v)}
                      className="text-gray-500 underline decoration-dotted underline-offset-2 hover:text-gray-300 focus-visible:text-gray-200 focus-visible:outline-none"
                    >
                      Forgot password?
                    </button>
                    {showForgotHint && (
                      <div
                        role="status"
                        className="absolute right-0 top-6 z-10 w-56 rounded-lg border border-gray-800 bg-gray-950 p-3 text-[11px] leading-relaxed text-gray-400 shadow-xl animate-fade-in-up"
                      >
                        Self-service password reset isn&apos;t available yet.
                        Contact your platform or organization administrator to
                        reset your password.
                      </div>
                    )}
                  </div>
                </div>
              )}

              <div role="alert" aria-live="polite">
                {error && (
                  <div className="flex items-start gap-2 rounded-lg border border-red-900/60 bg-red-950/50 px-4 py-2.5 text-sm text-red-300 animate-fade-in-up">
                    <AlertIcon />
                    <span>{error}</span>
                  </div>
                )}
              </div>

              <button
                type="submit"
                disabled={loading}
                className="group relative flex w-full items-center justify-center gap-2 rounded-lg bg-red-600 px-4 py-2.5 font-semibold text-white transition hover:bg-red-500 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-red-500 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {loading && <Spinner />}
                {loading
                  ? mode === "login"
                    ? "Signing in…"
                    : "Creating account…"
                  : mode === "login"
                    ? "Sign In"
                    : "Create Account"}
              </button>
            </form>

            <p className="mt-6 text-center text-sm text-gray-500">
              {mode === "login" ? (
                <>
                  No account?{" "}
                  <button
                    onClick={() => {
                      setMode("register");
                      setError("");
                    }}
                    className="font-medium text-red-400 hover:text-red-300 focus-visible:outline-none focus-visible:underline"
                  >
                    Register
                  </button>
                </>
              ) : (
                <>
                  Already have an account?{" "}
                  <button
                    onClick={() => {
                      setMode("login");
                      setError("");
                    }}
                    className="font-medium text-red-400 hover:text-red-300 focus-visible:outline-none focus-visible:underline"
                  >
                    Sign In
                  </button>
                </>
              )}
            </p>
          </div>

          <p className="mt-6 text-center text-xs text-gray-600">
            Protected by tenant-isolated authentication. All access is
            audit-logged.
          </p>
        </div>
      </div>
    </div>
  );
}

const inputClass =
  "w-full rounded-lg border border-gray-700 bg-gray-800/80 px-4 py-2.5 text-white placeholder-gray-500 transition focus:border-red-500 focus:outline-none focus:ring-1 focus:ring-red-500/50";

function Field({
  label,
  htmlFor,
  children,
}: {
  label: string;
  htmlFor: string;
  children: React.ReactNode;
}) {
  return (
    <div>
      <label htmlFor={htmlFor} className="block text-sm font-medium text-gray-300">
        {label}
      </label>
      <div className="mt-1.5">{children}</div>
    </div>
  );
}

function LogoMark() {
  return (
    <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-red-900/60 bg-gradient-to-br from-red-600/20 to-red-900/20">
      <svg viewBox="0 0 24 24" className="h-5 w-5 text-red-400" fill="none" aria-hidden="true">
        <path
          d="M12 2 3 6v6c0 5 3.8 8.7 9 10 5.2-1.3 9-5 9-10V6l-9-4Z"
          stroke="currentColor"
          strokeWidth="1.6"
          strokeLinejoin="round"
        />
        <path
          d="m9 12 2 2 4-4"
          stroke="currentColor"
          strokeWidth="1.6"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      </svg>
    </div>
  );
}

function EyeIcon() {
  return (
    <svg viewBox="0 0 24 24" className="h-[18px] w-[18px]" fill="none" aria-hidden="true">
      <path
        d="M1.5 12S5 5 12 5s10.5 7 10.5 7-3.5 7-10.5 7S1.5 12 1.5 12Z"
        stroke="currentColor"
        strokeWidth="1.5"
      />
      <circle cx="12" cy="12" r="3" stroke="currentColor" strokeWidth="1.5" />
    </svg>
  );
}

function EyeOffIcon() {
  return (
    <svg viewBox="0 0 24 24" className="h-[18px] w-[18px]" fill="none" aria-hidden="true">
      <path
        d="M3 3l18 18M10.6 10.6a3 3 0 0 0 4.24 4.24M6.6 6.7C3.9 8.4 1.5 12 1.5 12s3.5 7 10.5 7c1.9 0 3.5-.5 4.9-1.2M9.9 5.2C10.6 5.1 11.3 5 12 5c7 0 10.5 7 10.5 7-.3.6-1.2 2.1-2.7 3.6"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
      />
    </svg>
  );
}

function AlertIcon() {
  return (
    <svg viewBox="0 0 24 24" className="mt-0.5 h-4 w-4 flex-shrink-0" fill="none" aria-hidden="true">
      <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="1.5" />
      <path d="M12 8v5" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
      <circle cx="12" cy="16" r="0.9" fill="currentColor" />
    </svg>
  );
}

function Spinner() {
  return (
    <svg
      className="h-4 w-4 animate-spin text-white"
      viewBox="0 0 24 24"
      fill="none"
      aria-hidden="true"
    >
      <circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="3" opacity="0.25" />
      <path d="M21 12a9 9 0 0 0-9-9" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
    </svg>
  );
}
