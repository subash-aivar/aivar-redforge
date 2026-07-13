import type { NextConfig } from "next";

const isDev = process.env.NODE_ENV !== "production";

// Canonical local-development API-origin model: the browser NEVER talks
// to the backend cross-origin. Every `/api/v1/*` request the frontend
// issues (see src/lib/api.ts's same-origin-by-default API_BASE) is
// same-origin to whatever host/port the browser loaded the frontend
// from — localhost, a LAN IP, anything — and this rewrite proxies it
// server-side (Next.js process -> backend process, both on the same
// machine in local dev) to the real backend. This is what makes the
// LAN case (e.g. http://172.16.18.149:3000) work with zero extra
// configuration: there is no "browser reaches the wrong host" failure
// mode, because the browser only ever reaches its own origin.
//
// BACKEND_INTERNAL_URL (server-side only, no NEXT_PUBLIC_ prefix — never
// sent to the browser) is the one explicit-override escape hatch for
// when the backend is NOT reachable at localhost:8000 from wherever the
// Next.js server process itself runs (e.g. Docker Compose service
// networking, or a separately-deployed backend). Do not introduce a
// second, conflicting API-origin strategy alongside this one.
const BACKEND_INTERNAL_URL = process.env.BACKEND_INTERNAL_URL || "http://localhost:8000";

// CSP for Next.js App Router + Tailwind CSS.
// 'unsafe-inline' on style-src is required by Tailwind's JIT runtime.
// 'unsafe-eval' is required ONLY in development: Next.js's dev-mode
// webpack runtime (React Refresh / HMR) uses eval()-based module
// evaluation, and without this the entire client bundle silently fails
// to hydrate — no console error, no CSP violation report, the app just
// never becomes interactive (this was the root cause of the "permanent
// Loading..." / login-does-nothing regression: `next dev` needs eval,
// `next start`/production does not and never gets 'unsafe-eval').
// connect-src is 'self' by default — the API proxy above means the
// browser never NEEDS a cross-origin allowance for the backend. If
// NEXT_PUBLIC_API_URL is explicitly set (the escape-hatch override in
// src/lib/api.ts, bypassing the same-origin proxy entirely), that exact
// origin must also be allowed here, or the override would be silently
// CSP-blocked instead of working.
const explicitApiOrigin = process.env.NEXT_PUBLIC_API_URL || "";
const csp = [
  "default-src 'self'",
  `script-src 'self' 'unsafe-inline'${isDev ? " 'unsafe-eval'" : ""}`,
  "style-src 'self' 'unsafe-inline'",
  `connect-src 'self'${explicitApiOrigin ? ` ${explicitApiOrigin}` : ""}`,
  "img-src 'self' data:",
  "font-src 'self'",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "object-src 'none'",
]
  .join("; ")
  .trim();

const securityHeaders = [
  { key: "Content-Security-Policy", value: csp },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  {
    key: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=(), payment=()",
  },
  {
    key: "Strict-Transport-Security",
    value: "max-age=63072000; includeSubDomains; preload",
  },
];

const nextConfig: NextConfig = {
  output: "standalone",
  async headers() {
    return [
      {
        source: "/(.*)",
        headers: securityHeaders,
      },
    ];
  },
  async rewrites() {
    return [
      {
        source: "/api/v1/:path*",
        destination: `${BACKEND_INTERNAL_URL}/api/v1/:path*`,
      },
    ];
  },
};

export default nextConfig;
