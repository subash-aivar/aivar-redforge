"use client";

import Link from "next/link";

/**
 * Attack path administration is a platform-level operation requiring
 * PlatformPermission. This page redirects users to the platform control plane.
 * The previous stub called /api/v1/threat-intel/attack-paths which does not
 * exist; the real endpoint is /api/v1/attack-paths (platform-scoped).
 */
export default function AttackPathsRedirectPage() {
  return (
    <div className="flex min-h-[60vh] flex-col items-center justify-center gap-4 p-6 text-center">
      <div className="max-w-md">
        <h1 className="text-xl font-bold text-white">Attack Paths</h1>
        <p className="mt-2 text-sm text-gray-400">
          Attack path administration is a platform-level capability. It requires a
          platform role and is managed through the Platform Control Plane.
        </p>
        <Link
          href="/platform/threat-intel/attack-paths"
          className="mt-4 inline-block rounded-lg bg-purple-700 px-5 py-2 text-sm font-medium text-white hover:bg-purple-600"
        >
          Go to Platform → Attack Paths
        </Link>
      </div>
    </div>
  );
}
