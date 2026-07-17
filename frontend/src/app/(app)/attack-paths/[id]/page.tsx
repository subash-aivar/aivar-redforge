"use client";

import Link from "next/link";
import { use } from "react";

export default function AttackPathDetailRedirectPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  return (
    <div className="flex min-h-[60vh] flex-col items-center justify-center gap-4 p-6 text-center">
      <div className="max-w-md">
        <h1 className="text-xl font-bold text-white">Attack Path Detail</h1>
        <p className="mt-2 text-sm text-gray-400">
          Attack path details are managed in the Platform Control Plane. An
          organization ID is also required to load this path.
        </p>
        <Link
          href="/platform/threat-intel/attack-paths"
          className="mt-4 inline-block rounded-lg bg-purple-700 px-5 py-2 text-sm font-medium text-white hover:bg-purple-600"
        >
          Go to Platform → Attack Paths
        </Link>
        <p className="mt-3 text-xs text-gray-600">Path ID: {id}</p>
      </div>
    </div>
  );
}
