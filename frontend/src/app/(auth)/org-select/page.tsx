"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import {
  getAccessibleOrganizations,
  selectOrganization,
  createOrganization,
  type AccessibleOrganization,
} from "@/lib/auth";
import { isAuthenticated, ApiError } from "@/lib/api";

type Phase = "loading" | "select" | "setup" | "error";

export default function OrgSelectPage() {
  const router = useRouter();
  const [phase, setPhase] = useState<Phase>("loading");
  const [orgs, setOrgs] = useState<AccessibleOrganization[]>([]);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!isAuthenticated()) {
      router.replace("/login");
      return;
    }
    getAccessibleOrganizations()
      .then((list) => {
        if (list.length === 0) {
          setPhase("setup");
        } else if (list.length === 1) {
          // Auto-select the only organization.
          selectOrganization(list[0].id).then(() => {
            router.replace("/dashboard");
          }).catch((err) => {
            setError(err instanceof ApiError ? err.message : "Auto-select failed");
            setPhase("error");
          });
        } else {
          setOrgs(list);
          setPhase("select");
        }
      })
      .catch((err) => {
        setError(err instanceof ApiError ? err.message : "Failed to load organizations");
        setPhase("error");
      });
  }, [router]);

  async function handleSelect(orgId: string) {
    setPhase("loading");
    try {
      await selectOrganization(orgId);
      router.replace("/dashboard");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Organization selection failed");
      setPhase("error");
    }
  }

  if (phase === "loading") {
    return (
      <div className="flex min-h-screen items-center justify-center bg-gray-950">
        <div className="text-gray-400">Loading organizations...</div>
      </div>
    );
  }

  if (phase === "error") {
    return (
      <div className="flex min-h-screen items-center justify-center bg-gray-950">
        <div className="w-full max-w-md rounded-xl border border-red-800 bg-gray-900 p-8 text-center">
          <p className="text-red-400">{error}</p>
          <button
            onClick={() => router.push("/login")}
            className="mt-4 text-sm text-gray-400 hover:text-white"
          >
            Back to login
          </button>
        </div>
      </div>
    );
  }

  if (phase === "setup") {
    return <OrgSetupForm onCreated={handleSelect} />;
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-gray-950">
      <div className="w-full max-w-md rounded-xl border border-gray-800 bg-gray-900 p-8">
        <div className="mb-6 text-center">
          <h1 className="text-xl font-bold text-white">Select Organization</h1>
          <p className="mt-1 text-sm text-gray-400">Choose which organization to work in</p>
        </div>
        <div className="space-y-3">
          {orgs.map((org) => (
            <button
              key={org.id}
              onClick={() => handleSelect(org.id)}
              className="w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-3 text-left hover:border-red-500 hover:bg-gray-750 transition"
            >
              <div className="font-medium text-white">{org.name}</div>
              <div className="text-sm text-gray-400">{org.plan} · {org.status}</div>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

function OrgSetupForm({ onCreated }: { onCreated: (orgId: string) => void }) {
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  function deriveSlug(orgName: string): string {
    return orgName
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, "-")
      .replace(/^-|-$/g, "")
      .slice(0, 63);
  }

  function handleNameChange(v: string) {
    setName(v);
    setSlug(deriveSlug(v));
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      const org = await createOrganization(name, slug);
      onCreated(org.id);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to create organization");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-gray-950">
      <div className="w-full max-w-md rounded-xl border border-gray-800 bg-gray-900 p-8">
        <div className="mb-6 text-center">
          <h1 className="text-xl font-bold text-white">Create Your Organization</h1>
          <p className="mt-1 text-sm text-gray-400">
            Set up your first organization to start red-teaming
          </p>
        </div>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-300">Organization Name</label>
            <input
              type="text"
              value={name}
              onChange={(e) => handleNameChange(e.target.value)}
              className="mt-1 w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-2.5 text-white placeholder-gray-500 focus:border-red-500 focus:outline-none"
              placeholder="Acme Security"
              required
              minLength={2}
              maxLength={100}
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300">Slug</label>
            <input
              type="text"
              value={slug}
              onChange={(e) => setSlug(e.target.value)}
              className="mt-1 w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-2.5 text-white placeholder-gray-500 focus:border-red-500 focus:outline-none"
              placeholder="acme-security"
              required
              minLength={2}
              maxLength={63}
              pattern="^[a-z0-9-]+$"
            />
            <p className="mt-1 text-xs text-gray-500">Lowercase letters, numbers, and hyphens only</p>
          </div>
          {error && (
            <div className="rounded-lg border border-red-800 bg-red-950 px-4 py-2.5 text-sm text-red-300">
              {error}
            </div>
          )}
          <button
            type="submit"
            disabled={loading}
            className="w-full rounded-lg bg-red-600 px-4 py-2.5 font-medium text-white hover:bg-red-500 disabled:opacity-50"
          >
            {loading ? "Creating..." : "Create Organization"}
          </button>
        </form>
      </div>
    </div>
  );
}
