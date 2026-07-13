"use client";

import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { Target } from "@/lib/types";

export default function TargetsPage() {
  const [targets, setTargets] = useState<Target[]>([]);
  const [loading, setLoading] = useState(true);
  const [showCreate, setShowCreate] = useState(false);

  useEffect(() => {
    api.get<Target[]>("/api/v1/targets")
      .then((data) => setTargets(Array.isArray(data) ? data : []))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  return (
    <div>
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">AI Targets</h1>
          <p className="mt-1 text-sm text-gray-400">AI systems under security validation</p>
        </div>
        <button
          onClick={() => setShowCreate(true)}
          className="rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-500"
        >
          Register Target
        </button>
      </div>

      {showCreate && <CreateTargetForm onClose={() => setShowCreate(false)} onCreated={(t) => { setTargets([t, ...targets]); setShowCreate(false); }} />}

      {loading ? (
        <div className="mt-8 text-gray-500">Loading targets...</div>
      ) : targets.length === 0 ? (
        <div className="mt-8 rounded-xl border border-gray-800 bg-gray-900 p-8 text-center">
          <p className="text-gray-400">No AI targets registered yet.</p>
          <p className="mt-2 text-sm text-gray-500">Register an AI system to begin security validation.</p>
        </div>
      ) : (
        <div className="mt-6 space-y-3">
          {targets.map((t) => (
            <div key={t.id} className="rounded-xl border border-gray-800 bg-gray-900 p-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="font-medium text-white">{t.name}</h3>
                  <p className="mt-0.5 text-sm text-gray-400">{t.description || "No description"}</p>
                </div>
                <div className="flex items-center gap-3">
                  <span className="text-xs text-gray-500">{t.target_type}</span>
                  <span className="text-xs text-gray-500">{t.provider}</span>
                  <span className={`rounded px-2 py-0.5 text-xs ${t.status === "active" ? "bg-green-950 text-green-400" : "bg-gray-800 text-gray-500"}`}>
                    {t.status}
                  </span>
                </div>
              </div>
              <div className="mt-2 text-xs text-gray-600 truncate">{t.endpoint}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function CreateTargetForm({ onClose, onCreated }: { onClose: () => void; onCreated: (t: Target) => void }) {
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [targetType, setTargetType] = useState("llm_application");
  const [provider, setProvider] = useState("openai");
  const [endpoint, setEndpoint] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      const t = await api.post<Target>("/api/v1/targets", {
        name, description, target_type: targetType, provider, endpoint,
      });
      onCreated(t);
    } catch (err: any) {
      setError(err.message || "Failed to create target");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="mt-6 rounded-xl border border-gray-700 bg-gray-900 p-6">
      <h2 className="text-lg font-semibold text-white">Register AI Target</h2>
      <form onSubmit={submit} className="mt-4 space-y-3">
        <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Target name" required className="w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-2 text-white placeholder-gray-500 focus:border-red-500 focus:outline-none" />
        <input value={description} onChange={(e) => setDescription(e.target.value)} placeholder="Description" className="w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-2 text-white placeholder-gray-500 focus:border-red-500 focus:outline-none" />
        <div className="grid grid-cols-2 gap-3">
          <select value={targetType} onChange={(e) => setTargetType(e.target.value)} className="rounded-lg border border-gray-700 bg-gray-800 px-4 py-2 text-white">
            <option value="llm_application">LLM Application</option>
            <option value="ai_agent">AI Agent</option>
            <option value="rag_system">RAG System</option>
            <option value="mcp_server">MCP Server</option>
            <option value="ai_api">AI API</option>
            <option value="ai_workflow">AI Workflow</option>
            <option value="autonomous_agent">Autonomous Agent</option>
          </select>
          <select value={provider} onChange={(e) => setProvider(e.target.value)} className="rounded-lg border border-gray-700 bg-gray-800 px-4 py-2 text-white">
            <option value="openai">OpenAI</option>
            <option value="anthropic">Anthropic</option>
            <option value="google">Google</option>
            <option value="local">Local</option>
          </select>
        </div>
        <input value={endpoint} onChange={(e) => setEndpoint(e.target.value)} placeholder="Endpoint URL" required className="w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-2 text-white placeholder-gray-500 focus:border-red-500 focus:outline-none" />
        {error && <div className="text-sm text-red-400">{error}</div>}
        <div className="flex gap-3">
          <button type="submit" disabled={loading} className="rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white hover:bg-red-500 disabled:opacity-50">
            {loading ? "Creating..." : "Register Target"}
          </button>
          <button type="button" onClick={onClose} className="rounded-lg border border-gray-700 px-4 py-2 text-sm text-gray-400 hover:text-white">Cancel</button>
        </div>
      </form>
    </div>
  );
}
