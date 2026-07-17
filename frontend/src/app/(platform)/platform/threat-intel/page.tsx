"use client";

import { useEffect, useState } from "react";
import {
  listTactics,
  listTechniquesByTactic,
  searchTechniques,
  listKevVulnerabilities,
  listHighEpssVulnerabilities,
  listIngestions,
  cvssColor,
  cvssLabel,
  type AttackTactic,
  type AttackTechnique,
  type Vulnerability,
  type IngestionRecord,
} from "@/lib/referenceData";

type Tab = "tactics" | "techniques" | "vulnerabilities" | "ingestions";
type VulnFilter = "kev" | "epss_50" | "epss_10";

export default function ThreatIntelReferencePage() {
  const [tab, setTab] = useState<Tab>("tactics");

  return (
    <div>
      <h1 className="text-2xl font-bold text-white">Threat Intelligence — Reference Data</h1>
      <p className="mt-1 text-sm text-gray-400">
        Global ATT&CK catalog and vulnerability data. Read-only; populated by feed ingestion.
      </p>

      <div className="mt-6 flex gap-1 border-b border-gray-800">
        {(
          [
            ["tactics", "Tactics"],
            ["techniques", "Techniques"],
            ["vulnerabilities", "Vulnerabilities"],
            ["ingestions", "Ingestion Log"],
          ] as [Tab, string][]
        ).map(([key, label]) => (
          <button
            key={key}
            onClick={() => setTab(key)}
            className={`px-4 py-2 text-sm font-medium transition ${
              tab === key
                ? "border-b-2 border-purple-400 text-purple-300"
                : "text-gray-500 hover:text-gray-300"
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      <div className="mt-6">
        {tab === "tactics" && <TacticsTab />}
        {tab === "techniques" && <TechniquesTab />}
        {tab === "vulnerabilities" && <VulnerabilitiesTab />}
        {tab === "ingestions" && <IngestionsTab />}
      </div>
    </div>
  );
}

// ── Tactics ────────────────────────────────────────────────────────────────

function TacticsTab() {
  const [tactics, setTactics] = useState<AttackTactic[] | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    listTactics({ limit: 100 })
      .then(setTactics)
      .catch(() => setError("Failed to load tactics."));
  }, []);

  if (error) return <ErrorBanner msg={error} />;
  if (!tactics) return <LoadingRow />;
  if (tactics.length === 0) return <EmptyRow msg="No tactics ingested yet. Run an ATT&CK feed." />;

  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
      {tactics.map((t) => (
        <div key={t.tactic_id} className="rounded-xl border border-gray-800 bg-gray-900 p-4">
          <div className="flex items-start justify-between">
            <span className="font-mono text-xs text-purple-400">{t.tactic_id}</span>
            <span className="text-xs text-gray-600">{t.shortname}</span>
          </div>
          <div className="mt-1 text-sm font-medium text-white">{t.name}</div>
          <div className="mt-2 line-clamp-3 text-xs text-gray-500">{t.description}</div>
        </div>
      ))}
    </div>
  );
}

// ── Techniques ─────────────────────────────────────────────────────────────

function TechniquesTab() {
  const [tactics, setTactics] = useState<AttackTactic[]>([]);
  const [selectedTactic, setSelectedTactic] = useState("");
  const [search, setSearch] = useState("");
  const [techniques, setTechniques] = useState<AttackTechnique[] | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    listTactics({ limit: 100 }).then(setTactics).catch(() => {});
  }, []);

  useEffect(() => {
    if (!selectedTactic && !search) {
      setTechniques(null);
      return;
    }
    setTechniques(null);
    setError("");
    const promise = search
      ? searchTechniques(search, { limit: 50 })
      : listTechniquesByTactic(selectedTactic, { limit: 100 });
    promise.then(setTechniques).catch(() => setError("Failed to load techniques."));
  }, [selectedTactic, search]);

  return (
    <div>
      <div className="flex flex-wrap gap-3">
        <select
          value={selectedTactic}
          onChange={(e) => { setSelectedTactic(e.target.value); setSearch(""); }}
          className="rounded-lg border border-gray-700 bg-gray-900 px-3 py-2 text-sm text-gray-200 focus:outline-none focus:ring-1 focus:ring-purple-600"
        >
          <option value="">Select tactic…</option>
          {tactics.map((t) => (
            <option key={t.tactic_id} value={t.tactic_id}>{t.name}</option>
          ))}
        </select>
        <input
          type="text"
          placeholder="Or search techniques…"
          value={search}
          onChange={(e) => { setSearch(e.target.value); setSelectedTactic(""); }}
          className="rounded-lg border border-gray-700 bg-gray-900 px-3 py-2 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:ring-1 focus:ring-purple-600"
        />
      </div>

      {!selectedTactic && !search ? (
        <p className="mt-6 text-sm text-gray-600">
          Select a tactic or enter a search term to load techniques.
        </p>
      ) : error ? (
        <ErrorBanner msg={error} />
      ) : !techniques ? (
        <LoadingRow />
      ) : techniques.length === 0 ? (
        <EmptyRow msg="No techniques found." />
      ) : (
        <div className="mt-4 overflow-x-auto rounded-xl border border-gray-800">
          <table className="min-w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-xs text-gray-500">
                <th className="px-4 py-2 text-left">ID</th>
                <th className="px-4 py-2 text-left">Name</th>
                <th className="px-4 py-2 text-left">Platforms</th>
                <th className="px-4 py-2 text-left">Sub</th>
              </tr>
            </thead>
            <tbody>
              {techniques.map((t) => (
                <tr key={t.technique_id} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                  <td className="px-4 py-2 font-mono text-xs text-purple-400">{t.technique_id}</td>
                  <td className="px-4 py-2 text-gray-200">{t.name}</td>
                  <td className="px-4 py-2 text-xs text-gray-500">{t.platforms.slice(0, 3).join(", ")}</td>
                  <td className="px-4 py-2 text-xs text-gray-500">{t.is_sub_technique ? "✓" : ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ── Vulnerabilities ────────────────────────────────────────────────────────

function VulnerabilitiesTab() {
  const [filter, setFilter] = useState<VulnFilter>("kev");
  const [vulns, setVulns] = useState<Vulnerability[] | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    setVulns(null);
    setError("");
    const promise =
      filter === "kev"
        ? listKevVulnerabilities({ limit: 50 })
        : filter === "epss_50"
        ? listHighEpssVulnerabilities(0.5, { limit: 50 })
        : listHighEpssVulnerabilities(0.1, { limit: 50 });
    promise.then(setVulns).catch(() => setError("Failed to load vulnerabilities."));
  }, [filter]);

  return (
    <div>
      <div className="flex gap-2">
        {(
          [
            ["kev", "KEV Only"],
            ["epss_50", "EPSS ≥ 0.5"],
            ["epss_10", "EPSS ≥ 0.1"],
          ] as [VulnFilter, string][]
        ).map(([f, label]) => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={`rounded-full border px-3 py-1 text-xs font-medium transition ${
              filter === f
                ? "border-purple-700 bg-purple-950/60 text-purple-300"
                : "border-gray-700 text-gray-500 hover:border-gray-600 hover:text-gray-300"
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {error ? (
        <ErrorBanner msg={error} />
      ) : !vulns ? (
        <LoadingRow />
      ) : vulns.length === 0 ? (
        <EmptyRow msg="No vulnerabilities found for this filter." />
      ) : (
        <div className="mt-4 overflow-x-auto rounded-xl border border-gray-800">
          <table className="min-w-full text-sm">
            <thead>
              <tr className="border-b border-gray-800 text-xs text-gray-500">
                <th className="px-4 py-2 text-left">CVE</th>
                <th className="px-4 py-2 text-left">CVSS v3</th>
                <th className="px-4 py-2 text-left">EPSS</th>
                <th className="px-4 py-2 text-left">KEV</th>
                <th className="px-4 py-2 text-left">Description</th>
              </tr>
            </thead>
            <tbody>
              {vulns.map((v) => (
                <tr key={v.cve_id} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                  <td className="px-4 py-2 font-mono text-xs text-purple-400">{v.cve_id}</td>
                  <td className="px-4 py-2">
                    {v.cvss_v3 ? (
                      <span
                        className={`inline-block rounded border px-1.5 py-0.5 text-xs font-medium ${cvssColor(v.cvss_v3.base_score)}`}
                      >
                        {v.cvss_v3.base_score.toFixed(1)} {cvssLabel(v.cvss_v3.base_score)}
                      </span>
                    ) : (
                      <span className="text-gray-600">—</span>
                    )}
                  </td>
                  <td className="px-4 py-2 text-xs text-gray-400">
                    {v.epss ? (v.epss.probability * 100).toFixed(1) + "%" : "—"}
                  </td>
                  <td className="px-4 py-2 text-xs">
                    {v.is_kev ? (
                      <span className="rounded border border-red-800 bg-red-950/50 px-1.5 py-0.5 text-red-300">
                        KEV
                      </span>
                    ) : (
                      <span className="text-gray-700">—</span>
                    )}
                  </td>
                  <td className="max-w-xs px-4 py-2 text-xs text-gray-500">
                    <span className="line-clamp-2">{v.description}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ── Ingestion Log ──────────────────────────────────────────────────────────

function IngestionsTab() {
  const [records, setRecords] = useState<IngestionRecord[] | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    listIngestions({ limit: 50 })
      .then(setRecords)
      .catch(() => setError("Failed to load ingestion log."));
  }, []);

  if (error) return <ErrorBanner msg={error} />;
  if (!records) return <LoadingRow />;
  if (records.length === 0) return <EmptyRow msg="No ingestion records yet." />;

  return (
    <div className="overflow-x-auto rounded-xl border border-gray-800">
      <table className="min-w-full text-sm">
        <thead>
          <tr className="border-b border-gray-800 text-xs text-gray-500">
            <th className="px-4 py-2 text-left">Source</th>
            <th className="px-4 py-2 text-left">Object Type</th>
            <th className="px-4 py-2 text-left">External ID</th>
            <th className="px-4 py-2 text-left">Scope</th>
            <th className="px-4 py-2 text-left">Ingested At</th>
          </tr>
        </thead>
        <tbody>
          {records.map((r) => (
            <tr key={r.id} className="border-b border-gray-800/50 hover:bg-gray-800/30">
              <td className="px-4 py-2 text-xs text-purple-400">{r.source_system}</td>
              <td className="px-4 py-2 text-xs text-gray-300">{r.object_type}</td>
              <td className="max-w-xs px-4 py-2 font-mono text-xs text-gray-500">
                <span className="truncate block max-w-[200px]">{r.external_id}</span>
              </td>
              <td className="px-4 py-2 text-xs text-gray-500">{r.scope}</td>
              <td className="px-4 py-2 text-xs text-gray-500">
                {new Date(r.ingested_at).toLocaleString()}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

// ── Shared primitives ──────────────────────────────────────────────────────

function LoadingRow() {
  return <div className="mt-8 text-sm text-gray-500">Loading…</div>;
}

function ErrorBanner({ msg }: { msg: string }) {
  return (
    <div className="mt-4 rounded-lg border border-red-800 bg-red-950 px-4 py-3 text-sm text-red-300">
      {msg}
    </div>
  );
}

function EmptyRow({ msg }: { msg: string }) {
  return (
    <div className="mt-4 rounded-lg border border-gray-800 bg-gray-900 px-4 py-3 text-sm text-gray-500">
      {msg}
    </div>
  );
}
