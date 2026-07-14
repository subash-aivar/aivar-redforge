"use client";

import { useState } from "react";
import { ApiError } from "@/lib/api";
import {
  ZONE_LABELS,
  assignZone,
  getZoneOverview,
  listZoneAssignments,
  unassignZone,
} from "@/lib/commandCenter";
import {
  AsyncContent,
  KpiTile,
  Panel,
  PageHeader,
  useAsync,
} from "@/components/cc";

const ZONE_TYPES = Object.keys(ZONE_LABELS);

export default function ZonesPage() {
  const overview = useAsync(getZoneOverview, []);
  const assignments = useAsync(() => listZoneAssignments(), []);
  const [assetId, setAssetId] = useState("");
  const [zoneType, setZoneType] = useState("dmz");
  const [note, setNote] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  async function submit() {
    setMsg(null);
    setErr(null);
    try {
      await assignZone(assetId.trim(), zoneType, note.trim());
      setMsg(`Assigned ${assetId.trim()} to ${ZONE_LABELS[zoneType]}.`);
      setAssetId("");
      setNote("");
      overview.reload();
      assignments.reload();
    } catch (e) {
      setErr(e instanceof ApiError ? `${e.status}: ${e.message}` : "Assignment failed");
    }
  }

  async function remove(id: string) {
    try {
      await unassignZone(id);
      overview.reload();
      assignments.reload();
    } catch (e) {
      setErr(e instanceof ApiError ? `${e.status}: ${e.message}` : "Unassign failed");
    }
  }

  return (
    <div>
      <PageHeader
        title="Network Zones & DMZ"
        subtitle="Explicit, admin-authored network-zone classification. An asset is never auto-labelled DMZ from an IP heuristic — zones are deliberate assignments. The DMZ overview shows only assets an administrator placed in the DMZ."
      />

      <div className="mb-4 grid grid-cols-2 gap-3 md:grid-cols-4 lg:grid-cols-7">
        <AsyncContent state={overview}>
          {(o) => (
            <>
              {ZONE_TYPES.map((z) => (
                <KpiTile key={z} label={ZONE_LABELS[z]} value={o.counts_by_zone[z] ?? 0} />
              ))}
            </>
          )}
        </AsyncContent>
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Panel title="DMZ assets (explicitly assigned)">
          <AsyncContent state={overview} empty={(o) => o.dmz_assets.length === 0} emptyLabel="No assets assigned to the DMZ zone.">
            {(o) => (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-gray-800 text-left text-[11px] uppercase tracking-wider text-gray-500">
                      <th className="py-2 pr-4">Asset</th>
                      <th className="py-2 pr-4">Type</th>
                      <th className="py-2 pr-4">Active conditions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {o.dmz_assets.map((a) => (
                      <tr key={a.asset_id} className="border-b border-gray-800/60">
                        <td className="py-2 pr-4 text-gray-200">{a.asset_name}</td>
                        <td className="py-2 pr-4 text-gray-400">{a.asset_type}</td>
                        <td className="py-2 pr-4 tabular-nums text-red-300">{a.active_condition_count}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </AsyncContent>
        </Panel>

        <Panel title="Assign a zone">
          <div className="space-y-3">
            <input
              value={assetId}
              onChange={(e) => setAssetId(e.target.value)}
              placeholder="Asset ID (ULID)"
              className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-gray-200 placeholder-gray-600"
            />
            <select
              value={zoneType}
              onChange={(e) => setZoneType(e.target.value)}
              className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-gray-200"
            >
              {ZONE_TYPES.map((z) => (
                <option key={z} value={z}>{ZONE_LABELS[z]}</option>
              ))}
            </select>
            <input
              value={note}
              onChange={(e) => setNote(e.target.value)}
              placeholder="Note (optional)"
              className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-gray-200 placeholder-gray-600"
            />
            <button
              onClick={submit}
              disabled={!assetId.trim()}
              className="w-full rounded-lg bg-red-600 px-3 py-2 text-sm font-medium text-white hover:bg-red-500 disabled:opacity-40"
            >
              Assign zone
            </button>
            {msg && <div className="text-xs text-emerald-400">{msg}</div>}
            {err && <div className="text-xs text-red-400">{err}</div>}
            <p className="text-[11px] text-gray-600">
              Requires network-security management permission. Assigning an asset from another
              organization returns 404; an unknown zone type returns 422.
            </p>
          </div>
        </Panel>
      </div>

      <div className="mt-4">
        <Panel title="All zone assignments">
          <AsyncContent state={assignments} empty={(a) => a.length === 0} emptyLabel="No zone assignments yet.">
            {(a) => (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-gray-800 text-left text-[11px] uppercase tracking-wider text-gray-500">
                      <th className="py-2 pr-4">Asset</th>
                      <th className="py-2 pr-4">Zone</th>
                      <th className="py-2 pr-4">Note</th>
                      <th className="py-2 pr-4">Updated</th>
                      <th className="py-2 pr-4"></th>
                    </tr>
                  </thead>
                  <tbody>
                    {a.map((r) => (
                      <tr key={r.asset_id} className="border-b border-gray-800/60">
                        <td className="py-2 pr-4 text-gray-200">{r.asset_name}</td>
                        <td className="py-2 pr-4 text-gray-300">{ZONE_LABELS[r.zone_type] ?? r.zone_type}</td>
                        <td className="py-2 pr-4 text-gray-500">{r.note || "—"}</td>
                        <td className="py-2 pr-4 text-[11px] tabular-nums text-gray-500">
                          {new Date(r.updated_at).toLocaleString()}
                        </td>
                        <td className="py-2 pr-4 text-right">
                          <button
                            onClick={() => remove(r.asset_id)}
                            className="text-[11px] text-gray-500 hover:text-red-400"
                          >
                            unassign
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </AsyncContent>
        </Panel>
      </div>
    </div>
  );
}
