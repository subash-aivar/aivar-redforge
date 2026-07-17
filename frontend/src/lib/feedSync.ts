/**
 * Feed Synchronization API client — M22 Phase 2.
 *
 * All endpoints require platform permissions (PlatformPermission).
 * Manages feed registration, lifecycle, configuration, and sync history.
 */
import { api } from "@/lib/api";

// ── Response types ─────────────────────────────────────────────────────────

export interface RetryPolicy {
  max_attempts: number;
  base_delay_seconds: number;
  max_delay_seconds: number;
  jitter_factor: number;
}

export interface Feed {
  id: string;
  feed_key: string;
  display_name: string;
  source_kind: string;
  scope: string;
  organization_id: string | null;
  status: string;
  connector_config: Record<string, unknown>;
  credential_ref: string | null;
  schedule_interval_seconds: number;
  retry_policy: RetryPolicy;
  checkpoint: string | null;
  consecutive_failure_count: number;
  last_sync_started_at: string | null;
  last_sync_completed_at: string | null;
  last_sync_status: string | null;
  next_sync_due_at: string | null;
  created_at: string;
  updated_at: string;
  created_by: string;
  updated_by: string;
}

export interface FeedListResponse {
  items: Feed[];
  total: number;
}

export interface FeedSyncRun {
  id: string;
  feed_id: string;
  status: string;
  trigger: string;
  checkpoint_before: string | null;
  checkpoint_after: string | null;
  items_fetched: number;
  items_processed: number;
  items_failed: number;
  retry_attempts_used: number;
  error_message: string | null;
  started_at: string;
  finished_at: string | null;
  created_by: string;
}

export interface FeedSyncRunListResponse {
  items: FeedSyncRun[];
  total: number;
}

export interface RegisterFeedBody {
  feed_key: string;
  display_name: string;
  source_kind: string;
  interval_seconds: number;
  scope?: string;
  organization_id?: string | null;
  connector_config?: Record<string, string>;
  credential_ref?: string | null;
  retry_max_attempts?: number;
  retry_base_delay_seconds?: number;
  retry_max_delay_seconds?: number;
  retry_jitter_factor?: number;
}

export interface UpdateFeedBody {
  display_name?: string;
  connector_config?: Record<string, unknown>;
  credential_ref?: string | null;
  interval_seconds?: number;
  retry_max_attempts?: number;
}

// ── API functions ──────────────────────────────────────────────────────────

export function listFeeds(
  params: {
    scope?: string;
    status?: string;
    source_kind?: string;
    limit?: number;
    offset?: number;
  } = {},
): Promise<FeedListResponse> {
  const q = new URLSearchParams();
  if (params.scope) q.set("scope", params.scope);
  if (params.status) q.set("status", params.status);
  if (params.source_kind) q.set("source_kind", params.source_kind);
  if (params.limit != null) q.set("limit", String(params.limit));
  if (params.offset != null) q.set("offset", String(params.offset));
  const qs = q.toString();
  return api.get<FeedListResponse>(`/api/v1/threat-intel/feeds${qs ? `?${qs}` : ""}`);
}

export function getFeed(feedId: string): Promise<Feed> {
  return api.get<Feed>(`/api/v1/threat-intel/feeds/${encodeURIComponent(feedId)}`);
}

export function registerFeed(body: RegisterFeedBody): Promise<Feed> {
  return api.post<Feed>("/api/v1/threat-intel/feeds", body);
}

export function updateFeed(feedId: string, body: UpdateFeedBody): Promise<Feed> {
  return api.patch<Feed>(`/api/v1/threat-intel/feeds/${encodeURIComponent(feedId)}`, body);
}

export function activateFeed(feedId: string): Promise<Feed> {
  return api.post<Feed>(`/api/v1/threat-intel/feeds/${encodeURIComponent(feedId)}/activate`);
}

export function pauseFeed(feedId: string): Promise<Feed> {
  return api.post<Feed>(`/api/v1/threat-intel/feeds/${encodeURIComponent(feedId)}/pause`);
}

export function disableFeed(feedId: string): Promise<Feed> {
  return api.post<Feed>(`/api/v1/threat-intel/feeds/${encodeURIComponent(feedId)}/disable`);
}

export function triggerFeedSync(feedId: string): Promise<FeedSyncRun> {
  return api.post<FeedSyncRun>(
    `/api/v1/threat-intel/feeds/${encodeURIComponent(feedId)}/sync`,
  );
}

export function listSyncRuns(
  feedId: string,
  params: { limit?: number; offset?: number } = {},
): Promise<FeedSyncRunListResponse> {
  const q = new URLSearchParams();
  if (params.limit != null) q.set("limit", String(params.limit));
  if (params.offset != null) q.set("offset", String(params.offset));
  const qs = q.toString();
  return api.get<FeedSyncRunListResponse>(
    `/api/v1/threat-intel/feeds/${encodeURIComponent(feedId)}/runs${qs ? `?${qs}` : ""}`,
  );
}

export function getSyncRun(feedId: string, runId: string): Promise<FeedSyncRun> {
  return api.get<FeedSyncRun>(
    `/api/v1/threat-intel/feeds/${encodeURIComponent(feedId)}/runs/${encodeURIComponent(runId)}`,
  );
}

// ── Display helpers ────────────────────────────────────────────────────────

export function feedStatusColor(status: string): string {
  switch (status.toLowerCase()) {
    case "active": return "border-emerald-800 bg-emerald-950/50 text-emerald-300";
    case "paused": return "border-yellow-800 bg-yellow-950/50 text-yellow-300";
    case "disabled": return "border-gray-700 bg-gray-800 text-gray-400";
    case "error": return "border-red-800 bg-red-950/60 text-red-300";
    default: return "border-gray-700 bg-gray-800 text-gray-400";
  }
}

export function syncRunStatusColor(status: string): string {
  switch (status.toLowerCase()) {
    case "succeeded": return "border-emerald-800 bg-emerald-950/50 text-emerald-300";
    case "running": return "border-blue-800 bg-blue-950/50 text-blue-300";
    case "pending": return "border-gray-700 bg-gray-800 text-gray-400";
    case "failed": return "border-red-800 bg-red-950/60 text-red-300";
    default: return "border-gray-700 bg-gray-800 text-gray-400";
  }
}

export function formatInterval(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)}h`;
  return `${Math.round(seconds / 86400)}d`;
}

export const SOURCE_KIND_LABELS: Record<string, string> = {
  stix_taxii_pull: "STIX/TAXII Pull",
  nvd_cve: "NVD CVE",
  cisa_kev: "CISA KEV",
  mitre_attack: "MITRE ATT&CK",
  manual_upload: "Manual Upload",
};
