/**
 * AI Supply Chain API client — `ai_supply_chain` bounded context.
 *
 * REPOSITORY AUDIT FINDING (Slice 5): the previous version of this
 * file was entirely fictional — `/artifacts`, `/artifacts/{id}/scan`,
 * `/risks` do not exist anywhere in the backend. The real routes are
 * `/provenances` (record), `/provenances/{id}` (get),
 * `/provenances/{id}/verify`, `/provenances/{id}/manual-reset`,
 * `/provenances/{id}/mbom`, `/discovery-scans` — verified against
 * `backend/src/ai_supply_chain/api/v1/routes.py` and the real
 * `ModelProvenanceDTO`/`MBOMDTO`/`DiscoveryScanRunDTO` dataclasses.
 *
 * This context is command/get-by-id only — there is NO list/query
 * endpoint for provenance records here. The real list surface lives
 * in `ai_posture`'s `/reports/supply-chain-integrity` read-model
 * (see `lib/ai-posture.ts`), which is populated from this context's
 * domain events. This client is therefore a detail/action client, not
 * a list client — consistent with what the backend actually supports.
 */
import { api } from "@/lib/api";

export interface ModelProvenance {
  provenance_id: string;
  tenant_id: string;
  ai_system_asset_id: string;
  model_origin: string;
  integrity_status: string;
  operational_status: string;
  artifact_size_bytes: number;
  verification_method_latest: string | null;
  trust_delegation_note_latest: string;
  chain_entry_count: number;
  consecutive_failures: number;
}

export interface MBOM {
  mbom_id: string;
  provenance_id: string;
  completed: boolean;
  components: Record<string, unknown>[];
}

export interface DiscoveryScanRun {
  scan_run_id: string;
  state: string;
  partial: boolean;
  discovered_count: number;
  unmatched_count: number;
  failed_partitions: string[];
  api_calls_used: number;
}

export function getProvenance(provenanceId: string): Promise<ModelProvenance> {
  return api.get<ModelProvenance>(`/api/v1/ai-supply-chain/provenances/${provenanceId}`);
}

export function verifyProvenance(
  provenanceId: string,
  body: {
    retrieval_uri: string;
    provider_reported_checksum?: string;
    signature_provider?: string;
    signature_location?: string;
    signing_key_fingerprint?: string;
  }
): Promise<ModelProvenance> {
  return api.post<ModelProvenance>(`/api/v1/ai-supply-chain/provenances/${provenanceId}/verify`, body);
}

export function manualResetVerification(provenanceId: string): Promise<ModelProvenance> {
  return api.post<ModelProvenance>(`/api/v1/ai-supply-chain/provenances/${provenanceId}/manual-reset`, {});
}

export function recordProvenance(body: {
  asset_id: string;
  model_origin: string;
  artifact_size_bytes: number;
  registry_provider?: string;
  registry_id?: string;
  training_data_description?: string;
}): Promise<ModelProvenance> {
  return api.post<ModelProvenance>("/api/v1/ai-supply-chain/provenances", body);
}

export function runDiscoveryScan(body: {
  sources?: string[];
  cloud_accounts?: string[];
}): Promise<DiscoveryScanRun> {
  return api.post<DiscoveryScanRun>("/api/v1/ai-supply-chain/discovery-scans", body);
}
