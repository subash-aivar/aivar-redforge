import { api } from "@/lib/api";

export interface ModelArtifact {
  artifact_id: string;
  tenant_id: string;
  name: string;
  version: string;
  registry: string;
  status: string;
  risk_score: number;
  licenses: string[];
  dependencies: string[];
  vulnerabilities: number;
  last_scanned_at: string | null;
  created_at: string;
}

export interface SupplyChainRisk {
  risk_id: string;
  artifact_id: string;
  risk_type: string;
  severity: string;
  description: string;
  detected_at: string;
  status: string;
}

export function listArtifacts(): Promise<ModelArtifact[]> {
  return api.get<ModelArtifact[]>("/api/v1/ai-supply-chain/artifacts");
}

export function getArtifact(id: string): Promise<ModelArtifact> {
  return api.get<ModelArtifact>(`/api/v1/ai-supply-chain/artifacts/${id}`);
}

export function scanArtifact(id: string): Promise<{ scan_id: string; status: string }> {
  return api.post(`/api/v1/ai-supply-chain/artifacts/${id}/scan`, {});
}

export function listRisks(artifactId?: string): Promise<SupplyChainRisk[]> {
  const q = artifactId ? `?artifact_id=${artifactId}` : "";
  return api.get<SupplyChainRisk[]>(`/api/v1/ai-supply-chain/risks${q}`);
}
