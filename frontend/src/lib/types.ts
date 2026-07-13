/**
 * AIVAR RedForge — Frontend type definitions derived from real backend contracts.
 */

export interface Target {
  id: string;
  organization_id: string;
  name: string;
  description: string;
  target_type: string;
  provider: string;
  endpoint: string;
  status: string;
  tags: string[];
  created_at: string;
  updated_at: string;
}

export interface Finding {
  id: string;
  organization_id: string;
  run_id: string;
  target_id: string;
  evidence_ids: string[];
  title: string;
  description: string;
  severity: string;
  risk_score: number;
  status: string;
  recommendation: string;
  created_at: string;
  updated_at: string;
}

export interface Evidence {
  id: string;
  organization_id: string;
  run_id: string;
  target_id: string;
  attack_id: string;
  attack_type: string;
  result: string;
  confidence: number;
  request_url: string;
  response_status: number;
  duration_ms: number;
  finalized: boolean;
  created_at: string;
}

export interface RiskIncident {
  id: string;
  title: string;
  severity: string;
  score: number;
  status: string;
  affected_targets: string[];
  finding_ids: string[];
  created_at: string;
}

export interface Campaign {
  campaign_id: string;
  graph_id: string;
  organization_id: string;
  target_id: string;
  state: string;
  total_nodes: number;
  nodes_executed: number;
  nodes_completed: number;
  nodes_failed: number;
  created_at?: string;
}

export interface RuntimeHealth {
  status: string;
  version: string;
  timestamp: string;
}

export interface ReadinessCheck {
  status: string;
  checks: Record<string, string>;
}
