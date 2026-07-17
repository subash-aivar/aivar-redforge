/**
 * Compliance Operations Console API client — M24 Phase 4.
 *
 * organization_id is never sent by the client — the backend derives it
 * from the caller's verified token. No business rules live here; this
 * module only types and transports existing Phase 1–3 HTTP contracts.
 */
import { api } from "./api";

// ── Catalog (org read) ───────────────────────────────────────────────────────

export interface FrameworkMetadata {
  name: string;
  version: string;
  issuing_body: string;
  description: string;
  effective_date: string | null;
  tags: string[];
  external_url: string;
}

export interface FrameworkSummary {
  id: string;
  key: string;
  status: string;
  metadata: FrameworkMetadata;
  requirement_count: number;
  created_at: string;
  updated_at: string;
}

export interface ControlRequirement {
  id: string;
  framework_key: string;
  requirement_ref: string;
  title: string;
  description: string;
  domain: string;
  severity: string;
  guidance: string;
  policy_threshold: number;
  tags: string[];
  external_ref: string;
  created_at: string;
  updated_at: string;
}

export interface ControlMapping {
  id: string;
  source_requirement_id: string;
  target_requirement_id: string;
  source_framework_key: string;
  target_framework_key: string;
  confidence: string;
  rationale: string;
  version: string;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface Paginated<T> {
  items: T[];
  total: number;
  limit: number;
  offset: number;
}

export async function listFrameworks(): Promise<FrameworkSummary[]> {
  return api.get<FrameworkSummary[]>("/api/v1/compliance/frameworks");
}

export async function getFramework(key: string): Promise<FrameworkSummary> {
  return api.get<FrameworkSummary>(
    `/api/v1/compliance/frameworks/${encodeURIComponent(key)}`
  );
}

export async function listRequirements(
  frameworkKey: string,
  opts: { search?: string; limit?: number; offset?: number } = {}
): Promise<Paginated<ControlRequirement>> {
  const q = new URLSearchParams();
  if (opts.search) q.set("search", opts.search);
  if (opts.limit != null) q.set("limit", String(opts.limit));
  if (opts.offset != null) q.set("offset", String(opts.offset));
  const qs = q.toString();
  return api.get<Paginated<ControlRequirement>>(
    `/api/v1/compliance/requirements/${encodeURIComponent(frameworkKey)}${qs ? `?${qs}` : ""}`
  );
}

export async function getRequirement(
  frameworkKey: string,
  requirementId: string
): Promise<ControlRequirement> {
  return api.get<ControlRequirement>(
    `/api/v1/compliance/requirements/${encodeURIComponent(frameworkKey)}/${encodeURIComponent(requirementId)}`
  );
}

export async function listMappings(
  opts: {
    source_framework?: string;
    target_framework?: string;
    limit?: number;
    offset?: number;
  } = {}
): Promise<Paginated<ControlMapping>> {
  const q = new URLSearchParams();
  if (opts.source_framework) q.set("source_framework", opts.source_framework);
  if (opts.target_framework) q.set("target_framework", opts.target_framework);
  if (opts.limit != null) q.set("limit", String(opts.limit));
  if (opts.offset != null) q.set("offset", String(opts.offset));
  const qs = q.toString();
  return api.get<Paginated<ControlMapping>>(
    `/api/v1/compliance/mappings${qs ? `?${qs}` : ""}`
  );
}

// ── Organization assessment ──────────────────────────────────────────────────

export interface ComplianceProfile {
  id: string;
  organization_id: string;
  name: string;
  description: string;
  framework_keys: string[];
  status: string;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface AssessmentPeriod {
  id: string;
  organization_id: string;
  profile_id: string;
  name: string;
  framework_key: string;
  period_start: string;
  period_end: string;
  status: string;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface ConfirmedEvidenceLink {
  evidence_id: string;
  confirmed_by: string;
  confirmed_at: string;
  rationale: string;
}

export interface ControlAssessment {
  id: string;
  organization_id: string;
  profile_id: string;
  period_id: string;
  requirement_id: string;
  framework_key: string;
  status: string;
  evidence_links: ConfirmedEvidenceLink[];
  notes: string;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export async function listProfiles(): Promise<ComplianceProfile[]> {
  return api.get<ComplianceProfile[]>("/api/v1/compliance/profiles");
}

export async function getProfile(profileId: string): Promise<ComplianceProfile> {
  return api.get<ComplianceProfile>(
    `/api/v1/compliance/profiles/${encodeURIComponent(profileId)}`
  );
}

export async function listPeriods(profileId: string): Promise<AssessmentPeriod[]> {
  return api.get<AssessmentPeriod[]>(
    `/api/v1/compliance/profiles/${encodeURIComponent(profileId)}/periods`
  );
}

export async function getPeriod(periodId: string): Promise<AssessmentPeriod> {
  return api.get<AssessmentPeriod>(
    `/api/v1/compliance/periods/${encodeURIComponent(periodId)}`
  );
}

export async function listAssessments(periodId: string): Promise<ControlAssessment[]> {
  return api.get<ControlAssessment[]>(
    `/api/v1/compliance/periods/${encodeURIComponent(periodId)}/assessments`
  );
}

export async function getAssessment(
  assessmentId: string
): Promise<ControlAssessment> {
  return api.get<ControlAssessment>(
    `/api/v1/compliance/assessments/${encodeURIComponent(assessmentId)}`
  );
}

export async function beginEvidenceCollection(
  assessmentId: string
): Promise<ControlAssessment> {
  return api.post<ControlAssessment>(
    `/api/v1/compliance/assessments/${encodeURIComponent(assessmentId)}/begin-collection`,
    {}
  );
}

export async function submitForConfirmation(
  assessmentId: string
): Promise<ControlAssessment> {
  return api.post<ControlAssessment>(
    `/api/v1/compliance/assessments/${encodeURIComponent(assessmentId)}/submit-for-confirmation`,
    {}
  );
}

export async function technicallyValidate(
  assessmentId: string
): Promise<ControlAssessment> {
  return api.post<ControlAssessment>(
    `/api/v1/compliance/assessments/${encodeURIComponent(assessmentId)}/technically-validate`,
    {}
  );
}

export async function confirmEvidenceLink(
  assessmentId: string,
  body: { evidence_id: string; rationale?: string }
): Promise<ControlAssessment> {
  return api.post<ControlAssessment>(
    `/api/v1/compliance/assessments/${encodeURIComponent(assessmentId)}/evidence-links`,
    body
  );
}

// ── Recommendations ──────────────────────────────────────────────────────────

export interface EvidenceReference {
  source_kind: string;
  source_entity_id: string;
}

export interface EvidenceCandidate {
  reference: EvidenceReference;
  raw_score: number;
  rationale: string;
  signals: string[];
}

export interface RecommendationDecision {
  decided_by: string;
  decided_at: string;
  rationale: string;
}

export interface EvidenceRecommendation {
  id: string;
  organization_id: string;
  batch_id: string;
  assessment_id: string;
  period_id: string;
  requirement_id: string;
  framework_key: string;
  primary_reference: EvidenceReference;
  candidates: EvidenceCandidate[];
  confidence: string;
  score: number;
  rationale: string;
  status: string;
  dedup_key: string;
  decision: RecommendationDecision | null;
  linked_evidence_id: string | null;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface RecommendationList {
  items: EvidenceRecommendation[];
  total: number;
}

export interface RecommendationBatch {
  id: string;
  organization_id: string;
  period_id: string;
  assessment_id: string | null;
  generation_fingerprint: string;
  recommendation_ids: string[];
  created_count: number;
  updated_count: number;
  skipped_duplicate_count: number;
  generated_by: string;
  created_at: string;
}

export interface RecommendationStatistics {
  recommended: number;
  accepted: number;
  linked: number;
  rejected: number;
  total: number;
}

export async function generateRecommendations(
  periodId: string,
  body: { assessment_id?: string | null } = {}
): Promise<RecommendationBatch> {
  return api.post<RecommendationBatch>(
    `/api/v1/compliance/periods/${encodeURIComponent(periodId)}/recommendations/generate`,
    body
  );
}

export async function listPeriodRecommendations(
  periodId: string,
  opts: { status?: string; limit?: number; offset?: number } = {}
): Promise<RecommendationList> {
  const q = new URLSearchParams();
  if (opts.status) q.set("status", opts.status);
  if (opts.limit != null) q.set("limit", String(opts.limit));
  if (opts.offset != null) q.set("offset", String(opts.offset));
  const qs = q.toString();
  return api.get<RecommendationList>(
    `/api/v1/compliance/periods/${encodeURIComponent(periodId)}/recommendations${qs ? `?${qs}` : ""}`
  );
}

export async function listAssessmentRecommendations(
  assessmentId: string,
  opts: { status?: string; limit?: number; offset?: number } = {}
): Promise<RecommendationList> {
  const q = new URLSearchParams();
  if (opts.status) q.set("status", opts.status);
  if (opts.limit != null) q.set("limit", String(opts.limit));
  if (opts.offset != null) q.set("offset", String(opts.offset));
  const qs = q.toString();
  return api.get<RecommendationList>(
    `/api/v1/compliance/assessments/${encodeURIComponent(assessmentId)}/recommendations${qs ? `?${qs}` : ""}`
  );
}

export async function getRecommendation(
  recommendationId: string
): Promise<EvidenceRecommendation> {
  return api.get<EvidenceRecommendation>(
    `/api/v1/compliance/recommendations/${encodeURIComponent(recommendationId)}`
  );
}

export async function acceptRecommendation(
  recommendationId: string,
  rationale = ""
): Promise<EvidenceRecommendation> {
  return api.post<EvidenceRecommendation>(
    `/api/v1/compliance/recommendations/${encodeURIComponent(recommendationId)}/accept`,
    { rationale }
  );
}

export async function rejectRecommendation(
  recommendationId: string,
  rationale = ""
): Promise<EvidenceRecommendation> {
  return api.post<EvidenceRecommendation>(
    `/api/v1/compliance/recommendations/${encodeURIComponent(recommendationId)}/reject`,
    { rationale }
  );
}

export async function linkRecommendation(
  recommendationId: string,
  rationale = ""
): Promise<EvidenceRecommendation> {
  return api.post<EvidenceRecommendation>(
    `/api/v1/compliance/recommendations/${encodeURIComponent(recommendationId)}/link`,
    { rationale }
  );
}

export async function listRecommendationHistory(
  opts: { limit?: number; offset?: number } = {}
): Promise<RecommendationList> {
  const q = new URLSearchParams();
  if (opts.limit != null) q.set("limit", String(opts.limit));
  if (opts.offset != null) q.set("offset", String(opts.offset));
  const qs = q.toString();
  return api.get<RecommendationList>(
    `/api/v1/compliance/recommendations/history${qs ? `?${qs}` : ""}`
  );
}

export async function getRecommendationStatistics(
  periodId?: string
): Promise<RecommendationStatistics> {
  const q = periodId
    ? `?period_id=${encodeURIComponent(periodId)}`
    : "";
  return api.get<RecommendationStatistics>(
    `/api/v1/compliance/recommendations/statistics${q}`
  );
}

// ── Console read models (additive, paginated) ────────────────────────────────

export interface ConsoleOverview {
  profiles: number;
  open_periods: number;
  assessments_total: number;
  validated_count: number;
  posture_score: number;
  posture_band: string;
  status_counts: Record<string, number>;
  evidence_link_count: number;
  assessments_with_evidence: number;
  recommendation_counts: RecommendationStatistics;
  acceptance_pct: number;
  framework_progress: {
    framework_key: string;
    total: number;
    validated: number;
    coverage_pct: number;
  }[];
  open_period_summaries: {
    id: string;
    name: string;
    framework_key: string;
    period_start: string;
    period_end: string;
    status: string;
  }[];
  recently_validated: {
    id: string;
    framework_key: string;
    requirement_id: string;
    status: string;
    evidence_count: number;
    updated_at: string;
  }[];
}

export interface ConsoleEvidenceRow {
  id: string;
  category: string;
  source_kind: string;
  entity_id: string;
  assessment_id: string | null;
  recommendation_id: string | null;
  status: string;
  confidence: string | null;
  updated_at: string | null;
  rationale: string;
}

export interface ConsoleTimelineEvent {
  id: string;
  at: string | null;
  kind: string;
  title: string;
  detail: string;
  href: string | null;
}

export interface ConsoleAnalytics {
  posture_score: number;
  posture_band: string;
  validated_count: number;
  assessments_total: number;
  evidence_link_count: number;
  acceptance_pct: number;
  status_distribution: { label: string; value: number }[];
  framework_coverage: { label: string; value: number }[];
  recommendation_acceptance_mix: { label: string; value: number }[];
  evidence_growth: { label: string; value: number }[];
  validation_velocity: { label: string; value: number }[];
  compliance_trend: { label: string; value: number }[];
  recommendation_counts: RecommendationStatistics;
}

export interface ConsoleListParams {
  search?: string;
  sort?: string;
  sort_dir?: "asc" | "desc";
  limit?: number;
  offset?: number;
}

function appendListParams(q: URLSearchParams, opts: ConsoleListParams): void {
  if (opts.search) q.set("search", opts.search);
  if (opts.sort) q.set("sort", opts.sort);
  if (opts.sort_dir) q.set("sort_dir", opts.sort_dir);
  if (opts.limit != null) q.set("limit", String(opts.limit));
  if (opts.offset != null) q.set("offset", String(opts.offset));
}

export async function getConsoleOverview(): Promise<ConsoleOverview> {
  return api.get<ConsoleOverview>("/api/v1/compliance/console/overview");
}

export async function listConsoleAssessments(
  opts: ConsoleListParams & {
    period_id?: string;
    status?: string;
    framework_key?: string;
  } = {}
): Promise<Paginated<ControlAssessment>> {
  const q = new URLSearchParams();
  if (opts.period_id) q.set("period_id", opts.period_id);
  if (opts.status) q.set("status", opts.status);
  if (opts.framework_key) q.set("framework_key", opts.framework_key);
  appendListParams(q, opts);
  const qs = q.toString();
  return api.get<Paginated<ControlAssessment>>(
    `/api/v1/compliance/console/assessments${qs ? `?${qs}` : ""}`
  );
}

export async function listConsoleRecommendations(
  opts: ConsoleListParams & {
    status?: string;
    confidence?: string;
    framework_key?: string;
    assessment_id?: string;
    period_id?: string;
  } = {}
): Promise<Paginated<EvidenceRecommendation>> {
  const q = new URLSearchParams();
  if (opts.status) q.set("status", opts.status);
  if (opts.confidence) q.set("confidence", opts.confidence);
  if (opts.framework_key) q.set("framework_key", opts.framework_key);
  if (opts.assessment_id) q.set("assessment_id", opts.assessment_id);
  if (opts.period_id) q.set("period_id", opts.period_id);
  appendListParams(q, opts);
  const qs = q.toString();
  return api.get<Paginated<EvidenceRecommendation>>(
    `/api/v1/compliance/console/recommendations${qs ? `?${qs}` : ""}`
  );
}

export async function listConsoleEvidence(
  opts: ConsoleListParams & { category?: string } = {}
): Promise<Paginated<ConsoleEvidenceRow>> {
  const q = new URLSearchParams();
  if (opts.category) q.set("category", opts.category);
  appendListParams(q, opts);
  const qs = q.toString();
  return api.get<Paginated<ConsoleEvidenceRow>>(
    `/api/v1/compliance/console/evidence${qs ? `?${qs}` : ""}`
  );
}

export async function listConsoleTimeline(
  opts: {
    kind?: string;
    search?: string;
    limit?: number;
    offset?: number;
  } = {}
): Promise<Paginated<ConsoleTimelineEvent>> {
  const q = new URLSearchParams();
  if (opts.kind) q.set("kind", opts.kind);
  if (opts.search) q.set("search", opts.search);
  if (opts.limit != null) q.set("limit", String(opts.limit));
  if (opts.offset != null) q.set("offset", String(opts.offset));
  const qs = q.toString();
  return api.get<Paginated<ConsoleTimelineEvent>>(
    `/api/v1/compliance/console/timeline${qs ? `?${qs}` : ""}`
  );
}

export async function getConsoleAnalytics(): Promise<ConsoleAnalytics> {
  return api.get<ConsoleAnalytics>("/api/v1/compliance/console/analytics");
}
