import { api } from "@/lib/api";

// Verified against `backend/src/lessons_learned/api/v1/routes.py` and
// `LessonsApplicationService.get`/`create_for_incident` (application/
// services/lessons_application_service.py) — the real read model is
// keyed by `incident_id` only (`GET /lessons-learned/incident/{id}`);
// there is no list-all-reviews endpoint, and `lessons`/`actions` are
// integer counts on read, not full nested objects.

export interface LessonsLearnedRecord {
  ll_id: string;
  status: string;
  incident_id: string;
  lessons: number;
  actions: number;
  quality_score: number;
  techniques: string[];
}

export function getForIncident(incidentId: string): Promise<LessonsLearnedRecord> {
  return api.get<LessonsLearnedRecord>(`/api/v1/lessons-learned/incident/${incidentId}`);
}

export function createReview(
  incidentId: string,
  techniqueIds: string[] = []
): Promise<{ ll_id: string; status: string }> {
  return api.post<{ ll_id: string; status: string }>("/api/v1/lessons-learned", {
    incident_id: incidentId,
    technique_ids: techniqueIds,
  });
}

export function addLesson(
  llId: string,
  lesson: { category: string; description: string; impact_summary: string }
): Promise<unknown> {
  return api.post(`/api/v1/lessons-learned/${llId}/lessons`, lesson);
}

export function addAction(
  llId: string,
  action: { title: string; description: string; owner: string; priority: string }
): Promise<unknown> {
  return api.post(`/api/v1/lessons-learned/${llId}/actions`, action);
}

export function finalizeReview(llId: string, actor = "ui"): Promise<unknown> {
  return api.post(`/api/v1/lessons-learned/${llId}/finalize`, { actor });
}
