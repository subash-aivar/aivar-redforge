import { api } from "@/lib/api";

export interface LessonsLearnedReview {
  review_id: string;
  tenant_id: string;
  incident_id: string;
  status: string;
  technique_ids: string[];
  lessons: Lesson[];
  actions: Action[];
  created_at: string;
}

export interface Lesson {
  lesson_id: string;
  category: string;
  description: string;
  impact_summary: string;
}

export interface Action {
  action_id: string;
  title: string;
  description: string;
  owner: string;
  priority: string;
  status: string;
}

export function listReviews(): Promise<LessonsLearnedReview[]> {
  return api.get<LessonsLearnedReview[]>("/api/v1/lessons-learned");
}

export function getReview(reviewId: string): Promise<LessonsLearnedReview> {
  return api.get<LessonsLearnedReview>(`/api/v1/lessons-learned/${reviewId}`);
}

export function createReview(incidentId: string, techniqueIds: string[] = []): Promise<LessonsLearnedReview> {
  return api.post<LessonsLearnedReview>("/api/v1/lessons-learned", {
    incident_id: incidentId,
    technique_ids: techniqueIds,
  });
}

export function addLesson(reviewId: string, lesson: { category: string; description: string; impact_summary: string }): Promise<LessonsLearnedReview> {
  return api.post<LessonsLearnedReview>(`/api/v1/lessons-learned/${reviewId}/lessons`, lesson);
}

export function addAction(reviewId: string, action: { title: string; description: string; owner: string; priority: string }): Promise<LessonsLearnedReview> {
  return api.post<LessonsLearnedReview>(`/api/v1/lessons-learned/${reviewId}/actions`, action);
}

export function finalizeReview(reviewId: string): Promise<LessonsLearnedReview> {
  return api.post<LessonsLearnedReview>(`/api/v1/lessons-learned/${reviewId}/finalize`, {});
}
