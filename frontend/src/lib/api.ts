/**
 * AIVAR RedForge — Canonical API transport layer.
 *
 * Single point of contact with the backend.
 * Handles: authentication headers, error normalization, token lifecycle.
 */

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export class ApiError extends Error {
  constructor(
    public status: number,
    public code: string,
    message: string,
    public details?: unknown
  ) {
    super(message);
    this.name = "ApiError";
  }
}

function getToken(): string | null {
  if (typeof window === "undefined") return null;
  return sessionStorage.getItem("redforge_token");
}

/**
 * Exposed for callers that must construct their own request (e.g. the
 * Security Operations SSE stream client, which reads a raw fetch()
 * ReadableStream rather than going through request<T>() above) but
 * still need the exact same Authorization header this module already
 * uses everywhere else. Never put this value in a URL/query string.
 */
export function getAuthHeader(): Record<string, string> {
  const token = getToken();
  return token ? { Authorization: `Bearer ${token}` } : {};
}

export function getApiBase(): string {
  return API_BASE;
}

export function setToken(token: string): void {
  sessionStorage.setItem("redforge_token", token);
}

export function clearToken(): void {
  sessionStorage.removeItem("redforge_token");
}

export function isAuthenticated(): boolean {
  return !!getToken();
}

const ORG_KEY = "redforge_org_id";

export function setOrganizationId(orgId: string): void {
  sessionStorage.setItem(ORG_KEY, orgId);
}

export function getOrganizationId(): string | null {
  if (typeof window === "undefined") return null;
  return sessionStorage.getItem(ORG_KEY);
}

export function clearOrganizationId(): void {
  sessionStorage.removeItem(ORG_KEY);
}

export function clearSession(): void {
  clearToken();
  clearOrganizationId();
}

async function request<T>(
  method: string,
  path: string,
  body?: unknown,
  extraHeaders?: Record<string, string>
): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...extraHeaders,
  };
  const token = getToken();
  if (token) {
    headers["Authorization"] = `Bearer ${token}`;
  }

  const res = await fetch(`${API_BASE}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  if (!res.ok) {
    let errBody: any = {};
    try {
      errBody = await res.json();
    } catch {
      /* empty */
    }
    const msg =
      errBody?.error?.message || errBody?.detail || res.statusText;
    const code = errBody?.error?.code || `HTTP_${res.status}`;
    throw new ApiError(res.status, code, msg, errBody);
  }

  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

export const api = {
  get: <T>(path: string) => request<T>("GET", path),
  post: <T>(path: string, body?: unknown, extraHeaders?: Record<string, string>) =>
    request<T>("POST", path, body, extraHeaders),
  patch: <T>(path: string, body?: unknown) => request<T>("PATCH", path, body),
  delete: <T>(path: string) => request<T>("DELETE", path),
};
