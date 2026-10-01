/**
 * Thin fetch wrapper for the SentinelIQ API. Every JSON body in/out is
 * camelCase (see docs/API.md). Auth uses a short-lived JWT bearer token plus a
 * refresh token, both held in the Zustand auth store (src/store/authStore.ts).
 *
 * Transparent refresh: a 401 on any request triggers one attempt to exchange
 * the refresh token, then replays the original request. Without this an analyst
 * is silently logged out mid-investigation every time the access token expires.
 *
 * Concurrent 401s share a single in-flight refresh (`refreshPromise`). Firing
 * one refresh per failed request would be worse than useless -- refresh rotation
 * is single-use server-side, so the second exchange would look like a replay and
 * the backend would revoke the whole session family as suspected token theft.
 */
import { useAuthStore } from "../store/authStore";
import type { TokenResponse } from "./types";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "/v1";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
    this.name = "ApiError";
  }
}

let refreshPromise: Promise<boolean> | null = null;

async function performRefresh(): Promise<boolean> {
  const { refreshToken, setSession, logout } = useAuthStore.getState();
  if (!refreshToken) {
    logout();
    return false;
  }

  try {
    const response = await fetch(`${API_BASE_URL}/auth/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refreshToken }),
    });
    if (!response.ok) {
      logout();
      return false;
    }
    const body = (await response.json()) as TokenResponse;
    setSession({
      accessToken: body.accessToken,
      refreshToken: body.refreshToken,
      tenantId: body.tenantId,
      userId: body.userId,
      role: body.role,
    });
    return true;
  } catch {
    logout();
    return false;
  }
}

function refreshSession(): Promise<boolean> {
  if (!refreshPromise) {
    refreshPromise = performRefresh().finally(() => {
      refreshPromise = null;
    });
  }
  return refreshPromise;
}

async function toApiError(response: Response): Promise<ApiError> {
  let detail = response.statusText;
  try {
    const body = await response.json();
    if (typeof body.detail === "string") {
      detail = body.detail;
    } else if (Array.isArray(body.detail)) {
      // FastAPI 422 validation errors arrive as a list of per-field objects;
      // showing "[object Object]" to a user is not a message.
      detail = body.detail
        .map((entry: { loc?: unknown[]; msg?: string }) => {
          const field = Array.isArray(entry.loc) ? entry.loc.slice(1).join(".") : "";
          return field ? `${field}: ${entry.msg}` : entry.msg;
        })
        .filter(Boolean)
        .join("; ");
    }
  } catch {
    // response body wasn't JSON; keep statusText
  }
  return new ApiError(response.status, detail);
}

async function send(path: string, options: RequestInit): Promise<Response> {
  const token = useAuthStore.getState().accessToken;
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options.headers as Record<string, string> | undefined),
  };
  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }
  return fetch(`${API_BASE_URL}${path}`, { ...options, headers });
}

async function request<T>(path: string, options: RequestInit = {}, allowRetry = true): Promise<T> {
  let response = await send(path, options);

  if (response.status === 401 && allowRetry && useAuthStore.getState().refreshToken) {
    const refreshed = await refreshSession();
    if (refreshed) {
      response = await send(path, options);
    }
  }

  if (response.status === 401) {
    useAuthStore.getState().logout();
  }

  if (!response.ok) {
    throw await toApiError(response);
  }

  if (response.status === 204) {
    return undefined as T;
  }
  return (await response.json()) as T;
}

export const api = {
  get: <T>(path: string) => request<T>(path, { method: "GET" }),
  post: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: "POST", body: body !== undefined ? JSON.stringify(body) : undefined }),
  patch: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: "PATCH", body: body !== undefined ? JSON.stringify(body) : undefined }),
  put: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: "PUT", body: body !== undefined ? JSON.stringify(body) : undefined }),
  delete: <T>(path: string) => request<T>(path, { method: "DELETE" }),
  /** Absolute URL for a server-provided path (e.g. a signed report download). */
  absoluteUrl: (path: string) =>
    path.startsWith("http") ? path : `${API_BASE_URL}${path.replace(/^\/v1/, "")}`,
};

/** Build a query string from defined, non-empty values only. */
export function queryString(params: Record<string, string | number | boolean | undefined | null>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") {
      search.set(key, String(value));
    }
  }
  const rendered = search.toString();
  return rendered ? `?${rendered}` : "";
}
