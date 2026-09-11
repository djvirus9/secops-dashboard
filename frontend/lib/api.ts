export class ApiError extends Error {
  constructor(message: string, public status: number) { super(message); }
}
async function throwApiError(res: Response, method: string, path: string): Promise<never> {
  const body = await res.json().catch(() => null);
  const detail = body && typeof body.detail === "string" ? body.detail
    : Array.isArray(body?.detail) ? body.detail.map((issue: { loc?: string[]; msg?: string }) =>
      `${issue.loc?.slice(1).join(".") || "Request"}: ${issue.msg || "Invalid value"}`).join("; ")
    : `HTTP ${res.status}`;
  if (res.status === 401 && path !== "/auth/login" && typeof window !== "undefined") window.dispatchEvent(new Event("secops:unauthorized"));
  throw new ApiError(detail || `${method} ${path} failed`, res.status);
}

const STATIC_API_PATHS = new Map<string, string>([
  ["/assets", "/api/assets"],
  ["/assets/upsert", "/api/assets/upsert"],
  ["/dashboard/summary", "/api/dashboard/summary"],
  ["/findings", "/api/findings"],
  ["/import/scan", "/api/import/scan"],
  ["/ingest/signal", "/api/ingest/signal"],
  ["/integrations", "/api/integrations"],
  ["/integrations/slack/test", "/api/integrations/slack/test"],
  ["/parsers", "/api/parsers"],
  ["/health", "/api/health"],
  ["/risks", "/api/risks"],
  ["/imports", "/api/imports"],
  ["/notifications", "/api/notifications"],
  ["/scanner-tokens", "/api/scanner-tokens"],
  ["/github-sync", "/api/github-sync"],
  ...["/auth/login", "/auth/logout", "/auth/me", "/auth/password", "/users", "/saved-views", "/findings/bulk", "/findings/export.csv"].map((path): [string, string] => [path, `/api${path}`]),
]);
const FINDING_PATH =
  /^\/findings\/([0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})(\/comments)?$/i;

function toApiUrl(path: string): string {
  const managedPath = /^\/(scanner-tokens|github-sync)\/([0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})(?:\/(revoke|rotate|sync|runs))?$/i.exec(path);
  if (managedPath) {
    const [, resource, id, action] = managedPath;
    if (resource === "scanner-tokens" && ["revoke", "rotate"].includes(action)) return `/api/scanner-tokens/${encodeURIComponent(id)}/${action}`;
    if (resource === "github-sync" && (!action || ["sync", "runs"].includes(action))) return `/api/github-sync/${encodeURIComponent(id)}${action ? `/${action}` : ""}`;
    throw new Error("Unsupported API path");
  }
  if (/^\/(users|saved-views)\/[0-9a-f-]{36}$/i.test(path)) return `/api${path}`;
  const retryPath = /^\/notifications\/([0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})\/retry$/i.exec(path);
  if (retryPath) return `/api/notifications/${encodeURIComponent(retryPath[1])}/retry`;
  const staticPath = STATIC_API_PATHS.get(path);
  if (staticPath) return staticPath;

  const findingPath = FINDING_PATH.exec(path);
  if (!findingPath) {
    throw new Error("Unsupported API path");
  }

  const findingId = encodeURIComponent(findingPath[1]);
  const suffix = findingPath[2] === "/comments" ? "/comments" : "";
  return `/api/findings/${findingId}${suffix}`;
}

export type ApiQuery = Record<string, string | number | undefined>;

export async function apiGet<T>(path: string, options: { query?: ApiQuery; signal?: AbortSignal } = {}): Promise<T> {
  const query = new URLSearchParams();
  Object.entries(options.query || {}).forEach(([key, value]) => {
    if (value !== undefined && value !== "") query.set(key, String(value));
  });
  const url = toApiUrl(path) + (query.size ? `?${query}` : "");
  const res = await fetch(url, { cache: "no-store", signal: options.signal });
  if (!res.ok) return throwApiError(res, "GET", path);
  return res.json();
}

export async function apiPost<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(toApiUrl(path), {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) return throwApiError(res, "POST", path);
  return res.json();
}

export async function apiPatch<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(toApiUrl(path), {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) return throwApiError(res, "PATCH", path);
  return res.json();
}

export async function apiDelete(path: string): Promise<void> {
  const res = await fetch(toApiUrl(path), { method: "DELETE" });
  if (!res.ok) return throwApiError(res, "DELETE", path);
}
export async function downloadFindings(query: ApiQuery): Promise<void> {
  const params = new URLSearchParams();
  Object.entries(query).forEach(([key, value]) => { if (value !== undefined && value !== "") params.set(key, String(value)); });
  const response = await fetch(`${toApiUrl("/findings/export.csv")}?${params}`, { cache: "no-store" });
  if (!response.ok) return throwApiError(response, "GET", "/findings/export.csv");
  const url = URL.createObjectURL(await response.blob());
  const link = document.createElement("a");
  link.href = url; link.download = "secops-findings.csv";
  document.body.append(link); link.click(); link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
