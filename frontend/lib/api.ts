async function throwApiError(res: Response, method: string, path: string): Promise<never> {
  const body = await res.json().catch(() => null);
  const detail = body && typeof body.detail === "string" ? body.detail : `HTTP ${res.status}`;
  throw new Error(`${method} ${path} failed: ${detail}`);
}

export async function apiGet<T>(path: string): Promise<T> {
  const res = await fetch(`/api${path}`, { cache: "no-store" });
  if (!res.ok) return throwApiError(res, "GET", path);
  return res.json();
}

export async function apiPost<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`/api${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) return throwApiError(res, "POST", path);
  return res.json();
}

export async function apiPatch<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`/api${path}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) return throwApiError(res, "PATCH", path);
  return res.json();
}
