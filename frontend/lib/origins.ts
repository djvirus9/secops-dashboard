/** Parse deployment configuration without trusting client-controlled proxy headers. */
export function dashboardOrigins(value = "http://localhost:5000"): Set<string> {
  const entries = value.split(",").map((entry) => entry.trim());
  if (!entries.length || entries.some((entry) => !entry)) throw new Error("DASHBOARD_ORIGINS is empty");
  return new Set(entries.map((entry) => {
    const url = new URL(entry);
    if (!/^https?:$/.test(url.protocol) || url.username || url.password ||
        url.pathname !== "/" || url.search || url.hash ||
        (entry !== url.origin && entry !== `${url.origin}/`)) {
      throw new Error("DASHBOARD_ORIGINS must contain only canonical HTTP or HTTPS origins");
    }
    return url.origin;
  }));
}

export function isTrustedMutation(headers: Headers, allowedOrigins: Set<string>): boolean {
  // Session cookies are ambient browser credentials. Require Origin even if
  // Fetch Metadata is absent; null/sandboxed origins and cross-site forms fail closed.
  const origin = headers.get("origin");
  if (!origin || headers.get("sec-fetch-site") === "cross-site") return false;
  try {
    return new URL(origin).origin === origin && allowedOrigins.has(origin);
  } catch {
    return false;
  }
}
