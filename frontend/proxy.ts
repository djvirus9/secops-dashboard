import { NextRequest, NextResponse } from "next/server";
import { dashboardOrigins, isTrustedMutation } from "./lib/origins";

export function proxy(request: NextRequest): NextResponse {
  let origins: Set<string>;
  let destination: URL;
  try {
    origins = dashboardOrigins(process.env.DASHBOARD_ORIGINS);
    destination = new URL(process.env.BACKEND_URL || "http://localhost:8000");
    if (!/^https?:$/.test(destination.protocol) || destination.username || destination.password || destination.search || destination.hash) throw new Error();
  } catch {
    return NextResponse.json({ detail: "Dashboard origins or backend URL are invalid" }, { status: 503 });
  }
  if (request.nextUrl.pathname === "/_health") return NextResponse.json({ status: "ok" });
  if (!["GET", "HEAD", "OPTIONS"].includes(request.method.toUpperCase()) && !isTrustedMutation(request.headers, origins)) {
    return NextResponse.json({ detail: "Cross-origin state change rejected" }, { status: 403 });
  }
  if (!request.nextUrl.pathname.startsWith("/api/")) {
    if (request.nextUrl.pathname !== "/login" && !request.cookies.has("secops_session")) {
      // Next requires an absolute redirect URL. Choose only a configured origin;
      // a supplied Host can select an allowlisted host, never add a new one.
      const origin = [...origins].find(value => new URL(value).host === request.headers.get("host")) || [...origins][0];
      const login = new URL("/login", origin);
      login.searchParams.set("next", request.nextUrl.pathname + request.nextUrl.search);
      const response = NextResponse.redirect(login);
      response.headers.set("Cache-Control", "no-store");
      return response;
    }
    const response = NextResponse.next();
    response.headers.set("Cache-Control", "no-store");
    return response;
  }
  destination.pathname = destination.pathname.replace(/\/$/, "") + request.nextUrl.pathname.slice(4);
  destination.search = request.nextUrl.search;
  const headers = new Headers(request.headers);
  for (const name of ["authorization", "x-api-key", "x-secops-user", "host"]) headers.delete(name);
  // The API authenticates the cookie and enforces project permissions. Browser
  // requests never acquire administrative API-key privileges at this proxy.
  const session = request.cookies.get("secops_session");
  headers.delete("cookie");
  if (session) headers.set("cookie", `secops_session=${encodeURIComponent(session.value)}`);
  const response = NextResponse.rewrite(destination, { request: { headers } });
  response.headers.set("Cache-Control", "no-store");
  return response;
}
export const config = { matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"] };
