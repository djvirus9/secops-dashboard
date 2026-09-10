import { NextRequest, NextResponse } from "next/server";
import { dashboardOrigins, isConfiguredSecret, isTrustedMutation } from "./lib/origins";

function safeEqual(left: string, right: string): boolean {
  const maxLength = Math.max(left.length, right.length);
  let mismatch = left.length ^ right.length;
  for (let index = 0; index < maxLength; index += 1) {
    mismatch |= (left.charCodeAt(index) || 0) ^ (right.charCodeAt(index) || 0);
  }
  return mismatch === 0;
}

function readBasicCredentials(header: string | null): [string, string] | null {
  if (!header?.startsWith("Basic ")) return null;
  try {
    const decoded = new TextDecoder("utf-8", { fatal: true }).decode(
      Uint8Array.from(atob(header.slice(6)), (character) => character.charCodeAt(0))
    );
    const separator = decoded.indexOf(":");
    if (separator < 0) return null;
    return [decoded.slice(0, separator), decoded.slice(separator + 1)];
  } catch {
    return null;
  }
}

function unauthorized(): NextResponse {
  return new NextResponse("Authentication required", {
    status: 401,
    headers: {
      "Cache-Control": "no-store",
      "WWW-Authenticate": 'Basic realm="SecOps Dashboard", charset="UTF-8"',
    },
  });
}

function isUnsafeMethod(method: string): boolean {
  return !["GET", "HEAD", "OPTIONS"].includes(method.toUpperCase());
}

export function proxy(request: NextRequest): NextResponse {
  const expectedUser = process.env.DASHBOARD_USERNAME || "";
  const expectedPassword = process.env.DASHBOARD_PASSWORD || "";
  if (!expectedUser || !isConfiguredSecret(expectedPassword, 24) || !isConfiguredSecret(process.env.API_KEY || "", 32)) {
    return NextResponse.json(
      { detail: "Dashboard authentication is not securely configured" },
      { status: 503, headers: { "Cache-Control": "no-store" } }
    );
  }

  let allowedOrigins: Set<string>;
  try {
    allowedOrigins = dashboardOrigins(process.env.DASHBOARD_ORIGINS);
  } catch {
    return NextResponse.json(
      { detail: "Dashboard origins are not configured correctly" },
      { status: 503, headers: { "Cache-Control": "no-store" } }
    );
  }
  if (request.nextUrl.pathname === "/_health") return NextResponse.json({ status: "ok" });

  const credentials = readBasicCredentials(request.headers.get("authorization"));
  if (
    !credentials ||
    !safeEqual(credentials[0], expectedUser) ||
    !safeEqual(credentials[1], expectedPassword)
  ) {
    return unauthorized();
  }

  if (isUnsafeMethod(request.method) && !isTrustedMutation(request.headers, allowedOrigins)) {
    return NextResponse.json(
      { detail: "Cross-origin state change rejected" },
      { status: 403, headers: { "Cache-Control": "no-store" } }
    );
  }

  if (!request.nextUrl.pathname.startsWith("/api/")) {
    const response = NextResponse.next();
    response.headers.set("Cache-Control", "no-store");
    return response;
  }

  const backendUrl = process.env.BACKEND_URL || "http://localhost:8000";
  const apiKey = process.env.API_KEY || "";
  if (!apiKey) {
    return NextResponse.json(
      { detail: "Backend API authentication is not configured" },
      { status: 503, headers: { "Cache-Control": "no-store" } }
    );
  }

  let destination: URL;
  try {
    destination = new URL(backendUrl);
  } catch {
    return NextResponse.json(
      { detail: "Backend URL is invalid" },
      { status: 503, headers: { "Cache-Control": "no-store" } }
    );
  }

  if (!["http:", "https:"].includes(destination.protocol)) {
    return NextResponse.json(
      { detail: "Backend URL must use HTTP or HTTPS" },
      { status: 503, headers: { "Cache-Control": "no-store" } }
    );
  }

  const backendBasePath = destination.pathname.replace(/\/$/, "");
  const apiPath = request.nextUrl.pathname.slice(4);
  destination.pathname = `${backendBasePath}${apiPath.startsWith("/") ? apiPath : `/${apiPath}`}`;
  destination.search = request.nextUrl.search;
  destination.hash = "";

  const headers = new Headers(request.headers);
  headers.set("X-API-Key", apiKey);
  headers.set("X-SecOps-User", expectedUser);
  headers.delete("authorization");
  headers.delete("host");

  const response = NextResponse.rewrite(destination, { request: { headers } });
  response.headers.set("Cache-Control", "no-store");
  return response;
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
