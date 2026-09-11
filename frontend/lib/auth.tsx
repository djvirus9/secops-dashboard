import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { useRouter } from "next/router";
import type { UrlObject } from "url";
import { apiGet, apiPost, ApiError } from "./api";

export type User = { id: string; username: string; role: "admin" | "analyst" | "viewer"; projects: string[] | null; active?: boolean };
export function safeReturnRoute(value: unknown): UrlObject {
  if (typeof value !== "string" || !value.startsWith("/") || value.startsWith("//") || /[\\\u0000-\u0020]/.test(value)) return { pathname: "/" };
  // Do not normalize or decode the pathname: only literal application routes qualify.
  // Validate percent escapes before parsing query values so malformed returns fail closed.
  try { decodeURIComponent(value); } catch { return { pathname: "/" }; }
  const [beforeHash, ...fragment] = value.split("#");
  const queryStart = beforeHash.indexOf("?");
  const pathname = queryStart < 0 ? beforeHash : beforeHash.slice(0, queryStart);
  const params = new URLSearchParams(queryStart < 0 ? "" : beforeHash.slice(queryStart + 1));
  const query = Object.fromEntries([...new Set(params.keys())].map(key => {
    const values = params.getAll(key);
    return [key, values.length === 1 ? values[0] : values];
  }));
  const hash = fragment.length ? `#${fragment.join("#")}` : undefined;
  // Each navigation target is a literal. Untrusted values can only become query/fragment data.
  switch (pathname) {
    case "/": return { pathname: "/", query, hash };
    case "/findings": return { pathname: "/findings", query, hash };
    case "/assets": return { pathname: "/assets", query, hash };
    case "/risks": return { pathname: "/risks", query, hash };
    case "/integrations": return { pathname: "/integrations", query, hash };
    case "/imports": return { pathname: "/imports", query, hash };
    case "/notifications": return { pathname: "/notifications", query, hash };
    case "/profile": return { pathname: "/profile", query, hash };
    case "/users": return { pathname: "/users", query, hash };
  }
  const detail = /^\/findings\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/i.exec(pathname);
  return detail ? { pathname: "/findings/[id]", query: { ...query, id: detail[1] }, hash } : { pathname: "/" };
}
type Auth = { user: User | null; loading: boolean; error: string; reload: () => Promise<void>; login: (username: string, password: string) => Promise<void>; logout: () => Promise<void>; clear: () => void; canWrite: boolean; isAdmin: boolean };
const Context = createContext<Auth | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const router = useRouter();
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const reload = useCallback(async () => {
    setLoading(true); setError("");
    try { setUser((await apiGet<{ user: User }>("/auth/me")).user); }
    catch (reason) { setUser(null); if (!(reason instanceof ApiError && reason.status === 401)) setError(reason instanceof Error ? reason.message : "Unable to check your session"); }
    finally { setLoading(false); }
  }, []);
  const clear = useCallback(() => { setUser(null); setError(""); setLoading(false); }, []);
  useEffect(() => { void reload(); window.addEventListener("secops:unauthorized", clear); return () => window.removeEventListener("secops:unauthorized", clear); }, [reload, clear]);
  useEffect(() => {
    if (!router.isReady || loading || error || user || router.pathname === "/login") return;
    void router.replace({ pathname: "/login", query: { next: router.asPath } });
  }, [router, loading, error, user]);
  const login = async (username: string, password: string) => {
    const result = await apiPost<{ user: User }>("/auth/login", { username, password });
    setUser(result.user); setError(""); setLoading(false);
  };
  const logout = async () => { await apiPost("/auth/logout", {}); clear(); await router.replace("/login"); };
  return <Context.Provider value={{ user, loading, error, reload, login, logout, clear, canWrite: Boolean(user && user.role !== "viewer"), isAdmin: user?.role === "admin" }}>{children}</Context.Provider>;
}
export function useAuth() { const auth = useContext(Context); if (!auth) throw new Error("Authentication context missing"); return auth; }
