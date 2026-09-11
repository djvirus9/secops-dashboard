import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { useRouter } from "next/router";
import { apiGet, apiPost, ApiError } from "./api";

export type User = { id: string; username: string; role: "admin" | "analyst" | "viewer"; projects: string[] | null; active?: boolean };
export function safeReturnPath(value: unknown): string {
  if (typeof value !== "string" || !value.startsWith("/") || value.startsWith("//") || /[\\\u0000-\u0020]/.test(value)) return "/";
  const pathname = value.split(/[?#]/)[0];
  return ["/", "/findings", "/assets", "/risks", "/integrations", "/imports", "/notifications", "/profile", "/users"].includes(pathname) || /^\/findings\/[0-9a-f-]{36}$/i.test(pathname) ? value : "/";
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
    void router.replace({ pathname: "/login", query: { next: safeReturnPath(router.asPath) } });
  }, [router, loading, error, user]);
  const login = async (username: string, password: string) => {
    const result = await apiPost<{ user: User }>("/auth/login", { username, password });
    setUser(result.user); setError(""); setLoading(false);
  };
  const logout = async () => { await apiPost("/auth/logout", {}); clear(); await router.replace("/login"); };
  return <Context.Provider value={{ user, loading, error, reload, login, logout, clear, canWrite: Boolean(user && user.role !== "viewer"), isAdmin: user?.role === "admin" }}>{children}</Context.Provider>;
}
export function useAuth() { const auth = useContext(Context); if (!auth) throw new Error("Authentication context missing"); return auth; }
