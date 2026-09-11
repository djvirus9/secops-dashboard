import type { AppProps } from "next/app";
import Link from "next/link";
import { useState, useEffect } from "react";
import { AuthProvider, useAuth } from "../lib/auth";
import { ErrorNotice } from "../components/feedback";
import "../styles/globals.css";

const nav = [
  { href: "/", label: "Dashboard" },
  { href: "/findings", label: "Findings" },
  { href: "/assets", label: "Assets" },
  { href: "/risks", label: "Risks" },
  { href: "/integrations", label: "Integrations" },
  { href: "/imports", label: "Imports" },
  { href: "/notifications", label: "Delivery" },
  { href: "/users", label: "Users" },
  { href: "/scanner-tokens", label: "Scanner tokens" },
  { href: "/github-sync", label: "GitHub sync" },
  { href: "/profile", label: "Account" },
];
const adminPages = ["/users", "/notifications", "/scanner-tokens", "/github-sync"];

export default function App(props: AppProps) { return <AuthProvider><AppShell {...props} /></AuthProvider>; }

function AppShell({ Component, pageProps, router }: AppProps) {
  const auth = useAuth();
  const [logoutError, setLogoutError] = useState("");
  const [loggingOut, setLoggingOut] = useState(false);
  const [darkMode, setDarkMode] = useState(false);
  const [themeReady, setThemeReady] = useState(false);

  useEffect(() => {
    try { setDarkMode(localStorage.getItem("darkMode") === "true"); } catch { /* Storage may be disabled. */ }
    setThemeReady(true);
  }, []);

  useEffect(() => {
    if (!themeReady) return;
    if (darkMode) {
      document.documentElement.classList.add("dark");
    } else {
      document.documentElement.classList.remove("dark");
    }
    try { localStorage.setItem("darkMode", String(darkMode)); } catch { /* Theme still works in memory. */ }
  }, [darkMode, themeReady]);

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 transition-colors">
      <a href="#main-content" className="skip-link">Skip to content</a>
      <header className="border-b bg-white dark:bg-gray-800 dark:border-gray-700">
        <div className="mx-auto max-w-6xl px-4 sm:px-6 py-4 flex flex-col items-start gap-3 lg:flex-row lg:items-center lg:justify-between">
          <div className="font-semibold text-gray-900 dark:text-white">SecOps Dashboard</div>
          <div className="flex w-full min-w-0 items-start gap-2 lg:w-auto">
            <nav aria-label="Main navigation" className="flex min-w-0 flex-1 flex-wrap gap-2">
              {auth.user && nav.filter(n => auth.isAdmin || !adminPages.includes(n.href)).map((n) => {
                const active = router.pathname === n.href || (n.href !== "/" && router.pathname.startsWith(`${n.href}/`));
                return (
                  <Link
                    key={n.href}
                    href={n.href}
                    aria-current={active ? "page" : undefined}
                    className={
                      "rounded-md px-3 py-1 text-sm border transition-colors " +
                      (active
                        ? "bg-black text-white border-black dark:bg-white dark:text-black dark:border-white"
                        : "bg-white text-gray-700 hover:bg-gray-100 dark:bg-gray-800 dark:text-gray-300 dark:hover:bg-gray-700 dark:border-gray-600")
                    }
                  >
                    {n.href === "/integrations" && !auth.isAdmin ? auth.canWrite ? "Import scans" : "Scanners" : n.label}
                  </Link>
                );
              })}
            </nav>
            <button
              onClick={() => setDarkMode(!darkMode)}
              className="p-2 rounded-lg border bg-white hover:bg-gray-100 dark:bg-gray-800 dark:hover:bg-gray-700 dark:border-gray-600 transition-colors"
              aria-label="Toggle dark mode"
              aria-pressed={darkMode}
            >
              {darkMode ? (
                <svg className="w-5 h-5 text-yellow-500" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M10 2a1 1 0 011 1v1a1 1 0 11-2 0V3a1 1 0 011-1zm4 8a4 4 0 11-8 0 4 4 0 018 0zm-.464 4.95l.707.707a1 1 0 001.414-1.414l-.707-.707a1 1 0 00-1.414 1.414zm2.12-10.607a1 1 0 010 1.414l-.706.707a1 1 0 11-1.414-1.414l.707-.707a1 1 0 011.414 0zM17 11a1 1 0 100-2h-1a1 1 0 100 2h1zm-7 4a1 1 0 011 1v1a1 1 0 11-2 0v-1a1 1 0 011-1zM5.05 6.464A1 1 0 106.465 5.05l-.708-.707a1 1 0 00-1.414 1.414l.707.707zm1.414 8.486l-.707.707a1 1 0 01-1.414-1.414l.707-.707a1 1 0 011.414 1.414zM4 11a1 1 0 100-2H3a1 1 0 000 2h1z" clipRule="evenodd" />
                </svg>
              ) : (
                <svg className="w-5 h-5 text-gray-700" fill="currentColor" viewBox="0 0 20 20">
                  <path d="M17.293 13.293A8 8 0 016.707 2.707a8.001 8.001 0 1010.586 10.586z" />
                </svg>
              )}
            </button>
          </div>
        </div>
        {auth.user && <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-end gap-3 px-4 pb-3 text-sm sm:px-6">
          <span>{auth.user.username} · {auth.user.role}</span>
          <button className="button-secondary" disabled={loggingOut} onClick={async () => {
            setLoggingOut(true); setLogoutError("");
            try { await auth.logout(); } catch (reason) { setLogoutError(reason instanceof Error ? reason.message : "Sign out failed"); }
            finally { setLoggingOut(false); }
          }}>Sign out</button>
          <ErrorNotice message={logoutError} />
        </div>}
      </header>

      <main id="main-content" className="mx-auto min-w-0 max-w-6xl px-4 sm:px-6 py-8">
        {router.pathname === "/login" ? <Component {...pageProps} /> : auth.loading ? <p role="status">Checking your session…</p> : auth.error ? <ErrorNotice message={auth.error} retry={() => void auth.reload()} /> : auth.user ?
          !auth.isAdmin && adminPages.includes(router.pathname) ? <p role="alert">This page is available to administrators.</p> : <Component {...pageProps} /> : <p role="status">Redirecting to sign in…</p>}
      </main>
    </div>
  );
}
