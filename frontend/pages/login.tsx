import { useState, useEffect, type FormEvent } from "react";
import { useRouter } from "next/router";
import { safeReturnPath, useAuth } from "../lib/auth";
import { ErrorNotice } from "../components/feedback";

export default function Login() {
  const auth = useAuth(); const router = useRouter();
  const [username, setUsername] = useState(""); const [password, setPassword] = useState("");
  const [error, setError] = useState(""); const [busy, setBusy] = useState(false);
  useEffect(() => { if (router.isReady && auth.user) void router.replace(safeReturnPath(router.query.next)); }, [auth.user, router]);
  async function submit(event: FormEvent) {
    event.preventDefault(); setBusy(true); setError("");
    try { await auth.login(username, password); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Sign in failed"); }
    finally { setBusy(false); }
  }
  return <section className="mx-auto max-w-md rounded-xl border bg-white p-6 dark:border-gray-700 dark:bg-gray-800">
    <h1 className="text-2xl font-semibold">Sign in</h1>
    <p className="my-3 text-sm">Use the account provided by your dashboard administrator.</p>
    {router.query.passwordChanged === "1" && <p role="status" className="mb-3 text-sm">Password changed. Sign in again on each device.</p>}
    <ErrorNotice message={error || auth.error} retry={auth.error ? () => void auth.reload() : undefined} />
    <form onSubmit={submit} className="grid gap-4">
      <label className="grid gap-1 text-sm">Username<input className="input" autoComplete="username" required maxLength={100} value={username} onChange={event => setUsername(event.target.value)} /></label>
      <label className="grid gap-1 text-sm">Password<input className="input" type="password" autoComplete="current-password" required maxLength={1024} value={password} onChange={event => setPassword(event.target.value)} /></label>
      <button className="button-primary" disabled={busy || auth.loading} type="submit">{busy ? "Signing in…" : "Sign in"}</button>
    </form>
  </section>;
}
