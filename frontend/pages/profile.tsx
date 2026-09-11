import { useState, type FormEvent } from "react";
import { useRouter } from "next/router";
import { useAuth } from "../lib/auth";
import { apiPost } from "../lib/api";
import { ErrorNotice } from "../components/feedback";

export default function Profile() {
  const auth = useAuth(); const router = useRouter();
  const [current, setCurrent] = useState(""); const [password, setPassword] = useState(""); const [confirm, setConfirm] = useState("");
  const [error, setError] = useState(""); const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent) {
    event.preventDefault(); setError("");
    if (password !== confirm) { setError("New passwords do not match."); return; }
    setBusy(true);
    try { await apiPost("/auth/password", { current_password: current, new_password: password }); auth.clear(); await router.replace("/login?passwordChanged=1"); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Password change failed"); }
    finally { setBusy(false); }
  }
  return <section className="max-w-lg space-y-4">
    <h1 className="text-2xl font-semibold">Your account</h1>
    <p>{auth.user?.username} · {auth.user?.role}</p>
    <p className="text-sm">Projects: {auth.user?.projects === null ? "All projects" : auth.user?.projects?.join(", ") || "No projects assigned"}</p>
    <h2 className="text-lg font-semibold">Change password</h2><p className="text-sm">Use at least 15 characters. Changing your password signs you out on every device.</p>
    <ErrorNotice message={error} />
    <form onSubmit={submit} className="grid gap-3">
      <label className="grid gap-1 text-sm">Current password<input className="input" type="password" autoComplete="current-password" required maxLength={1024} value={current} onChange={e => setCurrent(e.target.value)} /></label>
      <label className="grid gap-1 text-sm">New password<input className="input" type="password" autoComplete="new-password" required minLength={15} maxLength={1024} value={password} onChange={e => setPassword(e.target.value)} /></label>
      <label className="grid gap-1 text-sm">Confirm new password<input className="input" type="password" autoComplete="new-password" required minLength={15} maxLength={1024} value={confirm} onChange={e => setConfirm(e.target.value)} /></label>
      <button className="button-primary" disabled={busy}>Change password and sign out</button>
    </form>
  </section>;
}
