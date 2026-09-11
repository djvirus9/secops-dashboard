import { useState, type FormEvent } from "react";
import { apiPost } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useApiResource } from "../lib/use-api-resource";
import { ErrorNotice } from "../components/feedback";

type ScannerToken = { id: string; name: string; project: string; created_at: string; expires_at: string; revoked_at: string | null; last_used_at: string | null; active: boolean };
type IssuedToken = { token: string; scanner_token: ScannerToken };
const date = (value: string | null) => value ? new Date(value).toLocaleString() : "Never";

export default function ScannerTokens() {
  const { isAdmin } = useAuth();
  const { data, error, loading, reload } = useApiResource<{ count: number; results: ScannerToken[] }>("/scanner-tokens", undefined, isAdmin);
  const [name, setName] = useState(""); const [project, setProject] = useState(""); const [days, setDays] = useState("90");
  const [unscoped, setUnscoped] = useState(false);
  const [issued, setIssued] = useState<IssuedToken | null>(null);
  const [confirmation, setConfirmation] = useState<{ token: ScannerToken; action: "rotate" | "revoke" } | null>(null);
  const [rotationDays, setRotationDays] = useState("90");
  const [busy, setBusy] = useState(false); const [failure, setFailure] = useState("");
  const [success, setSuccess] = useState(""); const [copyMessage, setCopyMessage] = useState("");
  async function create(event: FormEvent) {
    event.preventDefault(); if (issued || busy) return;
    setBusy(true); setFailure(""); setSuccess(""); setCopyMessage("");
    try {
      setIssued(await apiPost<IssuedToken>("/scanner-tokens", { name: name.trim(), project: unscoped ? "" : project.trim(), expires_in_days: Number(days) }));
      setName(""); setProject(""); setUnscoped(false); reload();
    } catch (reason) { setFailure(reason instanceof Error ? reason.message : "Unable to create token"); }
    finally { setBusy(false); }
  }
  async function confirm(event: FormEvent) {
    event.preventDefault(); if (!confirmation || issued || busy) return;
    setBusy(true); setFailure(""); setSuccess(""); setCopyMessage("");
    try {
      const { token, action } = confirmation;
      if (action === "rotate") setIssued(await apiPost<IssuedToken>(`/scanner-tokens/${token.id}/rotate`, { expires_in_days: Number(rotationDays) }));
      else { await apiPost(`/scanner-tokens/${token.id}/revoke`, {}); setSuccess("Token revoked. It can no longer import reports."); }
      setConfirmation(null); reload();
    } catch (reason) { setFailure(reason instanceof Error ? reason.message : "Unable to update token"); }
    finally { setBusy(false); }
  }
  async function copy() {
    if (!issued) return;
    try { await navigator.clipboard.writeText(issued.token); setCopyMessage("Token copied."); }
    catch { setCopyMessage("Clipboard unavailable. Select the token below and copy it manually."); }
  }
  return <div className="space-y-5">
    <div className="flex flex-wrap items-center justify-between gap-3"><h1 className="text-2xl font-semibold">Scanner tokens</h1><button className="button-secondary" disabled={busy || loading} onClick={reload}>Refresh tokens</button></div>
    <p className="text-sm">Give each scanner a token for one project. Scanner tokens can import reports; they cannot read dashboard data or administer this installation.</p>
    <ErrorNotice message={error} retry={reload} /><ErrorNotice message={failure} />
    {busy && <p role="status">Updating scanner tokens…</p>}
    {success && <p role="status">{success}</p>}
    {issued && <section aria-label="New token" className="space-y-3 rounded-xl border border-amber-400 bg-amber-50 p-4 text-amber-950 dark:border-amber-700 dark:bg-amber-950 dark:text-amber-100">
      <h2 className="font-semibold">Save your new token</h2>
      <p className="text-sm">This is the only time this token is shown. Store it in your scanner&apos;s secret settings before dismissing this message or leaving the page.</p>
      <p className="break-words text-sm">{issued.scanner_token.name} · Project: {issued.scanner_token.project || "No project"}</p>
      <label className="grid min-w-0 gap-1 text-sm">New scanner token<textarea className="input min-w-0 font-mono" value={issued.token} readOnly rows={3} spellCheck={false} autoComplete="off" onFocus={event => event.target.select()} /></label>
      <div className="flex flex-wrap gap-2"><button className="button-secondary" onClick={() => void copy()}>Copy token</button><button className="button-secondary" onClick={() => { setIssued(null); setCopyMessage(""); }}>Dismiss token</button></div>
      {copyMessage && <p role="status" className="text-sm">{copyMessage}</p>}
    </section>}
    <form onSubmit={create} className="grid gap-3 rounded-xl border bg-white p-4 sm:grid-cols-2 dark:border-gray-700 dark:bg-gray-800">
      <h2 className="font-semibold sm:col-span-2">Create scanner token</h2>
      <label className="grid gap-1 text-sm">Token name<input className="input" required maxLength={100} value={name} disabled={busy} onChange={event => setName(event.target.value)} /></label>
      <label className="grid gap-1 text-sm">Project<input className="input" required={!unscoped} maxLength={255} value={project} disabled={busy || unscoped} onChange={event => setProject(event.target.value)} /></label>
      <label className="flex items-center gap-2 text-sm sm:col-span-2"><input type="checkbox" checked={unscoped} disabled={busy} onChange={event => setUnscoped(event.target.checked)} />Use no project (unscoped imports only)</label>
      <label className="grid gap-1 text-sm">Expires in days<input className="input" type="number" required min={1} max={365} value={days} disabled={busy} onChange={event => setDays(event.target.value)} /></label>
      <div className="flex items-end"><button className="button-primary" disabled={busy || Boolean(issued)}>Create token</button></div>
      {issued && <p className="text-sm sm:col-span-2">Dismiss the displayed token before creating or changing another token.</p>}
    </form>
    {loading && <p role="status">Loading scanner tokens…</p>}
    {data && !data.results.length && <p>No scanner tokens created yet.</p>}
    <div className="space-y-3">{data?.results.map(token => <article aria-label={`Scanner token ${token.name}`} key={token.id} className="space-y-3 rounded-xl border bg-white p-4 dark:border-gray-700 dark:bg-gray-800">
      <div className="flex flex-wrap items-center justify-between gap-2"><h2 className="break-all font-semibold">{token.name}</h2><span className="text-sm">{token.revoked_at ? "Revoked" : token.active ? "Active" : "Expired"}</span></div>
      <p className="break-words text-sm">Project: {token.project || "No project"}</p>
      <dl className="grid gap-2 text-sm sm:grid-cols-3"><div><dt>Created</dt><dd>{date(token.created_at)}</dd></div><div><dt>Expires</dt><dd>{date(token.expires_at)}</dd></div><div><dt>Last used</dt><dd>{date(token.last_used_at)}</dd></div></dl>
      <div className="flex flex-wrap gap-2">{(["rotate", "revoke"] as const).filter(action => action === "rotate" || !token.revoked_at).map(action => <button key={action} className="button-secondary" disabled={busy || Boolean(issued)} onClick={() => { setConfirmation({ token, action }); setRotationDays("90"); setFailure(""); setSuccess(""); }}>{action === "rotate" ? "Rotate token" : "Revoke token"}</button>)}</div>
      {confirmation?.token.id === token.id && <form onSubmit={confirm} className="space-y-3 rounded-lg border border-amber-500 p-3">
        <h3 className="font-semibold">{confirmation.action === "rotate" ? "Rotate" : "Revoke"} {token.name}?</h3>
        <p className="text-sm">{confirmation.action === "rotate" ? "The current token will stop working immediately. Update your scanner with the new token after rotation." : "This scanner will no longer be able to import reports with this token."}</p>
        {confirmation.action === "rotate" && <label className="grid max-w-xs gap-1 text-sm">New token expires in days<input className="input" type="number" min={1} max={365} required value={rotationDays} disabled={busy} onChange={event => setRotationDays(event.target.value)} /></label>}
        <div className="flex flex-wrap gap-2"><button className="button-primary" disabled={busy || Boolean(issued)}>{confirmation.action === "rotate" ? "Confirm rotation" : "Confirm revocation"}</button><button className="button-secondary" type="button" disabled={busy} onClick={() => { setConfirmation(null); setFailure(""); }}>Cancel</button></div>
      </form>}
    </article>)}</div>
  </div>;
}
