import { useState, type FormEvent } from "react";
import { apiPatch, apiPost } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useApiResource } from "../lib/use-api-resource";
import { ErrorNotice } from "../components/feedback";

type Connection = { id: string; repository: string; project: string; sources: string[]; enabled: boolean; interval_minutes: number; status: string; next_sync_at: string | null; last_synced_at: string | null; last_error: string | null };
type Run = { id: string; status: string; started_at: string; completed_at: string | null; imported: number; new_findings: number; updated: number; error: string | null };
const sourceName = (source: string) => ({ code_scanning: "Code scanning", dependabot: "Dependabot" }[source] || source);
const date = (value: string | null) => value ? new Date(value).toLocaleString() : "Not yet";

function RunHistory({ id }: { id: string }) {
  const { data, error, loading, reload } = useApiResource<{ results: Run[] }>(`/github-sync/${id}/runs`);
  return <section aria-label="Sync history" className="space-y-3 border-t pt-3 dark:border-gray-700">
    <div className="flex flex-wrap items-center justify-between gap-2"><h3 className="font-semibold">Recent sync runs</h3><button className="button-secondary" onClick={reload} disabled={loading}>Refresh history</button></div>
    <ErrorNotice message={error} retry={reload} />
    {loading && <p role="status">Loading sync history…</p>}
    {data && !data.results.length && <p className="text-sm">No sync runs recorded yet.</p>}
    {data?.results.map(run => <div className="space-y-1 rounded-lg border p-3 text-sm dark:border-gray-700" key={run.id}>
      <p className="font-medium">{run.status} · Started {date(run.started_at)}</p>
      <p>Imported: {run.imported} · New findings: {run.new_findings} · Updated: {run.updated}</p>
      {run.completed_at && <p>Completed {date(run.completed_at)}</p>}
      {run.error && <p className="break-words text-red-700 dark:text-red-300">{run.error}</p>}
    </div>)}
  </section>;
}

export default function GitHubSync() {
  const { isAdmin } = useAuth();
  const { data, error, loading, reload } = useApiResource<{ configured: boolean; count: number; results: Connection[] }>("/github-sync", undefined, isAdmin);
  const [repository, setRepository] = useState(""); const [project, setProject] = useState(""); const [unscoped, setUnscoped] = useState(false);
  const [sources, setSources] = useState(["code_scanning", "dependabot"]); const [interval, setInterval] = useState("60");
  const [busy, setBusy] = useState(false); const [failure, setFailure] = useState(""); const [success, setSuccess] = useState("");
  const [editing, setEditing] = useState<string | null>(null); const [editInterval, setEditInterval] = useState("60");
  const [history, setHistory] = useState<string | null>(null);
  async function create(event: FormEvent) {
    event.preventDefault(); if (busy) return;
    setFailure(""); setSuccess("");
    if (!sources.length) { setFailure("Choose at least one GitHub alert source."); return; }
    setBusy(true);
    try {
      await apiPost("/github-sync", { repository: repository.trim(), project: unscoped ? "" : project.trim(), sources, interval_minutes: Number(interval) });
      setRepository(""); setProject(""); setUnscoped(false); setSuccess("Connection created. Check its sync status below."); reload();
    } catch (reason) { setFailure(reason instanceof Error ? reason.message : "Unable to create GitHub connection"); }
    finally { setBusy(false); }
  }
  async function update(connection: Connection, patch: { enabled?: boolean; interval_minutes?: number }) {
    if (busy) return; setBusy(true); setFailure(""); setSuccess("");
    try {
      await apiPatch(`/github-sync/${connection.id}`, patch); setEditing(null);
      setSuccess(patch.enabled === false ? "Scheduled sync paused. An in-progress run may still finish." : "Connection updated."); reload();
    } catch (reason) { setFailure(reason instanceof Error ? reason.message : "Unable to update GitHub connection"); }
    finally { setBusy(false); }
  }
  async function sync(connection: Connection) {
    if (busy) return; setBusy(true); setFailure(""); setSuccess("");
    try {
      await apiPost(`/github-sync/${connection.id}/sync`, {});
      setSuccess("Sync queued. Refresh the connection and its history to check the result."); reload();
    } catch (reason) { setFailure(reason instanceof Error ? reason.message : "Unable to queue GitHub sync"); }
    finally { setBusy(false); }
  }
  return <div className="space-y-5">
    <div className="flex flex-wrap items-center justify-between gap-3"><h1 className="text-2xl font-semibold">GitHub sync</h1><button className="button-secondary" disabled={busy || loading} onClick={reload}>Refresh connections</button></div>
    <p className="text-sm">Import GitHub code scanning and Dependabot alerts into a dashboard project. Repository, project and alert sources are fixed when you create a connection.</p>
    <ErrorNotice message={error} retry={reload} /><ErrorNotice message={failure} />
    {busy && <p role="status">Updating GitHub connection…</p>}
    {success && <p role="status">{success}</p>}
    {data?.configured === false && <section aria-label="GitHub setup required" className="space-y-2 rounded-xl border border-amber-400 p-4 text-sm dark:border-amber-700">
      <h2 className="font-semibold">GitHub access is not configured</h2>
      <p>You can save connections now. Sync needs a server-side GitHub credential with access to the selected repositories and alert sources.</p>
      <p>For a local installation, run <code className="break-all">python3 scripts/local.py github-token</code> privately, then restart the local app. Other deployments use the server&apos;s <code>GITHUB_SYNC_TOKEN</code> setting.</p>
    </section>}
    <form onSubmit={create} className="grid gap-3 rounded-xl border bg-white p-4 sm:grid-cols-2 dark:border-gray-700 dark:bg-gray-800">
      <h2 className="font-semibold sm:col-span-2">Connect repository</h2>
      <label className="grid gap-1 text-sm">GitHub repository<input className="input" placeholder="owner/repository" minLength={3} maxLength={140} required disabled={busy} value={repository} onChange={event => setRepository(event.target.value)} /></label>
      <label className="grid gap-1 text-sm">Project<input className="input" maxLength={255} required={!unscoped} disabled={busy || unscoped} value={project} onChange={event => setProject(event.target.value)} /></label>
      <label className="flex items-center gap-2 text-sm sm:col-span-2"><input type="checkbox" disabled={busy} checked={unscoped} onChange={event => setUnscoped(event.target.checked)} />Use no project (unscoped findings)</label>
      <fieldset className="space-y-2"><legend className="mb-1 text-sm">Alert sources</legend>{["code_scanning", "dependabot"].map(source => <label className="flex items-center gap-2 text-sm" key={source}><input type="checkbox" disabled={busy} checked={sources.includes(source)} onChange={event => setSources(event.target.checked ? [...sources, source] : sources.filter(value => value !== source))} />{sourceName(source)}</label>)}</fieldset>
      <label className="grid content-start gap-1 text-sm">Sync interval (minutes)<input aria-label="Sync interval (minutes)" className="input" type="number" min={15} max={1440} required disabled={busy} value={interval} onChange={event => setInterval(event.target.value)} /><span className="text-xs">Between 15 and 1440 minutes.</span></label>
      <div><button className="button-primary" disabled={busy}>Create connection</button></div>
    </form>
    {loading && <p role="status">Loading GitHub connections…</p>}
    {data && !data.results.length && <p>No GitHub connections created yet.</p>}
    <div className="space-y-3">{data?.results.map(connection => <article aria-label={`GitHub connection ${connection.repository}`} className="space-y-3 rounded-xl border bg-white p-4 dark:border-gray-700 dark:bg-gray-800" key={connection.id}>
      <div className="flex flex-wrap items-center justify-between gap-2"><h2 className="break-all font-semibold">{connection.repository}</h2><span className="text-sm">{connection.status} · {connection.enabled ? "Enabled" : "Paused"}</span></div>
      <p className="break-words text-sm">Project: {connection.project || "No project"} · {connection.sources.map(sourceName).join(", ")}</p>
      <dl className="grid gap-2 text-sm sm:grid-cols-3"><div><dt>Schedule</dt><dd>Every {connection.interval_minutes} minutes</dd></div><div><dt>Last sync</dt><dd>{date(connection.last_synced_at)}</dd></div><div><dt>Next sync</dt><dd>{connection.enabled ? date(connection.next_sync_at) : "Paused"}</dd></div></dl>
      {connection.last_error && <p className="break-words text-sm text-red-700 dark:text-red-300">{connection.last_error}</p>}
      <div className="flex flex-wrap gap-2">
        <button className="button-secondary" disabled={busy || !data.configured || !connection.enabled || ["queued", "syncing"].includes(connection.status)} onClick={() => void sync(connection)}>Sync now</button>
        <button className="button-secondary" disabled={busy} onClick={() => void update(connection, { enabled: !connection.enabled })}>{connection.enabled ? "Pause sync" : "Enable sync"}</button>
        <button className="button-secondary" disabled={busy} onClick={() => { setEditing(connection.id); setEditInterval(String(connection.interval_minutes)); setFailure(""); }}>Edit schedule</button>
        <button className="button-secondary" aria-expanded={history === connection.id} onClick={() => setHistory(history === connection.id ? null : connection.id)}>{history === connection.id ? "Hide history" : "View history"}</button>
      </div>
      {editing === connection.id && <form className="space-y-3 rounded-lg border p-3 dark:border-gray-700" onSubmit={event => { event.preventDefault(); void update(connection, { interval_minutes: Number(editInterval) }); }}>
        <label className="grid max-w-xs gap-1 text-sm">New interval (minutes)<input className="input" type="number" min={15} max={1440} required disabled={busy} value={editInterval} onChange={event => setEditInterval(event.target.value)} /></label>
        <div className="flex flex-wrap gap-2"><button className="button-primary" disabled={busy}>Save schedule</button><button type="button" className="button-secondary" disabled={busy} onClick={() => { setEditing(null); setFailure(""); }}>Cancel</button></div>
      </form>}
      {history === connection.id && <RunHistory id={connection.id} />}
    </article>)}</div>
  </div>;
}
