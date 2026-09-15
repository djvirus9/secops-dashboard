import { useEffect, useRef, useState } from "react";
import { apiPost } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useApiResource } from "../lib/use-api-resource";
import { safeJiraUrl, type JiraProgress } from "../lib/jira";
import { ErrorNotice } from "./feedback";

export function JiraProgressPanel({ findingId, status, assignee }: { findingId: string; status: string; assignee: string | null }) {
  const { canWrite } = useAuth();
  const { data, error, loading, reload } = useApiResource<JiraProgress>(`/findings/${findingId}/jira`);
  const [field, setField] = useState<"status" | "assignee" | null>(null);
  const [confirmed, setConfirmed] = useState(false);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState("");
  const [success, setSuccess] = useState("");
  const previousLocal = useRef(JSON.stringify([status, assignee]));
  useEffect(() => {
    const next = JSON.stringify([status, assignee]);
    if (previousLocal.current === next) return;
    previousLocal.current = next;
    reload(); setField(null); setConfirmed(false);
  }, [status, assignee, reload]);
  useEffect(() => { setConfirmed(false); }, [data?.link?.remote_updated_at, data?.push_preview.local_status, data?.push_preview.local_assignee]);
  const link = data?.link;
  const url = link ? safeJiraUrl(link.url) : null;
  const running = link?.status === "queued" || link?.status === "syncing";
  const ready = Boolean(data?.enabled && data.configured && !running && !busy && !loading);
  const canPush = ready && Boolean(link?.last_synced_at && link?.remote_updated_at) && link?.status !== "needs_review";
  async function pull() {
    setBusy(true); setFailure(""); setSuccess("");
    try { await apiPost(`/findings/${findingId}/jira/pull`, {}); reload(); setSuccess("Jira refresh queued. Refresh this panel after the worker runs."); }
    catch (reason) { setFailure(reason instanceof Error ? reason.message : "Unable to queue Jira refresh"); }
    finally { setBusy(false); }
  }
  async function push() {
    if (!field || !confirmed || !data?.link?.remote_updated_at) return;
    setBusy(true); setFailure(""); setSuccess("");
    try {
      await apiPost(`/findings/${findingId}/jira/push`, { field, expected_local_status: data.push_preview.local_status, expected_local_assignee: data.push_preview.local_assignee, expected_remote_updated_at: data.link.remote_updated_at });
      setField(null); setConfirmed(false); reload(); setSuccess("Explicit Jira update queued. No finding was marked fixed.");
    } catch (reason) { setFailure(reason instanceof Error ? reason.message : "Unable to queue Jira update"); }
    finally { setBusy(false); }
  }
  return <section className="space-y-3 rounded-xl border bg-white p-5 dark:border-gray-700 dark:bg-gray-800" aria-labelledby="jira-progress-heading">
    <header className="flex flex-wrap items-center justify-between gap-2"><h2 id="jira-progress-heading" className="text-lg font-semibold">Jira remediation progress</h2><button className="button-secondary" disabled={loading || busy} onClick={reload}>Refresh Jira panel</button></header>
    <p className="text-sm">A Jira transition to Done requests verification. It does not prove the finding is fixed, and the first observation does not change its local status.</p>
    <ErrorNotice message={error} retry={reload} /><ErrorNotice message={failure} />
    {success && <p role="status" className="text-sm">{success}</p>}{loading && <p role="status">Loading Jira progress…</p>}
    {data && <>{!data.configured && <p className="text-sm">Jira access is not configured.</p>}{!data.enabled && <p className="text-sm">Jira synchronization is disabled.</p>}{!link ? <div className="space-y-2"><p className="text-sm">No linked Jira issue has been discovered from a successful delivery.</p>{canWrite && <button className="button-secondary" disabled={!ready} onClick={() => void pull()}>Discover linked Jira issue</button>}</div> : <>
      <dl className="grid gap-3 text-sm sm:grid-cols-2 lg:grid-cols-4"><div><dt className="text-xs text-gray-500">Issue</dt><dd>{url ? <a href={url} className="text-indigo-600 underline dark:text-indigo-400" target="_blank" rel="noopener noreferrer">{link.issue_key}</a> : link.issue_key}</dd></div><div><dt className="text-xs text-gray-500">Remote status</dt><dd>{link.remote_status || "Not read yet"}</dd></div><div><dt className="text-xs text-gray-500">Remote assignee</dt><dd className="break-all">{link.remote_assignee || "Unassigned / not read"}</dd></div><div><dt className="text-xs text-gray-500">Sync state</dt><dd>{link.status.replaceAll("_", " ")} · {link.operation.replaceAll("_", " ")}</dd></div><div className="sm:col-span-2"><dt className="text-xs text-gray-500">Last successful sync</dt><dd>{link.last_synced_at ? new Date(link.last_synced_at).toLocaleString() : "Not yet"}</dd></div></dl>
      {link.last_error && <p className="break-words rounded-lg border border-amber-300 p-3 text-sm text-amber-900 dark:border-amber-800 dark:text-amber-200">{link.last_error}</p>}
      {canWrite && <div className="flex flex-wrap gap-2"><button className="button-secondary" disabled={!ready} onClick={() => void pull()}>Pull Jira progress</button><button className="button-secondary" disabled={!canPush || !data.push_preview.status_target_category} onClick={() => { setField("status"); setConfirmed(false); }}>Review status push</button><button className="button-secondary" disabled={!canPush || !data.push_preview.assignee_mapped} onClick={() => { setField("assignee"); setConfirmed(false); }}>Review assignee push</button></div>}
      {canWrite && !link.last_synced_at && <p className="text-xs">Pull the issue first to establish a remote baseline before pushing changes.</p>}
      {canWrite && !data.push_preview.assignee_mapped && <p className="text-xs">Assignee updates require an active Jira account mapping and an eligible dashboard owner.</p>}
      {field && <form className="space-y-3 rounded-lg border border-indigo-300 p-4 dark:border-indigo-800" onSubmit={event => { event.preventDefault(); void push(); }}><h3 className="font-semibold">Confirm external Jira update</h3><p className="break-words text-sm">Issue {link.issue_key}: {field === "status" ? `send local status ${data.push_preview.local_status.replaceAll("_", " ")} as Jira category ${data.push_preview.status_target_category}` : data.push_preview.local_assignee ? `assign to the Jira account mapped to ${data.push_preview.local_assignee}` : "clear the Jira assignee to match the unassigned finding"}.</p><p className="text-xs">The worker checks both local and remote versions again; concurrent changes require a fresh review.</p><label className="flex items-start gap-2 text-sm"><input type="checkbox" checked={confirmed} disabled={busy} onChange={event => setConfirmed(event.target.checked)} />I confirm this update to the linked Jira issue.</label><div className="flex flex-wrap gap-2"><button className="button-primary" disabled={!confirmed || !canPush}>Queue Jira update</button><button type="button" className="button-secondary" disabled={busy} onClick={() => { setField(null); setConfirmed(false); }}>Cancel Jira update</button></div></form>}
    </>}{data.note && <p className="text-xs text-gray-500 dark:text-gray-400">{data.note}</p>}</>}
  </section>;
}
