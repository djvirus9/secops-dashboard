import Link from "next/link";
import { useState, type FormEvent } from "react";
import { apiPost, apiPut } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useApiResource } from "../lib/use-api-resource";
import { ErrorNotice, Pagination } from "../components/feedback";

type Alert = { id: string; project: string; kind: "sla" | "coverage"; resource_id: string; condition: string; state: "open" | "acknowledged" | "resolved"; title: string; message: string; owner: string | null; team: string | null; escalation_contact: string | null; first_seen_at: string; last_seen_at: string; resolved_at: string | null; acknowledged_at: string | null; acknowledged_by: string | null };
type Policy = { project: string; enabled: boolean; warn_before_hours: number; reminder_hours: number; notify_slack: boolean; last_evaluated_at: string | null; next_evaluation_at: string | null; last_error: string | null };
const empty = { project: "", enabled: false, warn_before_hours: 24, reminder_hours: 24, notify_slack: false };
const date = (value: string | null) => value ? new Date(value).toLocaleString() : "Not yet";

export default function OperationsPage() {
  const { canWrite, isAdmin } = useAuth();
  const [filters, setFilters] = useState({ state: "active", project: "", kind: "" });
  const [draft, setDraft] = useState(filters);
  const [offset, setOffset] = useState(0);
  const [form, setForm] = useState(empty);
  const [editing, setEditing] = useState(false);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState("");
  const [success, setSuccess] = useState("");
  const alerts = useApiResource<{ count: number; results: Alert[] }>("/automation/alerts", { ...filters, offset, limit: 50 });
  const settings = useApiResource<{ policies: Policy[]; slack_configured: boolean }>("/automation");
  async function acknowledge(id: string) {
    setBusy(true); setFailure(""); setSuccess("");
    try { await apiPost(`/automation/alerts/${id}/acknowledge`, {}); alerts.reload(); setSuccess("Alert acknowledged. Reminders pause until the condition changes or reappears."); }
    catch (reason) { setFailure(reason instanceof Error ? reason.message : "Unable to acknowledge alert"); }
    finally { setBusy(false); }
  }
  async function save(event: FormEvent) {
    event.preventDefault(); setBusy(true); setFailure(""); setSuccess("");
    try { const { project, ...policy } = form; await apiPut("/automation/policies", policy, { query: { project } }); settings.reload(); alerts.reload(); setSuccess("Operations policy saved."); setForm(empty); setEditing(false); }
    catch (reason) { setFailure(reason instanceof Error ? reason.message : "Unable to save operations policy"); }
    finally { setBusy(false); }
  }
  async function evaluate(project: string) {
    setBusy(true); setFailure(""); setSuccess("");
    try { await apiPost("/automation/evaluate", {}, { query: { project } }); settings.reload(); setSuccess("Evaluation queued. Refresh the inbox after the worker runs."); }
    catch (reason) { setFailure(reason instanceof Error ? reason.message : "Unable to queue evaluation"); }
    finally { setBusy(false); }
  }
  return <div className="space-y-5">
    <header className="flex flex-wrap items-end justify-between gap-3"><div><p className="text-xs font-semibold uppercase tracking-[.18em] text-indigo-600 dark:text-indigo-400">Closed-loop remediation</p><h1 className="mt-1 text-3xl font-semibold">Operations inbox</h1><p className="mt-2 text-sm">SLA warnings, overdue work and reporting gaps for your authorized projects.</p></div><button className="button-secondary" disabled={alerts.loading || settings.loading || busy} onClick={() => { alerts.reload(); settings.reload(); }}>Refresh</button></header>
    <ErrorNotice message={failure} />{success && <p role="status" className="text-sm">{success}</p>}
    <form className="grid gap-3 rounded-xl border bg-white p-4 sm:grid-cols-2 lg:grid-cols-4 dark:border-gray-700 dark:bg-gray-800" onSubmit={event => { event.preventDefault(); setFilters(draft); setOffset(0); }}>
      <label className="grid gap-1 text-sm">Alert state<select className="input" value={draft.state} onChange={event => setDraft({ ...draft, state: event.target.value })}><option value="active">Active</option><option value="all">All</option><option value="resolved">Resolved</option></select></label>
      <label className="grid gap-1 text-sm">Alert project<input className="input" maxLength={255} value={draft.project} onChange={event => setDraft({ ...draft, project: event.target.value })} placeholder="All authorized projects" /></label>
      <label className="grid gap-1 text-sm">Alert type<select className="input" value={draft.kind} onChange={event => setDraft({ ...draft, kind: event.target.value })}><option value="">All types</option><option value="sla">Remediation SLA</option><option value="coverage">Scanner coverage</option></select></label>
      <div className="flex items-end"><button className="button-primary">Apply alert filters</button></div>
    </form>
    <ErrorNotice message={alerts.error} retry={alerts.reload} />{alerts.loading && <p role="status">Loading operations alerts…</p>}
    {alerts.data && <><div className="space-y-3">{!alerts.data.results.length && <p className="rounded-xl border p-5 text-sm dark:border-gray-700">No alerts match. Policies must be enabled and evaluated before an inbox can show reporting or SLA conditions.</p>}{alerts.data.results.map(alert => <article key={alert.id} className="space-y-3 rounded-xl border bg-white p-4 dark:border-gray-700 dark:bg-gray-800">
      <div className="flex flex-wrap items-start justify-between gap-3"><div className="min-w-0"><div className="flex flex-wrap gap-2 text-xs"><span className="rounded-full border px-2 py-1 dark:border-gray-600">{alert.kind.toUpperCase()}</span><span className="rounded-full border px-2 py-1 dark:border-gray-600">{alert.condition.replaceAll("_", " ")}</span><span className="rounded-full border px-2 py-1 dark:border-gray-600">{alert.state}</span></div><h2 className="mt-2 break-words font-semibold">{alert.title}</h2><p className="mt-1 break-words text-sm">{alert.message}</p></div>{canWrite && alert.state === "open" && <button className="button-secondary" disabled={busy} onClick={() => void acknowledge(alert.id)} aria-label={`Acknowledge ${alert.title}`}>Acknowledge</button>}</div>
      <dl className="grid gap-2 text-xs sm:grid-cols-2 lg:grid-cols-4"><div><dt className="text-gray-500">Project</dt><dd className="break-all">{alert.project || "No project"}</dd></div><div><dt className="text-gray-500">Owner / team</dt><dd className="break-words">{alert.owner || "Unassigned"} · {alert.team || "Unowned"}</dd></div><div><dt className="text-gray-500">Escalation contact</dt><dd className="break-all">{alert.escalation_contact || "Not set"}</dd></div><div><dt className="text-gray-500">Last observed</dt><dd>{date(alert.last_seen_at)}</dd></div></dl>
      {alert.acknowledged_at && <p className="text-xs">Acknowledged by {alert.acknowledged_by || "operator"} on {date(alert.acknowledged_at)}.</p>}
      <Link className="text-sm text-indigo-600 underline dark:text-indigo-400" href={alert.kind === "sla" ? `/findings/${alert.resource_id}` : { pathname: "/coverage", query: { project: alert.project } }}>{alert.kind === "sla" ? "Open finding" : "Review coverage"}</Link>
    </article>)}</div><Pagination count={alerts.data.count} offset={offset} limit={50} loading={alerts.loading} onPage={setOffset} /></>}
    <section className="space-y-3 rounded-xl border bg-white p-5 dark:border-gray-700 dark:bg-gray-800"><h2 className="text-lg font-semibold">Operations policies</h2><p className="text-sm">Policies are opt-in. Acknowledgement suppresses repeat reminders, while changed or recurring conditions need fresh attention. Slack uses the shared configured channel, not a direct message to the owner.</p><ErrorNotice message={settings.error} retry={settings.reload} />
      {settings.data && <><p className="text-xs">Slack delivery: {settings.data.slack_configured ? "configured" : "not configured"}</p>{!settings.data.policies.length && <p className="text-sm">No operations policies configured.</p>}<div className="space-y-2">{settings.data.policies.map(policy => <div key={policy.project} className="flex flex-wrap items-start justify-between gap-3 rounded-lg border p-3 dark:border-gray-700"><div className="min-w-0 text-sm"><h3 className="break-all font-semibold">{policy.project || "No project"} · {policy.enabled ? "enabled" : "paused"}</h3><p>Warn {policy.warn_before_hours}h before SLA · remind every {policy.reminder_hours}h · Slack {policy.notify_slack ? "on" : "off"}</p><p className="text-xs">Last evaluated: {date(policy.last_evaluated_at)} · Next: {date(policy.next_evaluation_at)}</p>{policy.last_error && <p className="mt-1 break-words text-amber-800 dark:text-amber-300">{policy.last_error}</p>}</div>{isAdmin && <div className="flex flex-wrap gap-2"><button className="button-secondary" disabled={busy} onClick={() => { setForm({ project: policy.project, enabled: policy.enabled, warn_before_hours: policy.warn_before_hours, reminder_hours: policy.reminder_hours, notify_slack: policy.notify_slack }); setEditing(true); }} aria-label={`Edit operations policy ${policy.project || "No project"}`}>Edit</button><button className="button-secondary" disabled={busy || !policy.enabled} onClick={() => void evaluate(policy.project)} aria-label={`Evaluate ${policy.project || "No project"}`}>Evaluate now</button></div>}</div>)}</div></>}
      {isAdmin && <form className="grid gap-3 border-t pt-4 sm:grid-cols-2 dark:border-gray-700" onSubmit={save}><h3 className="font-semibold sm:col-span-2">{editing ? "Edit operations policy" : "Create operations policy"}</h3><label className="grid gap-1 text-sm">Policy project<input className="input" required disabled={busy || editing} maxLength={255} value={form.project} onChange={event => setForm({ ...form, project: event.target.value })} placeholder="Exact project key from Catalog" /></label><label className="grid gap-1 text-sm">SLA warning lead time (hours)<input className="input" type="number" required min={1} max={168} value={form.warn_before_hours} onChange={event => setForm({ ...form, warn_before_hours: Number(event.target.value) })} /></label><label className="grid gap-1 text-sm">Reminder interval (hours)<input className="input" type="number" required min={1} max={168} value={form.reminder_hours} onChange={event => setForm({ ...form, reminder_hours: Number(event.target.value) })} /></label><div className="space-y-2"><label className="flex items-start gap-2 text-sm"><input type="checkbox" checked={form.enabled} onChange={event => setForm({ ...form, enabled: event.target.checked })} />Enable operations policy</label><label className="flex items-start gap-2 text-sm"><input type="checkbox" checked={form.notify_slack} onChange={event => setForm({ ...form, notify_slack: event.target.checked })} />Send reminders to the configured Slack channel</label></div><p className="text-xs sm:col-span-2">Create the project in Catalog first. Pausing a policy resolves its active alerts as disabled. Enabling Slack authorizes external delivery of the project&apos;s alert details.</p><div className="flex flex-wrap gap-2"><button className="button-primary" disabled={busy}>Save operations policy</button>{editing && <button type="button" className="button-secondary" disabled={busy} onClick={() => { setForm(empty); setEditing(false); }}>Cancel policy edit</button>}</div></form>}
    </section>
  </div>;
}
