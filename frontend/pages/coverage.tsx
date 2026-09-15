import { useState, type FormEvent } from "react";
import { apiPatch, apiPost } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useApiResource } from "../lib/use-api-resource";
import { ErrorNotice } from "../components/feedback";

type Health = "healthy" | "stale" | "failing" | "missing" | "disabled";
type CoverageRow = {
  id: string; project: string; team: string | null; source_type: "scanner" | "github"; source: string;
  interval_hours: number; required: boolean; enabled: boolean; health: Health; last_status: string | null;
  last_successful_at: string | null; last_clean_at: string | null; last_findings: number | null; next_due_at: string | null;
};
type CoverageData = { count: number; required_attention: number; health: Record<Health, number>; results: CoverageRow[]; generated_at: string };
const initial = { project: "", source_type: "scanner" as "scanner" | "github", source: "", interval_hours: "24", required: true };
const colors: Record<Health, string> = {
  healthy: "bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-200",
  stale: "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-200",
  failing: "bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-200",
  missing: "bg-orange-100 text-orange-800 dark:bg-orange-950 dark:text-orange-200",
  disabled: "bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-200",
};
const when = (value: string | null) => value ? new Date(value).toLocaleString() : "Never";

export default function CoveragePage() {
  const { isAdmin } = useAuth();
  const { data, error, loading, reload } = useApiResource<CoverageData>("/coverage");
  const [form, setForm] = useState(initial); const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState(""); const [success, setSuccess] = useState("");
  async function create(event: FormEvent) {
    event.preventDefault(); setBusy(true); setFailure(""); setSuccess("");
    try {
      await apiPost("/coverage", { ...form, interval_hours: Number(form.interval_hours) });
      setForm(initial); setSuccess("Coverage expectation created."); reload();
    } catch (reason) { setFailure(reason instanceof Error ? reason.message : "Unable to create coverage expectation"); }
    finally { setBusy(false); }
  }
  async function toggle(row: CoverageRow) {
    setBusy(true); setFailure(""); setSuccess("");
    try { await apiPatch(`/coverage/${row.id}`, { enabled: !row.enabled }); setSuccess("Coverage expectation updated."); reload(); }
    catch (reason) { setFailure(reason instanceof Error ? reason.message : "Unable to update coverage expectation"); }
    finally { setBusy(false); }
  }
  return <div className="space-y-6">
    <header><p className="text-xs font-semibold uppercase tracking-[.18em] text-indigo-600 dark:text-indigo-400">Detection assurance</p><h1 className="mt-1 text-3xl font-semibold">Security coverage</h1><p className="mt-2 max-w-3xl text-sm text-gray-600 dark:text-gray-300">See what is healthy, stale, failing, or has never reported. Successful scanner imports with zero findings remain visible as clean evidence.</p></header>
    <ErrorNotice message={error || failure} retry={error ? reload : undefined} />{success && <p role="status" className="text-sm text-emerald-700 dark:text-emerald-300">{success}</p>}
    {loading && <p role="status">Loading security coverage…</p>}
    {data && <>
      <section className="grid gap-3 sm:grid-cols-3 lg:grid-cols-6" aria-label="Coverage summary">
        <Metric label="Expected" value={data.count} /><Metric label="Needs attention" value={data.required_attention} tone={data.required_attention ? "danger" : "ok"} />
        {(["healthy", "stale", "failing", "missing"] as Health[]).map(name => <Metric key={name} label={name} value={data.health[name] || 0} />)}
      </section>
      {!data.results.length ? <p className="rounded-xl border p-6 dark:border-gray-700">No coverage expectations exist yet. Add the scanners and repositories that every project must report.</p> : <div className="overflow-x-auto rounded-xl border bg-white dark:border-gray-700 dark:bg-gray-800"><table className="min-w-full text-sm"><caption className="sr-only">Security coverage expectations</caption><thead><tr className="text-left">{["Project / team", "Source", "Health", "Last success", "Last clean", "Next due", "Result", "Actions"].map(label => <th key={label} scope="col" className="p-3">{label}</th>)}</tr></thead><tbody>{data.results.map(row => <tr key={row.id} className="border-t dark:border-gray-700"><td className="p-3"><div className="font-medium">{row.project}</div><div className="text-xs text-gray-500">{row.team || "No owning team"}</div></td><td className="p-3"><div>{row.source}</div><div className="text-xs text-gray-500">{row.source_type} · every {row.interval_hours}h{row.required ? " · required" : ""}</div></td><td className="p-3"><span className={`rounded-full px-2.5 py-1 text-xs font-semibold ${colors[row.health]}`}>{row.health}</span></td><td className="whitespace-nowrap p-3">{when(row.last_successful_at)}</td><td className="whitespace-nowrap p-3">{when(row.last_clean_at)}</td><td className="whitespace-nowrap p-3">{when(row.next_due_at)}</td><td className="p-3">{row.last_status || "No report"}{row.last_findings !== null && <div className="text-xs text-gray-500">{row.last_findings} finding(s)</div>}</td><td className="p-3">{isAdmin && <button className="button-secondary" disabled={busy} onClick={() => void toggle(row)}>{row.enabled ? "Disable" : "Enable"}</button>}</td></tr>)}</tbody></table></div>}
    </>}
    {isAdmin && <form className="grid gap-3 rounded-xl border bg-white p-5 sm:grid-cols-2 lg:grid-cols-5 dark:border-gray-700 dark:bg-gray-800" onSubmit={create}><h2 className="text-lg font-semibold sm:col-span-2 lg:col-span-5">Add expected coverage</h2><label className="grid gap-1 text-sm">Project<input className="input" required maxLength={255} value={form.project} onChange={event => setForm({ ...form, project: event.target.value })} /></label><label className="grid gap-1 text-sm">Source type<select className="input" value={form.source_type} onChange={event => setForm({ ...form, source_type: event.target.value as "scanner" | "github" })}><option value="scanner">Scanner import</option><option value="github">GitHub repository</option></select></label><label className="grid gap-1 text-sm">{form.source_type === "github" ? "Repository" : "Parser name"}<input className="input" required maxLength={200} placeholder={form.source_type === "github" ? "owner/repository" : "semgrep"} value={form.source} onChange={event => setForm({ ...form, source: event.target.value })} /></label><label className="grid gap-1 text-sm">Expected every (hours)<input className="input" type="number" min="1" max="2160" required value={form.interval_hours} onChange={event => setForm({ ...form, interval_hours: event.target.value })} /></label><label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={form.required} onChange={event => setForm({ ...form, required: event.target.checked })} />Required control</label><div className="lg:col-span-5"><button className="button-primary" disabled={busy}>{busy ? "Saving…" : "Add expectation"}</button></div></form>}
  </div>;
}

function Metric({ label, value, tone }: { label: string; value: number; tone?: "danger" | "ok" }) {
  return <div className="rounded-xl border bg-white p-4 dark:border-gray-700 dark:bg-gray-800"><div className="text-xs capitalize text-gray-500 dark:text-gray-400">{label}</div><div className={`mt-1 text-2xl font-bold ${tone === "danger" ? "text-red-700 dark:text-red-300" : tone === "ok" ? "text-emerald-700 dark:text-emerald-300" : ""}`}>{value}</div></div>;
}
