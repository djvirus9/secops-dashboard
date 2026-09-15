import { useEffect, useMemo, useState } from "react";
import { useRouter } from "next/router";
import { useAuth } from "../lib/auth";
import { downloadFindings } from "../lib/api";
import { filterQuery, initialFilters, readFilters, type FindingFilters } from "../lib/finding-filters";
import { SavedViews } from "../components/saved-views";
import { BulkFindings } from "../components/bulk-findings";
import Link from "next/link";
import { useApiResource } from "../lib/use-api-resource";
import { ErrorNotice, Pagination } from "../components/feedback";

type Finding = {
  id: string; tool: string; title: string; severity: string; asset: string;
  project?: string; status: string; assignee: string | null; risk_score: number; priority_score: number;
  kev: boolean; epss_percentile: number | null; remediation_due_at: string | null; sla_status: string; last_seen: string;
};
type Page = { count: number; page_count: number; offset: number; results: Finding[] };
const limit = 50;

export default function FindingsPage() {
  const router = useRouter(); const { canWrite } = useAuth();
  const filters = useMemo(() => readFilters(router.query), [router.query]);
  const rawOffset = typeof router.query.offset === "string" ? Number(router.query.offset) : 0;
  const offset = Number.isSafeInteger(rawOffset) && rawOffset >= 0 ? rawOffset : 0;
  const [draft, setDraft] = useState(initialFilters);
  const [selected, setSelected] = useState<string[]>([]);
  const [busy, setBusy] = useState(false); const [exporting, setExporting] = useState(false);
  const [actionError, setActionError] = useState(""); const [success, setSuccess] = useState("");
  const stateKey = JSON.stringify({ ...filters, offset });
  const { data, error, loading, reload } = useApiResource<Page>("/findings", { ...filters, limit, offset }, router.isReady);
  useEffect(() => { setDraft(filters); setSelected([]); setSuccess(""); }, [stateKey]);
  const navigate = (next: FindingFilters, nextOffset = 0) => { setSelected([]); void router.push({ pathname: "/findings", query: filterQuery(next, nextOffset) }, undefined, { shallow: true }); };
  async function exportCsv() {
    setExporting(true); setActionError("");
    try { await downloadFindings(filters); } catch (reason) { setActionError(reason instanceof Error ? reason.message : "Export failed"); }
    finally { setExporting(false); }
  }
  const field = (name: keyof typeof draft, label: string) => <label className="grid gap-1 text-sm" key={name}>
    {label}<input className="input" value={draft[name]} onChange={(event) => setDraft({ ...draft, [name]: event.target.value })} />
  </label>;

  return <div className="space-y-4">
    <div className="flex flex-wrap items-center justify-between gap-3">
      <h1 className="text-2xl font-semibold">Findings</h1>
      <div className="flex gap-2"><button className="button-secondary" onClick={() => { setSelected([]); reload(); }} disabled={loading || busy}>Refresh</button><button className="button-secondary" onClick={() => void exportCsv()} disabled={exporting}>Export matching CSV</button></div>
    </div>
    <form className="grid gap-3 rounded-xl border bg-white p-4 sm:grid-cols-2 lg:grid-cols-4 dark:border-gray-700 dark:bg-gray-800" onSubmit={(event) => {
      event.preventDefault(); navigate(readFilters(draft));
    }}>
      {field("q", "Search findings")}
      <label className="grid gap-1 text-sm">Severity
        <select aria-label="Severity" className="input" value={draft.severity} onChange={(event) => setDraft({ ...draft, severity: event.target.value })}>
          <option value="">All severities</option>
          {["critical", "high", "medium", "low", "info"].map((value) => <option key={value}>{value}</option>)}
        </select>
      </label>
      <label className="grid gap-1 text-sm">Status
        <select aria-label="Status" className="input" value={draft.status} onChange={(event) => setDraft({ ...draft, status: event.target.value })}>
          <option value="">All statuses</option>
          {["open", "investigating", "verification_pending", "resolved", "closed", "false_positive", "duplicate"].map((value) => <option key={value} value={value}>{value.replaceAll("_", " ")}</option>)}
        </select>
      </label>
      <label className="grid gap-1 text-sm">Sort
        <select aria-label="Sort" className="input" value={draft.sort} onChange={(event) => setDraft({ ...draft, sort: event.target.value })}>
          <option value="priority_desc">Highest priority first</option><option value="risk_desc">Highest contextual risk</option><option value="last_seen_desc">Most recently seen</option>
        </select>
      </label>
      {field("project", "Project")}{field("tool", "Tool")}{field("assignee", "Assignee")}
      <label className="grid gap-1 text-sm">Known exploited
        <select aria-label="Known exploited" className="input" value={draft.kev} onChange={event => setDraft({ ...draft, kev: event.target.value })}><option value="">All findings</option><option value="true">CISA KEV only</option><option value="false">Not listed in KEV</option></select>
      </label>
      <label className="grid gap-1 text-sm">Remediation SLA
        <select aria-label="Remediation SLA" className="input" value={draft.sla} onChange={event => setDraft({ ...draft, sla: event.target.value })}><option value="">All SLA states</option><option value="overdue">Overdue</option><option value="due_soon">Due within 7 days</option><option value="accepted">Accepted risk</option><option value="on_track">On track</option></select>
      </label>
      <div className="flex items-end gap-2">
        <button disabled={busy} className="rounded-lg bg-indigo-600 px-3 py-2 text-sm text-white" type="submit">Apply filters</button>
        <button className="button-secondary" type="button" disabled={busy} onClick={() => navigate(initialFilters)}>Clear</button>
      </div>
    </form>
    <SavedViews filters={filters} apply={next => navigate(next)} />
    <ErrorNotice message={error} retry={reload} />
    <ErrorNotice message={actionError} />
    {success && <p role="status">{success}</p>}
    {canWrite && selected.length > 0 && <BulkFindings key={selected.join(",")} ids={selected} projects={[...new Set(data?.results.filter(row => selected.includes(row.id)).map(row => row.project || "") || [])]} pending={setBusy} done={message => { setSuccess(message); setSelected([]); reload(); }} />}
    {loading && <p role="status">Loading findings…</p>}
    {data && <>
      {data.results.length === 0 ? <p className="rounded-xl border p-6 dark:border-gray-700">No findings match these filters.</p> :
        <div className="overflow-x-auto rounded-xl border bg-white shadow-xs dark:border-gray-700 dark:bg-gray-800">
          <table className="min-w-full text-sm">
            <caption className="sr-only">Security findings matching the current filters</caption>
            <thead className="bg-gray-50 dark:bg-gray-900"><tr>
              {canWrite && <th className="p-3"><input type="checkbox" aria-label="Select all findings on this page" disabled={busy || loading} checked={data.results.length > 0 && selected.length === data.results.length} onChange={event => setSelected(event.target.checked ? data.results.map(f => f.id) : [])} /></th>}
              {["Priority", "Severity", "SLA", "Title", "Project / asset", "Assignee", "Last seen", "Actions"].map((label) => <th key={label} scope="col" className="p-3 text-left">{label}</th>)}
            </tr></thead>
            <tbody>{data.results.map((finding) => <tr key={finding.id} className="border-t hover:bg-gray-50 dark:border-gray-700 dark:hover:bg-gray-700/50">
              {canWrite && <td className="p-3"><input type="checkbox" aria-label={`Select ${finding.title}`} disabled={busy || loading} checked={selected.includes(finding.id)} onChange={event => setSelected(event.target.checked ? [...selected, finding.id] : selected.filter(id => id !== finding.id))} /></td>}
              <td className="p-3"><strong className={finding.priority_score >= 80 ? "text-red-700 dark:text-red-300" : ""}>{finding.priority_score}</strong><span className="text-xs text-gray-400">/100</span></td>
              <td className="p-3"><span className={`rounded-sm px-2 py-1 text-xs font-medium ${finding.severity === "critical" || finding.severity === "high" ? "bg-red-100 text-red-900 dark:bg-red-900/50 dark:text-red-200" : "bg-gray-100 text-gray-900 dark:bg-gray-700 dark:text-gray-100"}`}>{finding.severity}</span></td>
              <td className="p-3"><span className={`rounded-full px-2 py-1 text-xs font-medium ${finding.sla_status === "overdue" ? "bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-200" : finding.sla_status === "accepted" ? "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-200" : "bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-200"}`}>{finding.sla_status.replace("_", " ")}</span>{finding.remediation_due_at && <div className="mt-1 whitespace-nowrap text-xs text-gray-500">{new Date(finding.remediation_due_at).toLocaleDateString()}</div>}</td>
              <td className="p-3"><Link href={`/findings/${finding.id}`} className="text-indigo-600 hover:underline dark:text-indigo-400">{finding.title}</Link><div className="mt-1 flex flex-wrap gap-1 text-xs text-gray-500 dark:text-gray-400"><span>{finding.tool}</span>{finding.kev && <span className="rounded bg-red-700 px-1.5 text-white">KEV</span>}{finding.epss_percentile !== null && finding.epss_percentile >= .9 && <span className="rounded bg-orange-100 px-1.5 text-orange-900 dark:bg-orange-950 dark:text-orange-200">EPSS {(finding.epss_percentile * 100).toFixed(0)}th</span>}</div></td>
              <td className="p-3">{finding.project && <div className="font-medium">{finding.project}</div>}{finding.asset}</td>
              <td className="p-3">{finding.assignee || "Unassigned"}</td>
              <td className="p-3 whitespace-nowrap">{new Date(finding.last_seen).toLocaleDateString()}</td>
              <td className="p-3"><Link href={`/findings/${finding.id}`} aria-label={`View ${finding.title}`} className="text-indigo-600 hover:underline dark:text-indigo-400">View</Link></td>
            </tr>)}</tbody>
          </table>
        </div>}
      <Pagination count={data.count} offset={offset} limit={limit} loading={loading || busy} onPage={value => navigate(filters, value)} />
    </>}
  </div>;
}
