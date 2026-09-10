import { useState } from "react";
import Link from "next/link";
import { useApiResource } from "../lib/use-api-resource";
import { ErrorNotice, Pagination } from "../components/feedback";

type Finding = {
  id: string; tool: string; title: string; severity: string; asset: string;
  project?: string; status: string; assignee: string | null; risk_score: number; last_seen: string;
};
type Page = { count: number; page_count: number; offset: number; results: Finding[] };
const initialFilters = { q: "", severity: "", status: "", assignee: "", tool: "", project: "", sort: "risk_desc" };
const limit = 50;

export default function FindingsPage() {
  const [draft, setDraft] = useState(initialFilters);
  const [filters, setFilters] = useState(initialFilters);
  const [offset, setOffset] = useState(0);
  const { data, error, loading, reload } = useApiResource<Page>("/findings", { ...filters, limit, offset });
  const field = (name: keyof typeof draft, label: string) => <label className="grid gap-1 text-sm" key={name}>
    {label}<input className="input" value={draft[name]} onChange={(event) => setDraft({ ...draft, [name]: event.target.value })} />
  </label>;

  return <div className="space-y-4">
    <div className="flex flex-wrap items-center justify-between gap-3">
      <h1 className="text-2xl font-semibold">Findings</h1>
      <button className="button-secondary" onClick={reload} disabled={loading}>Refresh</button>
    </div>
    <form className="grid gap-3 rounded-xl border bg-white p-4 sm:grid-cols-2 lg:grid-cols-4 dark:border-gray-700 dark:bg-gray-800" onSubmit={(event) => {
      event.preventDefault(); setOffset(0); setFilters({ ...draft });
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
          {["open", "investigating", "resolved", "closed"].map((value) => <option key={value}>{value}</option>)}
        </select>
      </label>
      <label className="grid gap-1 text-sm">Sort
        <select aria-label="Sort" className="input" value={draft.sort} onChange={(event) => setDraft({ ...draft, sort: event.target.value })}>
          <option value="risk_desc">Highest risk first</option><option value="last_seen_desc">Most recently seen</option>
        </select>
      </label>
      {field("project", "Project")}{field("tool", "Tool")}{field("assignee", "Assignee")}
      <div className="flex items-end gap-2">
        <button className="rounded-lg bg-indigo-600 px-3 py-2 text-sm text-white" type="submit">Apply filters</button>
        <button className="button-secondary" type="button" onClick={() => { setDraft(initialFilters); setFilters(initialFilters); setOffset(0); }}>Clear</button>
      </div>
    </form>
    <ErrorNotice message={error} retry={reload} />
    {loading && <p role="status">Loading findings…</p>}
    {data && <>
      {data.results.length === 0 ? <p className="rounded-xl border p-6 dark:border-gray-700">No findings match these filters.</p> :
        <div className="overflow-x-auto rounded-xl border bg-white shadow-sm dark:border-gray-700 dark:bg-gray-800">
          <table className="min-w-full text-sm">
            <caption className="sr-only">Security findings matching the current filters</caption>
            <thead className="bg-gray-50 dark:bg-gray-900"><tr>
              {["Risk", "Severity", "Status", "Title", "Project / asset", "Assignee", "Last seen", "Actions"].map((label) => <th key={label} scope="col" className="p-3 text-left">{label}</th>)}
            </tr></thead>
            <tbody>{data.results.map((finding) => <tr key={finding.id} className="border-t hover:bg-gray-50 dark:border-gray-700 dark:hover:bg-gray-700/50">
              <td className="p-3 font-semibold">{finding.risk_score}</td>
              <td className="p-3"><span className={`rounded px-2 py-1 text-xs font-medium ${finding.severity === "critical" || finding.severity === "high" ? "bg-red-100 text-red-900 dark:bg-red-900/50 dark:text-red-200" : "bg-gray-100 text-gray-900 dark:bg-gray-700 dark:text-gray-100"}`}>{finding.severity}</span></td>
              <td className="p-3">{finding.status}</td>
              <td className="p-3"><Link href={`/findings/${finding.id}`} className="text-indigo-600 hover:underline dark:text-indigo-400">{finding.title}</Link><div className="text-xs text-gray-500 dark:text-gray-400">{finding.tool}</div></td>
              <td className="p-3">{finding.project && <div className="font-medium">{finding.project}</div>}{finding.asset}</td>
              <td className="p-3">{finding.assignee || "Unassigned"}</td>
              <td className="p-3 whitespace-nowrap">{new Date(finding.last_seen).toLocaleDateString()}</td>
              <td className="p-3"><Link href={`/findings/${finding.id}`} aria-label={`View ${finding.title}`} className="text-indigo-600 hover:underline dark:text-indigo-400">View</Link></td>
            </tr>)}</tbody>
          </table>
        </div>}
      <Pagination count={data.count} offset={offset} limit={limit} loading={loading} onPage={setOffset} />
    </>}
  </div>;
}
