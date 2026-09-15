import Link from "next/link";
import { useState } from "react";
import { useAuth } from "../lib/auth";
import type { Ownership } from "../lib/ownership";
import { useApiResource } from "../lib/use-api-resource";
import { ErrorNotice, Pagination } from "../components/feedback";

type Finding = { id: string; project: string; title: string; asset: string; severity: string; status: string; assignee?: string | null; ownership?: Ownership; priority_score: number; remediation_due_at: string | null; last_seen: string };
const limit = 50;
export default function MyQueuePage() {
  const { isAdmin, user } = useAuth();
  const [view, setView] = useState("personal");
  const [teamId, setTeamId] = useState("");
  const [offset, setOffset] = useState(0);
  const teams = useApiResource<{ teams?: { id: string; name: string }[]; results?: { id: string; name: string }[] }>(isAdmin ? "/catalog" : "/ownership/my-teams", undefined, view === "team");
  const { data, error, loading, reload } = useApiResource<{ count: number; overdue: number; results: Finding[] }>(view === "personal" ? "/my-queue" : "/ownership/queue", { offset, limit, ...(view === "personal" ? {} : { view, team_id: view === "team" ? teamId : undefined }) });
  const title = view === "personal" ? "My queue" : view === "team" ? "Team queue" : "Unassigned queue";
  return <div className="space-y-5">
    <header className="flex flex-wrap items-end justify-between gap-3"><div><p className="text-xs font-semibold uppercase tracking-[.18em] text-indigo-600 dark:text-indigo-400">Ownership worklists</p><h1 className="mt-1 text-3xl font-semibold">{title}</h1><p className="mt-2 text-sm text-gray-600 dark:text-gray-300">Active work ordered by priority and deadline. Every queue respects your project grants.</p></div><button className="button-secondary" disabled={loading} onClick={reload}>Refresh</button></header>
    <div className="flex flex-wrap gap-2" role="group" aria-label="Queue view">{[["personal", "My work"], ["team", "Team work"], ["unassigned", "Unassigned"]].map(([key, label]) => <button key={key} className={view === key ? "button-primary" : "button-secondary"} aria-pressed={view === key} onClick={() => { setView(key); setOffset(0); }}>{label}</button>)}</div>
    {view === "team" && <div className="max-w-md space-y-2"><label className="grid gap-1 text-sm">Queue team<select className="input" value={teamId} onChange={event => { setTeamId(event.target.value); setOffset(0); }}><option value="">All my teams</option>{(teams.data?.teams || teams.data?.results || []).map(team => <option key={team.id} value={team.id}>{team.name}</option>)}</select></label><ErrorNotice message={teams.error} retry={teams.reload} /><p className="text-xs">Team membership does not grant access to additional projects.</p></div>}
    {view === "unassigned" && <p className="rounded-lg border border-amber-300 bg-amber-50 p-3 text-sm dark:border-amber-800 dark:bg-amber-950/30">Includes findings without an owner and stored assignees who are no longer eligible. Open a finding to assign an active account with access.</p>}
    <ErrorNotice message={error} retry={reload} />{loading && <p role="status">Loading your queue…</p>}
    {data && <><section className="grid max-w-md grid-cols-2 gap-3" aria-label="Queue summary"><Metric label="Findings" value={data.count} /><Metric label="Overdue" value={data.overdue} danger={data.overdue > 0} /></section>
      {!data.results.length ? <p className="rounded-xl border p-6 dark:border-gray-700">No active findings in this queue.</p> : <div className="overflow-x-auto rounded-xl border bg-white dark:border-gray-700 dark:bg-gray-800"><table className="min-w-full text-sm"><caption className="sr-only">{title} findings</caption><thead><tr className="text-left">{["Priority", "Severity", "Finding", "Project / asset", "Owner", "Status", "Deadline"].map(label => <th key={label} className="p-3" scope="col">{label}</th>)}</tr></thead><tbody>{data.results.map(row => <tr key={row.id} className="border-t dark:border-gray-700"><td className="p-3 font-bold">{row.priority_score}</td><td className="p-3">{row.severity}</td><td className="p-3"><Link className="text-indigo-600 hover:underline dark:text-indigo-400" href={`/findings/${row.id}`}>{row.title}</Link></td><td className="p-3"><div className="font-medium">{row.project || "No project"}</div><div className="break-all text-xs">{row.asset}</div></td><td className="p-3"><span>{view === "personal" ? user?.username || "You" : row.assignee || "Unassigned"}</span>{row.ownership?.status === "invalid_assignee" && <div className="text-xs text-amber-800 dark:text-amber-300">Needs reassignment</div>}{row.ownership?.team_name && <div className="text-xs text-gray-500">{row.ownership.team_name}</div>}</td><td className="p-3">{row.status.replaceAll("_", " ")}</td><td className="whitespace-nowrap p-3">{row.remediation_due_at ? new Date(row.remediation_due_at).toLocaleDateString() : "Untracked"}</td></tr>)}</tbody></table></div>}
      <Pagination count={data.count} offset={offset} limit={limit} loading={loading} onPage={setOffset} />
    </>}
  </div>;
}
function Metric({ label, value, danger = false }: { label: string; value: number; danger?: boolean }) { return <div className="rounded-xl border bg-white p-4 dark:border-gray-700 dark:bg-gray-800"><div className="text-xs text-gray-500">{label}</div><div className={`mt-1 text-2xl font-bold ${danger ? "text-red-700 dark:text-red-300" : ""}`}>{value}</div></div>; }
