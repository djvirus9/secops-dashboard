import { useEligibleAssignees } from "../lib/ownership";
import { ErrorNotice } from "./feedback";

export function AssigneeSelect({ label = "Assignee", projects, value, onChange, current, disabled, required = false }: {
  label?: string; projects: string[]; value: string; onChange: (value: string) => void;
  current?: string | null; disabled?: boolean; required?: boolean;
}) {
  const { users, error, loading, truncated, reload } = useEligibleAssignees(projects);
  const unknownCurrent = current && !users.some(user => user.username === current);
  return <div className="min-w-0 space-y-1">
    <label className="grid gap-1 text-sm">{label}<select className="input w-full min-w-0" aria-label={label} value={value} onChange={event => onChange(event.target.value)} disabled={disabled || loading || Boolean(error)} required={required}>
      <option value="">{required ? "Choose an eligible account" : "Unassigned"}</option>
      {unknownCurrent && <option value={current} disabled>{current} · current, not in eligible options</option>}
      {users.map(user => <option key={user.id} value={user.username}>{user.username}</option>)}
    </select></label>
    {loading && <p className="text-xs" role="status">Loading eligible assignees…</p>}
    <ErrorNotice message={error} retry={reload} />
    {!loading && !error && unknownCurrent && <p className="text-xs text-amber-800 dark:text-amber-300">The stored assignee is retained. Select an eligible account to reassign; project access is checked again when saving.</p>}
    {!loading && !error && !users.length && <p className="text-xs">No eligible accounts for {projects.length > 1 ? "every selected project" : "this project"}. An administrator can review account grants.</p>}
    {truncated && <p className="text-xs">Showing the first 200 eligible accounts per project. Some accounts may not appear in this selection.</p>}
  </div>;
}
