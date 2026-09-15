import { useEffect, useState, type FormEvent } from "react";
import { apiDelete, apiPut } from "../lib/api";
import { useApiResource } from "../lib/use-api-resource";
import type { User } from "../lib/auth";
import type { OwnershipRule } from "../lib/ownership";
import { AssigneeSelect } from "./assignee-select";
import { ErrorNotice } from "./feedback";

type Team = { id: string; name: string; active: boolean };
type Project = { name: string; team_id: string | null; active: boolean };

export function OwnershipControls({ teams, projects }: { teams: Team[]; projects: Project[] }) {
  const [teamId, setTeamId] = useState("");
  const [userId, setUserId] = useState("");
  const [project, setProject] = useState("");
  const [enabled, setEnabled] = useState(false);
  const [assignee, setAssignee] = useState("");
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState("");
  const [success, setSuccess] = useState("");
  const accounts = useApiResource<{ results: User[] }>("/users");
  const members = useApiResource<{ results: User[] }>(teamId ? `/ownership/teams/${teamId}/members` : "/users", undefined, Boolean(teamId));
  const rules = useApiResource<{ results: OwnershipRule[] }>("/ownership/rules", project ? { project } : undefined);
  const rule = rules.data?.results.find(row => row.project === project);
  useEffect(() => { setEnabled(rule?.enabled || false); setAssignee(rule?.default_assignee || ""); }, [project, rule]);
  async function membership(id: string, remove = false) {
    if (!teamId) return;
    setBusy(true); setFailure(""); setSuccess("");
    try {
      const path = `/ownership/teams/${teamId}/members/${id}`;
      if (remove) await apiDelete(path); else await apiPut(path, {});
      setUserId(""); members.reload(); rules.reload(); setSuccess(remove ? "Team member removed. Project grants are unchanged." : "Team member added. Project grants are unchanged.");
    } catch (reason) { setFailure(reason instanceof Error ? reason.message : "Unable to update membership"); }
    finally { setBusy(false); }
  }
  async function saveRule(event: FormEvent) {
    event.preventDefault(); setBusy(true); setFailure(""); setSuccess("");
    try {
      await apiPut("/ownership/rules", { enabled, default_assignee: assignee || null }, { query: { project } });
      rules.reload(); setSuccess("Ownership routing saved. Existing manual assignments are preserved.");
    } catch (reason) { setFailure(reason instanceof Error ? reason.message : "Unable to save routing"); }
    finally { setBusy(false); }
  }
  const available = accounts.data?.results.filter(user => user.active !== false && user.role !== "viewer" && !members.data?.results.some(member => member.id === user.id)) || [];
  return <section className="space-y-4 rounded-xl border bg-white p-5 dark:border-gray-700 dark:bg-gray-800">
    <div><h2 className="text-lg font-semibold">Ownership routing</h2><p className="mt-1 text-sm">Membership organizes work; it never grants project access. Routing is explicitly enabled per project. An optional default assignee must belong to the owning team and have project access.</p></div>
    <ErrorNotice message={failure} />{success && <p role="status" className="text-sm">{success}</p>}
    <div className="grid gap-6 lg:grid-cols-2">
      <div className="min-w-0 space-y-3">
        <h3 className="font-medium">Team membership</h3>
        <label className="grid gap-1 text-sm">Manage team<select className="input" value={teamId} disabled={busy} onChange={event => { setTeamId(event.target.value); setUserId(""); setFailure(""); setSuccess(""); }}><option value="">Choose a team</option>{teams.map(team => <option key={team.id} value={team.id}>{team.name}{team.active ? "" : " · inactive"}</option>)}</select></label>
        <ErrorNotice message={members.error} retry={members.reload} />
        {members.loading && <p role="status">Loading team members…</p>}
        {members.data && <><ul className="space-y-2">{members.data.results.map(member => <li key={member.id} className="flex flex-wrap items-center justify-between gap-2 rounded-lg border p-2 text-sm dark:border-gray-700"><span className="break-all">{member.username} · {member.role}{member.active === false ? " · inactive" : ""}</span><button className="button-secondary" disabled={busy} onClick={() => void membership(member.id, true)} aria-label={`Remove ${member.username} from team`}>Remove</button></li>)}</ul>{!members.data.results.length && <p className="text-sm">This team has no members.</p>}</>}
        <ErrorNotice message={accounts.error} retry={accounts.reload} />
        {teamId && <form className="flex flex-wrap items-end gap-2" onSubmit={event => { event.preventDefault(); void membership(userId); }}><label className="grid min-w-0 flex-1 gap-1 text-sm">Add team member<select className="input" value={userId} disabled={busy || accounts.loading || members.loading} required onChange={event => setUserId(event.target.value)}><option value="">Choose an active account</option>{available.map(user => <option key={user.id} value={user.id}>{user.username} · {user.role}</option>)}</select></label><button className="button-primary" disabled={busy || !userId || members.loading}>Add member</button></form>}
      </div>
      <form className="min-w-0 space-y-3" onSubmit={saveRule}>
        <h3 className="font-medium">Project assignment rule</h3>
        <label className="grid gap-1 text-sm">Routing project<select className="input" value={project} disabled={busy} required onChange={event => { setProject(event.target.value); setFailure(""); setSuccess(""); }}><option value="">Choose a managed project</option>{projects.map(row => <option key={row.name} value={row.name}>{row.name}{row.active ? "" : " · inactive"}</option>)}</select></label>
        <ErrorNotice message={rules.error} retry={rules.reload} />
        {project && <><p className="text-sm">Owning team: {rule?.team_name || teams.find(team => team.id === projects.find(row => row.name === project)?.team_id)?.name || "Unowned"}</p>
          <AssigneeSelect label="Default assignee" projects={[project]} value={assignee} current={rule?.default_assignee} onChange={setAssignee} disabled={busy} />
          <label className="flex items-start gap-2 text-sm"><input type="checkbox" checked={enabled} disabled={busy} onChange={event => setEnabled(event.target.checked)} />Enable ownership routing for this project</label>
          {rule?.warning && <p className="text-sm text-amber-800 dark:text-amber-300">{rule.warning}</p>}
          <p className="text-xs">If the default owner becomes ineligible, work remains visible in the unassigned queue. Routing does not overwrite a manual assignment.</p>
          <button className="button-primary" disabled={busy || rules.loading || Boolean(rules.error)}>Save routing</button></>}
      </form>
    </div>
  </section>;
}
