import { useState, type FormEvent } from "react";
import { apiPatch, apiPost } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useApiResource } from "../lib/use-api-resource";
import { ErrorNotice } from "../components/feedback";

type Team = { id: string; name: string; contact: string; active: boolean };
type Project = {
  name: string; display_name: string; team_id: string | null; team_name: string | null;
  business_unit: string; tier: string; repository_url: string; active: boolean;
};
type Catalog = { teams: Team[]; projects: Project[]; unmanaged_projects: string[] };

const teamInitial = { name: "", contact: "" };
const projectInitial = {
  name: "", display_name: "", team_id: "", business_unit: "", tier: "medium", repository_url: "",
};

export default function CatalogPage() {
  const { isAdmin } = useAuth();
  const { data, error, loading, reload } = useApiResource<Catalog>("/catalog");
  const [team, setTeam] = useState(teamInitial);
  const [project, setProject] = useState(projectInitial);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState("");
  const [success, setSuccess] = useState("");

  async function addTeam(event: FormEvent) {
    event.preventDefault(); setBusy(true); setFailure(""); setSuccess("");
    try {
      await apiPost("/catalog/teams", team);
      setTeam(teamInitial); setSuccess("Team created."); reload();
    } catch (reason) {
      setFailure(reason instanceof Error ? reason.message : "Unable to create team");
    } finally { setBusy(false); }
  }

  async function addProject(event: FormEvent) {
    event.preventDefault(); setBusy(true); setFailure(""); setSuccess("");
    try {
      await apiPost("/catalog/projects", { ...project, team_id: project.team_id || null });
      setProject(projectInitial); setSuccess("Project profile created."); reload();
    } catch (reason) {
      setFailure(reason instanceof Error ? reason.message : "Unable to create project profile");
    } finally { setBusy(false); }
  }

  async function toggle(kind: "teams" | "projects", row: Team | Project) {
    setBusy(true); setFailure(""); setSuccess("");
    try {
      const id = kind === "teams" ? (row as Team).id : encodeURIComponent((row as Project).name);
      await apiPatch(`/catalog/${kind}/${id}`, { active: !row.active });
      setSuccess(`${kind === "teams" ? "Team" : "Project"} updated.`); reload();
    } catch (reason) {
      setFailure(reason instanceof Error ? reason.message : "Unable to update catalog");
    } finally { setBusy(false); }
  }

  return <div className="space-y-6">
    <header>
      <p className="text-xs font-semibold uppercase tracking-[.18em] text-indigo-600 dark:text-indigo-400">Ownership</p>
      <h1 className="mt-1 text-3xl font-semibold">Project and team catalog</h1>
      <p className="mt-2 max-w-3xl text-sm text-gray-600 dark:text-gray-300">Add operational ownership and business context without changing the project keys used by existing findings, grants or scanner tokens.</p>
    </header>
    <ErrorNotice message={error || failure} retry={error ? reload : undefined} />
    {success && <p role="status" className="text-sm text-emerald-700 dark:text-emerald-300">{success}</p>}
    {loading && <p role="status">Loading catalog…</p>}
    {data && <>
      <section className="grid gap-4 lg:grid-cols-2">
        <div className="rounded-xl border bg-white p-5 dark:border-gray-700 dark:bg-gray-800">
          <h2 className="text-lg font-semibold">Teams</h2>
          {!data.teams.length ? <p className="mt-3 text-sm">No teams defined.</p> : <div className="mt-3 space-y-2">
            {data.teams.map(row => <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border p-3 text-sm dark:border-gray-700" key={row.id}>
              <div><div className="font-medium">{row.name}</div><div className="text-gray-500">{row.contact || "No escalation contact"} · {row.active ? "active" : "inactive"}</div></div>
              {isAdmin && <button className="button-secondary" disabled={busy} onClick={() => void toggle("teams", row)}>{row.active ? "Deactivate" : "Activate"}</button>}
            </div>)}
          </div>}
        </div>
        <div className="rounded-xl border bg-white p-5 dark:border-gray-700 dark:bg-gray-800">
          <h2 className="text-lg font-semibold">Unmanaged project keys</h2>
          <p className="mt-1 text-xs text-gray-500">Observed in findings, imports or coverage but missing an ownership profile.</p>
          {!data.unmanaged_projects.length ? <p className="mt-3 text-sm">Every observed project has a profile.</p> : <div className="mt-3 flex flex-wrap gap-2">
            {data.unmanaged_projects.map(name => isAdmin
              ? <button key={name} className="rounded-full border px-3 py-1 text-sm dark:border-gray-600" onClick={() => setProject({ ...projectInitial, name, display_name: name })}>{name}</button>
              : <span key={name} className="rounded-full border px-3 py-1 text-sm dark:border-gray-600">{name}</span>)}
          </div>}
        </div>
      </section>
      <section className="rounded-xl border bg-white p-5 dark:border-gray-700 dark:bg-gray-800">
        <h2 className="text-lg font-semibold">Managed projects</h2>
        {!data.projects.length ? <p className="mt-3 text-sm">No project profiles defined.</p> : <div className="mt-3 overflow-x-auto">
          <table className="min-w-full text-sm">
            <thead><tr className="text-left">{["Project", "Team", "Business unit", "Tier", "Repository", "State", ...(isAdmin ? ["Actions"] : [])].map(label => <th className="p-3" scope="col" key={label}>{label}</th>)}</tr></thead>
            <tbody>{data.projects.map(row => <tr className="border-t dark:border-gray-700" key={row.name}>
              <td className="p-3"><div className="font-medium">{row.display_name || row.name}</div><div className="font-mono text-xs text-gray-500">{row.name}</div></td>
              <td className="p-3">{row.team_name || "Unowned"}</td><td className="p-3">{row.business_unit || "—"}</td><td className="p-3">{row.tier}</td>
              <td className="max-w-xs break-all p-3">{row.repository_url ? <a className="text-indigo-600 underline dark:text-indigo-400" href={row.repository_url} target="_blank" rel="noopener noreferrer">{row.repository_url}</a> : "—"}</td>
              <td className="p-3">{row.active ? "active" : "inactive"}</td>
              {isAdmin && <td className="p-3"><button className="button-secondary" disabled={busy} onClick={() => void toggle("projects", row)}>{row.active ? "Deactivate" : "Activate"}</button></td>}
            </tr>)}</tbody>
          </table>
        </div>}
      </section>
    </>}
    {isAdmin && <section className="grid gap-4 lg:grid-cols-2">
      <form className="space-y-3 rounded-xl border bg-white p-5 dark:border-gray-700 dark:bg-gray-800" onSubmit={addTeam}>
        <h2 className="text-lg font-semibold">Create team</h2>
        <label className="grid gap-1 text-sm">Team name<input className="input" required maxLength={100} value={team.name} onChange={event => setTeam({ ...team, name: event.target.value })} /></label>
        <label className="grid gap-1 text-sm">Escalation contact<input className="input" maxLength={255} placeholder="security-team@example.com or #security" value={team.contact} onChange={event => setTeam({ ...team, contact: event.target.value })} /></label>
        <button className="button-primary" disabled={busy}>Create team</button>
      </form>
      <form className="grid gap-3 rounded-xl border bg-white p-5 sm:grid-cols-2 dark:border-gray-700 dark:bg-gray-800" onSubmit={addProject}>
        <h2 className="text-lg font-semibold sm:col-span-2">Create project profile</h2>
        <label className="grid gap-1 text-sm">Project key<input className="input" required maxLength={255} value={project.name} onChange={event => setProject({ ...project, name: event.target.value })} /></label>
        <label className="grid gap-1 text-sm">Display name<input className="input" maxLength={255} value={project.display_name} onChange={event => setProject({ ...project, display_name: event.target.value })} /></label>
        <label className="grid gap-1 text-sm">Owning team<select className="input" value={project.team_id} onChange={event => setProject({ ...project, team_id: event.target.value })}><option value="">Unowned</option>{data?.teams.filter(row => row.active).map(row => <option key={row.id} value={row.id}>{row.name}</option>)}</select></label>
        <label className="grid gap-1 text-sm">Business unit<input className="input" maxLength={255} value={project.business_unit} onChange={event => setProject({ ...project, business_unit: event.target.value })} /></label>
        <label className="grid gap-1 text-sm">Business tier<select className="input" value={project.tier} onChange={event => setProject({ ...project, tier: event.target.value })}><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></label>
        <label className="grid gap-1 text-sm">Repository URL<input className="input" type="url" maxLength={500} placeholder="https://github.com/owner/repository" value={project.repository_url} onChange={event => setProject({ ...project, repository_url: event.target.value })} /></label>
        <div className="sm:col-span-2"><button className="button-primary" disabled={busy}>Create project profile</button></div>
      </form>
    </section>}
  </div>;
}
