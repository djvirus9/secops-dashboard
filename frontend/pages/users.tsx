import { useState, type FormEvent } from "react";
import { apiPatch, apiPost } from "../lib/api";
import { useAuth, type User } from "../lib/auth";
import { useApiResource } from "../lib/use-api-resource";
import { ErrorNotice } from "../components/feedback";

const empty = { username: "", password: "", role: "viewer" as User["role"], active: true, allProjects: false, unscoped: false, projects: "" };
export default function Users() {
  const auth = useAuth();
  const { data, error, loading, reload } = useApiResource<{ results: User[] }>("/users", undefined, auth.isAdmin);
  const [editing, setEditing] = useState<string | null>(null);
  const [form, setForm] = useState(empty); const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState(""); const [success, setSuccess] = useState("");
  function edit(user: User) {
    setEditing(user.id); setFailure(""); setSuccess("");
    setForm({ username: user.username, password: "", role: user.role, active: user.active !== false, allProjects: user.projects === null, unscoped: Boolean(user.projects?.includes("")), projects: user.projects?.filter(Boolean).join("\n") || "" });
  }
  async function submit(event: FormEvent) {
    event.preventDefault(); setBusy(true); setFailure(""); setSuccess("");
    const projects = form.role === "admin" || form.allProjects ? null : [...new Set([...form.projects.split("\n").map(p => p.trim()).filter(Boolean), ...(form.unscoped ? [""] : [])])];
    try {
      if (editing) await apiPatch(`/users/${editing}`, { role: form.role, active: form.active, projects, ...(form.password ? { password: form.password } : {}) });
      else await apiPost("/users", { username: form.username, password: form.password, role: form.role, projects });
      const changedSelf = editing === auth.user?.id;
      setForm(empty); setEditing(null); setSuccess("Account saved."); reload();
      if (changedSelf) await auth.reload();
    } catch (reason) { setFailure(reason instanceof Error ? reason.message : "Unable to save account"); }
    finally { setBusy(false); }
  }
  return <div className="space-y-5">
    <h1 className="text-2xl font-semibold">User accounts</h1>
    <p className="text-sm">Administrators manage the whole dashboard. Analysts can update assigned projects; viewers have read-only access. Project grants control access within this installation.</p>
    <ErrorNotice message={error} retry={reload} /><ErrorNotice message={failure} />
    {success && <p role="status">{success}</p>}
    <form className="grid gap-3 rounded-xl border bg-white p-5 sm:grid-cols-2 dark:border-gray-700 dark:bg-gray-800" onSubmit={submit}>
      <h2 className="text-lg font-semibold sm:col-span-2">{editing ? `Edit ${form.username}` : "Create account"}</h2>
      <label className="grid gap-1 text-sm">Username<input className="input" required maxLength={100} pattern={"[a-zA-Z0-9][a-zA-Z0-9._@\\-]{0,99}"} autoComplete="off" disabled={!!editing || busy} value={form.username} onChange={e => setForm({ ...form, username: e.target.value })} /></label>
      <label className="grid gap-1 text-sm">{editing ? "Reset password (optional)" : "Initial password"}<input aria-label={editing ? "Reset password (optional)" : "Initial password"} className="input" type="password" required={!editing} minLength={15} maxLength={1024} autoComplete="new-password" disabled={busy} value={form.password} onChange={e => setForm({ ...form, password: e.target.value })} /><span className="text-xs">At least 15 characters.</span></label>
      <label className="grid gap-1 text-sm">Role<select aria-label="Role" className="input" value={form.role} disabled={busy} onChange={e => setForm({ ...form, role: e.target.value as User["role"] })}><option value="viewer">Viewer</option><option value="analyst">Analyst</option><option value="admin">Administrator</option></select></label>
      {editing && <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={form.active} disabled={busy} onChange={e => setForm({ ...form, active: e.target.checked })} />Account active</label>}
      {form.role !== "admin" && <fieldset className="space-y-3 sm:col-span-2"><legend className="font-medium">Project access</legend>
        <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={form.allProjects} disabled={busy} onChange={e => setForm({ ...form, allProjects: e.target.checked })} />All projects, including future projects</label>
        {!form.allProjects && <><label className="grid gap-1 text-sm">Allowed projects (one per line)<textarea className="input" rows={3} disabled={busy} value={form.projects} onChange={e => setForm({ ...form, projects: e.target.value })} /></label>
          <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={form.unscoped} disabled={busy} onChange={e => setForm({ ...form, unscoped: e.target.checked })} />Include findings without a project</label>
          <p className="text-xs">An empty list grants no project access.</p></>}
      </fieldset>}
      {editing && <p className="text-sm sm:col-span-2">Changing access or resetting the password may require this user to sign in again. At least one active administrator must remain.</p>}
      <div className="flex gap-2"><button className="button-primary" disabled={busy}>{editing ? "Save account" : "Create account"}</button>{editing && <button type="button" className="button-secondary" disabled={busy} onClick={() => { setEditing(null); setForm(empty); setFailure(""); }}>Cancel editing</button>}</div>
    </form>
    {loading && <p role="status">Loading accounts…</p>}
    {data && <div className="overflow-x-auto rounded-xl border dark:border-gray-700"><table className="min-w-full text-sm"><caption className="sr-only">Dashboard accounts</caption><thead><tr>{["Username", "Role", "Projects", "State", "Actions"].map(label => <th scope="col" className="p-3 text-left" key={label}>{label}</th>)}</tr></thead><tbody>{data.results.map(user => <tr className="border-t dark:border-gray-700" key={user.id}><td className="p-3">{user.username}</td><td className="p-3">{user.role}</td><td className="max-w-xs break-words p-3">{user.projects === null ? "All projects" : user.projects.map(project => project || "No project").join(", ") || "No access"}</td><td className="p-3">{user.active === false ? "Disabled" : "Active"}</td><td className="p-3"><button className="button-secondary" aria-label={`Edit account ${user.username}`} disabled={busy} onClick={() => edit(user)}>Edit</button></td></tr>)}</tbody></table></div>}
  </div>;
}
