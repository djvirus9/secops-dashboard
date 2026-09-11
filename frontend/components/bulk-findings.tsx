import { useState, type FormEvent } from "react";
import { apiPost } from "../lib/api";
import { ErrorNotice } from "./feedback";

export function BulkFindings({ ids, done, pending }: { ids: string[]; done: (message: string) => void; pending: (busy: boolean) => void }) {
  const [status, setStatus] = useState(""); const [mode, setMode] = useState("unchanged"); const [assignee, setAssignee] = useState("");
  const [confirmed, setConfirmed] = useState(false); const [busy, setBusy] = useState(false); const [error, setError] = useState("");
  const destructive = ["resolved", "closed"].includes(status);
  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!ids.length || (!status && mode === "unchanged") || (destructive && !confirmed)) return;
    setBusy(true); pending(true); setError("");
    try {
      const result = await apiPost<{ updated: number }>("/findings/bulk", { ids, ...(status ? { status } : {}), ...(mode !== "unchanged" ? { assignee: mode === "clear" ? null : assignee.trim() } : {}) });
      done(`Updated ${result.updated} selected findings.`);
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Bulk update failed"); }
    finally { setBusy(false); pending(false); }
  }
  return <form className="space-y-3 rounded-xl border p-4 dark:border-gray-700" onSubmit={submit}>
    <h2 className="font-semibold">Update {ids.length} selected findings</h2>
    <p className="text-xs">Selection includes only the rows selected on this page.</p>
    <ErrorNotice message={error} />
    <div className="flex flex-wrap items-end gap-3">
      <label className="grid gap-1 text-sm">Bulk status<select aria-label="Bulk status" className="input" value={status} disabled={busy} onChange={e => { setStatus(e.target.value); setConfirmed(false); }}><option value="">Keep status</option>{["open", "investigating", "resolved", "closed"].map(value => <option key={value}>{value}</option>)}</select></label>
      <label className="grid gap-1 text-sm">Assignment action<select aria-label="Assignment action" className="input" value={mode} disabled={busy} onChange={e => setMode(e.target.value)}><option value="unchanged">Keep assignee</option><option value="assign">Assign to</option><option value="clear">Unassign</option></select></label>
      {mode === "assign" && <label className="grid gap-1 text-sm">Bulk assignee<input className="input" required maxLength={255} disabled={busy} value={assignee} onChange={e => setAssignee(e.target.value)} /></label>}
      <button className="button-primary" disabled={busy || (!status && mode === "unchanged") || (destructive && !confirmed) || (mode === "assign" && !assignee.trim())}>Apply to {ids.length} selected</button>
    </div>
    {destructive && <label className="flex items-start gap-2 text-sm"><input type="checkbox" checked={confirmed} disabled={busy} onChange={e => setConfirmed(e.target.checked)} />Confirm marking {ids.length} selected findings as {status}</label>}
  </form>;
}
