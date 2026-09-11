import { useState, type FormEvent } from "react";
import { apiDelete, apiPatch, apiPost } from "../lib/api";
import { useApiResource } from "../lib/use-api-resource";
import { filterQuery, readFilters, type FindingFilters } from "../lib/finding-filters";
import { ErrorNotice } from "./feedback";

type SavedView = { id: string; name: string; filters: FindingFilters };
export function SavedViews({ filters, apply }: { filters: FindingFilters; apply: (filters: FindingFilters) => void }) {
  const { data, error, loading, reload } = useApiResource<{ results: SavedView[] }>("/saved-views");
  const [selected, setSelected] = useState(""); const [name, setName] = useState("");
  const [busy, setBusy] = useState(false); const [failure, setFailure] = useState(""); const [success, setSuccess] = useState("");
  const view = data?.results.find(item => item.id === selected);
  async function mutate(action: "create" | "rename" | "delete") {
    setBusy(true); setFailure(""); setSuccess("");
    try {
      if (action === "create") await apiPost("/saved-views", { name: name.trim(), filters: filterQuery(filters) });
      if (action === "rename" && view) await apiPatch(`/saved-views/${view.id}`, { name: name.trim() });
      if (action === "delete" && view) await apiDelete(`/saved-views/${view.id}`);
      setName(""); setSelected(""); setSuccess(action === "delete" ? "Saved view deleted." : "View saved."); reload();
    } catch (reason) { setFailure(reason instanceof Error ? reason.message : "Saved view update failed"); }
    finally { setBusy(false); }
  }
  return <section aria-label="Saved views" className="space-y-3 rounded-xl border p-4 dark:border-gray-700">
    <h2 className="font-semibold">Your saved views</h2>
    <p className="text-xs">Views are private to your account and save the applied filters.</p>
    <ErrorNotice message={error} retry={reload} /><ErrorNotice message={failure} />
    {success && <p role="status">{success}</p>}
    <div className="flex flex-wrap items-end gap-2">
      <label className="grid min-w-0 gap-1 text-sm">Saved view<select aria-label="Saved view" className="input" value={selected} disabled={busy || loading} onChange={e => { setSelected(e.target.value); setName(data?.results.find(item => item.id === e.target.value)?.name || ""); setSuccess(""); }}><option value="">Choose a view</option>{data?.results.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label>
      <button className="button-secondary" disabled={!view || busy} onClick={() => { if (view) apply(readFilters(view.filters)); }}>Apply saved view</button>
      <button className="button-secondary" disabled={!view || busy} onClick={() => { if (view && window.confirm(`Delete saved view “${view.name}”?`)) void mutate("delete"); }}>Delete view</button>
    </div>
    <form className="flex flex-wrap items-end gap-2" onSubmit={(event: FormEvent) => { event.preventDefault(); void mutate("create"); }}>
      <label className="grid min-w-0 gap-1 text-sm">View name<input className="input" required maxLength={100} value={name} onChange={e => setName(e.target.value)} /></label>
      <button className="button-secondary" disabled={busy || !name.trim()}>Save current filters</button>
      <button type="button" className="button-secondary" disabled={busy || !view || !name.trim()} onClick={() => void mutate("rename")}>Rename selected view</button>
    </form>
  </section>;
}
