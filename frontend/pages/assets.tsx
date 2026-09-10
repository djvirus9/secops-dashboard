import { useState } from "react";
import { apiPost } from "../lib/api";
import { useApiResource } from "../lib/use-api-resource";
import { ErrorNotice, Pagination } from "../components/feedback";

type Asset = {
  id: string;
  key: string;
  project?: string;
  name: string;
  environment: string;
  owner: string;
  criticality: string;
  exposure: string;
  created_at: string;
  updated_at: string;
};

type AssetsResponse = {
  count: number;
  results: Asset[];
};

const defaultForm = {
  key: "",
  project: "",
  name: "",
  environment: "prod",
  owner: "",
  criticality: "medium",
  exposure: "internal",
};

export default function Assets() {
  const [offset, setOffset] = useState(0);
  const [search, setSearch] = useState({ q: "", project: "" });
  const [filters, setFilters] = useState(search);
  const { data, error, loading, reload: loadAssets } = useApiResource<AssetsResponse>("/assets", { ...filters, offset, limit: 50 });
  const [err, setErr] = useState<string>("");
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState(defaultForm);
  const [saving, setSaving] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.key.trim()) return;

    setSaving(true);
    setErr("");
    try {
      await apiPost("/assets/upsert", form);
      setForm(defaultForm);
      setShowForm(false);
      setEditingId(null);
      setOffset(0);
      loadAssets();
    } catch (err: any) {
      setErr(err?.message || "Failed to save asset");
    } finally {
      setSaving(false);
    }
  };

  const editAsset = (asset: Asset) => {
    setErr("");
    setForm({
      key: asset.key,
      project: asset.project || "",
      name: asset.name,
      environment: asset.environment,
      owner: asset.owner,
      criticality: asset.criticality,
      exposure: asset.exposure,
    });
    setEditingId(asset.id);
    setShowForm(true);
  };

  const cancelEdit = () => {
    setErr("");
    setForm(defaultForm);
    setShowForm(false);
    setEditingId(null);
  };

  const criticalityColor: Record<string, string> = {
    low: "bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400",
    medium: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400",
    high: "bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400",
  };

  const exposureColor: Record<string, string> = {
    internal: "bg-blue-100 text-blue-800 dark:bg-blue-900/30 dark:text-blue-400",
    internet: "bg-purple-100 text-purple-800 dark:bg-purple-900/30 dark:text-purple-400",
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold text-gray-900 dark:text-white">Assets</h1>
          <p className="text-sm text-gray-600 dark:text-gray-400">
            Manage your infrastructure inventory with ownership and criticality.
          </p>
        </div>
        <button
          onClick={() => { if (showForm) cancelEdit(); else { setForm(defaultForm); setEditingId(null); setErr(""); setShowForm(true); } }}
          disabled={saving}
          className="rounded-lg bg-black dark:bg-white px-4 py-2 text-sm font-medium text-white dark:text-black hover:opacity-80 transition-opacity"
        >
          {showForm ? "Cancel" : "Add Asset"}
        </button>
      </div>

      <form className="flex flex-wrap items-end gap-3" onSubmit={(event) => { event.preventDefault(); setOffset(0); setFilters({ ...search }); }}>
        <label className="grid gap-1 text-sm">Search assets<input className="input" value={search.q} onChange={(event) => setSearch({ ...search, q: event.target.value })} /></label>
        <label className="grid gap-1 text-sm">Filter by project<input className="input" value={search.project} onChange={(event) => setSearch({ ...search, project: event.target.value })} /></label>
        <button className="button-secondary" type="submit">Search</button>
        <button className="button-secondary" type="button" onClick={loadAssets} disabled={loading}>Refresh</button>
      </form>
      <ErrorNotice message={error} retry={loadAssets} />
      <ErrorNotice message={err} />

      {showForm && (
        <form onSubmit={handleSubmit} className="rounded-xl border dark:border-gray-700 bg-white dark:bg-gray-800 p-5 shadow-sm">
          <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            {editingId ? "Edit Asset" : "Add New Asset"}
          </h2>
          <div className="grid gap-4 md:grid-cols-2">
            <Field label="Key (unique identifier)">
              <input
                type="text"
                value={form.key}
                onChange={(e) => setForm({ ...form, key: e.target.value })}
                placeholder="e.g., api.prod.example.com"
                className="w-full rounded-md border dark:border-gray-600 px-3 py-2 text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                disabled={!!editingId}
              />
            </Field>
            <Field label="Project">
              <input className="input" value={form.project} disabled={!!editingId} onChange={(event) => setForm({ ...form, project: event.target.value })} placeholder="e.g., payments-api" />
            </Field>
            <Field label="Display Name">
              <input
                type="text"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                placeholder="e.g., Production API"
                className="w-full rounded-md border dark:border-gray-600 px-3 py-2 text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              />
            </Field>
            <Field label="Owner">
              <input
                type="text"
                value={form.owner}
                onChange={(e) => setForm({ ...form, owner: e.target.value })}
                placeholder="e.g., security-team"
                className="w-full rounded-md border dark:border-gray-600 px-3 py-2 text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              />
            </Field>
            <Field label="Environment">
              <select
                aria-label="Environment"
                value={form.environment}
                onChange={(e) => setForm({ ...form, environment: e.target.value })}
                className="w-full rounded-md border dark:border-gray-600 px-3 py-2 text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              >
                <option value="prod">Production</option>
                <option value="staging">Staging</option>
                <option value="dev">Development</option>
                <option value="unknown">Unknown</option>
              </select>
            </Field>
            <Field label="Criticality">
              <select
                aria-label="Criticality"
                value={form.criticality}
                onChange={(e) => setForm({ ...form, criticality: e.target.value })}
                className="w-full rounded-md border dark:border-gray-600 px-3 py-2 text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              >
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
              </select>
            </Field>
            <Field label="Exposure">
              <select
                aria-label="Exposure"
                value={form.exposure}
                onChange={(e) => setForm({ ...form, exposure: e.target.value })}
                className="w-full rounded-md border dark:border-gray-600 px-3 py-2 text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              >
                <option value="internal">Internal</option>
                <option value="internet">Internet-facing</option>
              </select>
            </Field>
          </div>
          <div className="mt-4 flex gap-2">
            <button
              type="submit"
              disabled={saving || !form.key.trim()}
              className="rounded-lg bg-black dark:bg-white px-4 py-2 text-sm font-medium text-white dark:text-black disabled:opacity-50"
            >
              {saving ? "Saving..." : editingId ? "Update Asset" : "Create Asset"}
            </button>
            {editingId && (
              <button
                type="button"
                onClick={cancelEdit}
                disabled={saving}
                className="rounded-lg border dark:border-gray-600 px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700"
              >
                Cancel
              </button>
            )}
          </div>
        </form>
      )}

      {loading && <p role="status">Loading assets…</p>}
      {data && (data.results.length === 0 ? (
        <div className="rounded-xl border dark:border-gray-700 bg-white dark:bg-gray-800 p-8 text-center shadow-sm">
          <p className="text-gray-600 dark:text-gray-400">No matching assets. Change the search or add your first asset.</p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-xl border dark:border-gray-700 bg-white dark:bg-gray-800 shadow-sm">
          <table className="min-w-full text-sm">
            <caption className="sr-only">Assets matching the current filters</caption>
            <thead className="bg-gray-50 dark:bg-gray-900 text-gray-700 dark:text-gray-200">
              <tr>
                <th scope="col" className="text-left p-3">Project / key</th>
                <th scope="col" className="text-left p-3">Name</th>
                <th scope="col" className="text-left p-3">Owner</th>
                <th scope="col" className="text-left p-3">Environment</th>
                <th scope="col" className="text-left p-3">Criticality</th>
                <th scope="col" className="text-left p-3">Exposure</th>
                <th scope="col" className="text-left p-3">Updated</th>
                <th scope="col" className="text-left p-3">Actions</th>
              </tr>
            </thead>
            <tbody className="text-gray-900 dark:text-gray-100">
              {data.results.map((asset) => (
                <tr key={asset.id} className="border-t border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700/50">
                  <td className="p-3 text-sm">{asset.project && <div className="font-medium">{asset.project}</div>}<span className="font-mono">{asset.key}</span></td>
                  <td className="p-3">{asset.name}</td>
                  <td className="p-3 text-gray-600 dark:text-gray-400">{asset.owner || "-"}</td>
                  <td className="p-3">
                    <span className="px-2 py-1 rounded text-xs bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300">
                      {asset.environment}
                    </span>
                  </td>
                  <td className="p-3">
                    <span className={`px-2 py-1 rounded text-xs font-medium ${criticalityColor[asset.criticality] || criticalityColor.medium}`}>
                      {asset.criticality}
                    </span>
                  </td>
                  <td className="p-3">
                    <span className={`px-2 py-1 rounded text-xs font-medium ${exposureColor[asset.exposure] || exposureColor.internal}`}>
                      {asset.exposure}
                    </span>
                  </td>
                  <td className="p-3 text-gray-500 dark:text-gray-400 text-xs">
                    {new Date(asset.updated_at).toLocaleDateString()}
                  </td>
                  <td className="p-3">
                    <button
                      onClick={() => editAsset(asset)}
                      disabled={saving}
                      aria-label={`Edit ${asset.name}`}
                      className="text-blue-600 dark:text-blue-400 hover:underline text-sm"
                    >
                      Edit
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ))}
      {data && <Pagination count={data.count} offset={offset} limit={50} loading={loading} onPage={setOffset} />}
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="grid gap-1">
      <span className="text-xs font-medium text-gray-600 dark:text-gray-400">{label}</span>
      {children}
    </label>
  );
}
