import { useEffect, useState } from "react";
import { apiGet, apiPost } from "../lib/api";

type Asset = {
  id: string;
  key: string;
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
  name: "",
  environment: "prod",
  owner: "",
  criticality: "medium",
  exposure: "internal",
};

export default function Assets() {
  const [data, setData] = useState<AssetsResponse | null>(null);
  const [err, setErr] = useState<string>("");
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState(defaultForm);
  const [saving, setSaving] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);

  const loadAssets = () => {
    apiGet<AssetsResponse>("/assets")
      .then(setData)
      .catch((e) => setErr(String(e?.message || e)));
  };

  useEffect(() => {
    loadAssets();
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!form.key.trim()) return;

    setSaving(true);
    try {
      await apiPost("/assets/upsert", form);
      setForm(defaultForm);
      setShowForm(false);
      setEditingId(null);
      loadAssets();
    } catch (err: any) {
      setErr(err?.message || "Failed to save asset");
    } finally {
      setSaving(false);
    }
  };

  const editAsset = (asset: Asset) => {
    setForm({
      key: asset.key,
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
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold text-gray-900 dark:text-white">Assets</h1>
          <p className="text-sm text-gray-600 dark:text-gray-400">
            Manage your infrastructure inventory with ownership and criticality.
          </p>
        </div>
        <button
          onClick={() => setShowForm(!showForm)}
          className="rounded-lg bg-black dark:bg-white px-4 py-2 text-sm font-medium text-white dark:text-black hover:opacity-80 transition-opacity"
        >
          {showForm ? "Cancel" : "Add Asset"}
        </button>
      </div>

      {err && (
        <div className="rounded-md border border-red-300 dark:border-red-800 bg-red-50 dark:bg-red-900/20 p-3 text-sm text-gray-900 dark:text-white">
          {err}
        </div>
      )}

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
                className="rounded-lg border dark:border-gray-600 px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700"
              >
                Cancel
              </button>
            )}
          </div>
        </form>
      )}

      {!data ? (
        <div className="text-gray-600 dark:text-gray-400">Loading...</div>
      ) : data.results.length === 0 ? (
        <div className="rounded-xl border dark:border-gray-700 bg-white dark:bg-gray-800 p-8 text-center shadow-sm">
          <p className="text-gray-600 dark:text-gray-400">No assets yet. Add your first asset or ingest signals to auto-create assets.</p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-xl border dark:border-gray-700 bg-white dark:bg-gray-800 shadow-sm">
          <table className="min-w-full text-sm">
            <thead className="bg-gray-50 dark:bg-gray-900 text-gray-700 dark:text-gray-200">
              <tr>
                <th className="text-left p-3">Key</th>
                <th className="text-left p-3">Name</th>
                <th className="text-left p-3">Owner</th>
                <th className="text-left p-3">Environment</th>
                <th className="text-left p-3">Criticality</th>
                <th className="text-left p-3">Exposure</th>
                <th className="text-left p-3">Updated</th>
                <th className="text-left p-3"></th>
              </tr>
            </thead>
            <tbody className="text-gray-900 dark:text-gray-100">
              {data.results.map((asset) => (
                <tr key={asset.id} className="border-t border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-750">
                  <td className="p-3 font-mono text-sm">{asset.key}</td>
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
      )}

      <p className="text-xs text-gray-500 dark:text-gray-400">
        {data?.count || 0} asset(s) in inventory. Assets are auto-created when ingesting signals.
      </p>
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
