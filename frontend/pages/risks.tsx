import { useApiResource } from "../lib/use-api-resource";
import { ErrorNotice } from "../components/feedback";

type RiskRow = {
  asset: string;
  project?: string;
  total_findings: number;
  max_risk: number;
  avg_risk: number;
};

export default function Risks() {
  const { data, error, loading, reload } = useApiResource<{ count: number; results: RiskRow[] }>("/risks");

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-semibold text-gray-900 dark:text-white">Risks</h1>
      <ErrorNotice message={error} retry={reload} />
      <button className="button-secondary" onClick={reload} disabled={loading}>Refresh</button>
      {loading && <p role="status">Loading risks…</p>}
      {data?.results.length === 0 && <p>No active findings contribute to risk.</p>}
      {data && (
        <div className="grid gap-4">
          {data.results.map((r) => (
            <div key={`${r.project || ""}:${r.asset}`} className="rounded-xl border dark:border-gray-700 bg-white dark:bg-gray-800 p-5 shadow-sm">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="break-all font-mono text-sm text-gray-900 dark:text-white">{r.project && `${r.project} / `}{r.asset}</div>
                <span className="rounded-full border dark:border-gray-600 px-2 py-1 text-xs text-gray-700 dark:text-gray-300">max {r.max_risk}</span>
              </div>
              <div className="mt-3 grid grid-cols-3 gap-3 text-sm">
                <Metric label="Findings" value={r.total_findings} />
                <Metric label="Avg Risk" value={r.avg_risk} />
                <Metric label="Max Risk" value={r.max_risk} />
              </div>
            </div>
          ))}
        </div>
      )}
      <p className="text-xs text-gray-500 dark:text-gray-400">Active findings, sorted by highest risk.</p>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-lg border dark:border-gray-600 bg-gray-50 dark:bg-gray-700 p-3">
      <div className="text-xs text-gray-500 dark:text-gray-400">{label}</div>
      <div className="mt-1 text-lg font-semibold text-gray-900 dark:text-white">{value}</div>
    </div>
  );
}
