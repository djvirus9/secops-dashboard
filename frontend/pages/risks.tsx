import { useEffect, useState } from "react";

type RiskRow = {
  asset: string;
  total_findings: number;
  max_risk: number;
  avg_risk: number;
};

export default function Risks() {
  const [data, setData] = useState<{ count: number; results: RiskRow[] } | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    const run = async () => {
      try {
        setErr(null);
        const r = await fetch("/api/risks", { cache: "no-store" } as any);
        const j = await r.json();
        if (!r.ok) throw new Error(j?.detail || `HTTP ${r.status}`);
        setData(j);
      } catch (e: any) {
        setErr(e?.message || "Failed to load risks");
      }
    };
    run();
  }, []);

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-semibold">Risks</h1>
      {err && <div className="rounded-md border border-red-300 bg-red-50 p-3 text-sm">❌ {err}</div>}
      {!data ? (
        <div className="text-sm text-gray-600">Loading...</div>
      ) : (
        <div className="grid gap-4">
          {data.results.map((r) => (
            <div key={r.asset} className="rounded-xl border bg-white p-5 shadow-sm">
              <div className="flex items-center justify-between">
                <div className="font-mono text-sm">{r.asset}</div>
                <span className="rounded-full border px-2 py-1 text-xs">max {r.max_risk}</span>
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
      <p className="text-xs text-gray-500">Sorted by max risk, then count.</p>
    </div>
  );
}

function Metric({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-lg border p-3">
      <div className="text-xs text-gray-500">{label}</div>
      <div className="mt-1 text-lg font-semibold">{value}</div>
    </div>
  );
}
