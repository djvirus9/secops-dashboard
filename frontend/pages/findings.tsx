import { useEffect, useState } from "react";

type Finding = {
  id: string;
  tool: string;
  title: string;
  severity: string;
  asset: string;
  status: string;
  risk_score: number;
  last_seen: string;
};

export default function Findings() {
  const [data, setData] = useState<{ count: number; results: Finding[] } | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    const run = async () => {
      try {
        setErr(null);
        const r = await fetch("/api/findings", { cache: "no-store" } as any);
        const j = await r.json();
        if (!r.ok) throw new Error(j?.detail || `HTTP ${r.status}`);
        setData(j);
      } catch (e: any) {
        setErr(e?.message || "Failed to load findings");
      }
    };
    run();
  }, []);

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-semibold">Findings</h1>
      {err && <div className="rounded-md border border-red-300 bg-red-50 p-3 text-sm">❌ {err}</div>}
      {!data ? (
        <div className="text-sm text-gray-600">Loading...</div>
      ) : (
        <div className="rounded-xl border bg-white shadow-sm overflow-auto">
          <table className="w-full text-sm">
            <thead className="border-b bg-gray-50">
              <tr>
                <th className="p-3 text-left">Severity</th>
                <th className="p-3 text-left">Risk</th>
                <th className="p-3 text-left">Title</th>
                <th className="p-3 text-left">Asset</th>
                <th className="p-3 text-left">Tool</th>
                <th className="p-3 text-left">Status</th>
                <th className="p-3 text-left">Last Seen</th>
              </tr>
            </thead>
            <tbody>
              {data.results.map((f) => (
                <tr key={f.id} className="border-b last:border-b-0">
                  <td className="p-3">
                    <span className="rounded-full border px-2 py-1 text-xs">{f.severity.toUpperCase()}</span>
                  </td>
                  <td className="p-3 font-mono">{f.risk_score}</td>
                  <td className="p-3">{f.title}</td>
                  <td className="p-3 font-mono">{f.asset}</td>
                  <td className="p-3">{f.tool}</td>
                  <td className="p-3">{f.status}</td>
                  <td className="p-3 font-mono">{f.last_seen}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <p className="text-xs text-gray-500">Tip: Go to Dashboard and submit a test signal, then refresh.</p>
    </div>
  );
}
