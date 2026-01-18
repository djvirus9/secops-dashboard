import { useEffect, useState } from "react";
import { apiGet } from "../lib/api";

type Finding = {
  id: string;
  fingerprint: string;
  tool: string;
  title: string;
  severity: string;
  asset: string;
  status: string;
  risk_score: number;
  occurrences: number;
  last_seen: string;
};

export default function FindingsPage() {
  const [data, setData] = useState<{ count: number; results: Finding[] } | null>(null);
  const [err, setErr] = useState<string>("");

  useEffect(() => {
    apiGet<{ count: number; results: Finding[] }>("/findings")
      .then(setData)
      .catch((e) => setErr(String(e?.message || e)));
  }, []);

  return (
    <div className="space-y-4">
      <h1 className="text-2xl font-semibold text-gray-900 dark:text-white">Findings</h1>

      {err && <div className="mb-4 p-3 rounded bg-red-50 dark:bg-red-900/40 border border-red-300 dark:border-red-700 text-gray-900 dark:text-white">Error: {err}</div>}

      {!data ? (
        <div className="text-gray-600 dark:text-gray-300">Loading...</div>
      ) : (
        <div className="overflow-x-auto rounded-xl border dark:border-gray-700 bg-white dark:bg-gray-800 shadow-sm">
          <table className="min-w-full text-sm">
            <thead className="bg-gray-50 dark:bg-gray-900 text-gray-700 dark:text-gray-200">
              <tr>
                <th className="text-left p-3">Risk</th>
                <th className="text-left p-3">Severity</th>
                <th className="text-left p-3">Tool</th>
                <th className="text-left p-3">Title</th>
                <th className="text-left p-3">Asset</th>
                <th className="text-left p-3">Occur</th>
                <th className="text-left p-3">Last seen</th>
              </tr>
            </thead>
            <tbody className="text-gray-900 dark:text-gray-100">
              {data.results.map((f) => (
                <tr key={f.id} className="border-t border-gray-200 dark:border-gray-700">
                  <td className="p-3 font-semibold">{f.risk_score}</td>
                  <td className="p-3">{f.severity}</td>
                  <td className="p-3">{f.tool}</td>
                  <td className="p-3">{f.title}</td>
                  <td className="p-3">{f.asset}</td>
                  <td className="p-3">{f.occurrences}</td>
                  <td className="p-3 text-gray-500 dark:text-gray-400">{f.last_seen}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
