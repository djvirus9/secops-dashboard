import { useEffect, useState } from "react";
import Link from "next/link";
import { apiGet } from "../lib/api";

type Finding = {
  id: string;
  fingerprint: string;
  tool: string;
  title: string;
  severity: string;
  asset: string;
  status: string;
  assignee: string | null;
  risk_score: number;
  occurrences: number;
  last_seen: string;
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-600 text-white",
  high: "bg-orange-500 text-white",
  medium: "bg-yellow-500 text-black",
  low: "bg-blue-500 text-white",
  info: "bg-gray-500 text-white",
};

const STATUS_COLORS: Record<string, string> = {
  open: "bg-red-100 text-red-800 dark:bg-red-900/50 dark:text-red-200",
  investigating: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/50 dark:text-yellow-200",
  resolved: "bg-green-100 text-green-800 dark:bg-green-900/50 dark:text-green-200",
  closed: "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200",
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
                <th className="text-left p-3">Status</th>
                <th className="text-left p-3">Title</th>
                <th className="text-left p-3">Asset</th>
                <th className="text-left p-3">Assignee</th>
                <th className="text-left p-3">Last seen</th>
                <th className="text-left p-3"></th>
              </tr>
            </thead>
            <tbody className="text-gray-900 dark:text-gray-100">
              {data.results.map((f) => (
                <tr key={f.id} className="border-t border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700/50">
                  <td className="p-3 font-semibold">{f.risk_score}</td>
                  <td className="p-3">
                    <span className={`px-2 py-1 rounded text-xs font-medium ${SEVERITY_COLORS[f.severity] || "bg-gray-400"}`}>
                      {f.severity}
                    </span>
                  </td>
                  <td className="p-3">
                    <span className={`px-2 py-1 rounded text-xs font-medium ${STATUS_COLORS[f.status] || ""}`}>
                      {f.status}
                    </span>
                  </td>
                  <td className="p-3">{f.title}</td>
                  <td className="p-3">{f.asset}</td>
                  <td className="p-3 text-gray-500 dark:text-gray-400">{f.assignee || "-"}</td>
                  <td className="p-3 text-gray-500 dark:text-gray-400">{new Date(f.last_seen).toLocaleDateString()}</td>
                  <td className="p-3">
                    <Link href={`/findings/${f.id}`} className="text-indigo-600 dark:text-indigo-400 hover:underline text-sm">
                      View
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
