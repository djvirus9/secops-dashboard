import { useAuth } from "../lib/auth";
import { useState } from "react";
import Link from "next/link";
import { useApiResource } from "../lib/use-api-resource";
import { ErrorNotice, Pagination } from "../components/feedback";

type ImportRun = {
  id: string; parser: string | null; filename: string | null; project: string; actor: string;
  status: "processing" | "completed" | "failed" | "interrupted"; imported: number; new_findings: number;
  deduplicated: number; error: string | null; created_at: string; completed_at: string | null;
};

export default function ImportsPage() {
  const { canWrite } = useAuth();
  const [offset, setOffset] = useState(0);
  const { data, error, loading, reload } = useApiResource<{ count: number; results: ImportRun[] }>("/imports", { offset, limit: 50 });
  return <div className="space-y-4">
    <div className="flex flex-wrap items-center justify-between gap-3">
      <h1 className="text-2xl font-semibold">Import history</h1>
      <div className="flex gap-2">{canWrite && <Link href="/integrations" className="button-secondary">Import a scan</Link>}<button className="button-secondary" onClick={reload} disabled={loading}>Refresh</button></div>
    </div>
    <p className="text-sm text-gray-600 dark:text-gray-400">Review scan processing results, failures, and the number of findings added or matched.</p>
    <ErrorNotice message={error} retry={reload} />
    {loading && <p role="status">Loading import history…</p>}
    {data && <>
      {!data.results.length ? <p>No imports recorded.</p> : <div className="overflow-x-auto rounded-xl border bg-white dark:border-gray-700 dark:bg-gray-800">
        <table className="min-w-full text-sm">
          <caption className="sr-only">Scan import history</caption>
          <thead><tr>{["Started", "Project / source", "Status", "Findings", "Imported by", "Details"].map((name) => <th className="p-3 text-left" scope="col" key={name}>{name}</th>)}</tr></thead>
          <tbody>{data.results.map((run) => <tr key={run.id} className="border-t dark:border-gray-700">
            <td className="p-3 whitespace-nowrap">{new Date(run.created_at).toLocaleString()}</td>
            <td className="p-3"><div className="font-medium">{run.project || "No project"}</div><div>{run.parser || "Auto-detect"}</div>{run.filename && <div className="max-w-xs break-words text-xs">{run.filename}</div>}</td>
            <td className="p-3"><span className={`rounded-sm px-2 py-1 text-xs font-medium ${run.status === "failed" || run.status === "interrupted" ? "bg-red-100 text-red-900 dark:bg-red-900/40 dark:text-red-200" : run.status === "completed" ? "bg-green-100 text-green-900 dark:bg-green-900/40 dark:text-green-200" : "bg-gray-100 text-gray-900 dark:bg-gray-700 dark:text-gray-100"}`}>{run.status}</span></td>
            <td className="p-3"><div>{run.imported} imported</div><div className="text-xs">{run.new_findings} new · {run.deduplicated} matched</div></td>
            <td className="p-3">{run.actor}</td>
            <td className="max-w-sm break-words p-3">{run.error || (run.completed_at ? `${run.status === "completed" ? "Completed" : "Ended"} ${new Date(run.completed_at).toLocaleString()}` : run.status === "processing" ? "Processing" : run.status === "interrupted" ? "Import interrupted; submit the report again." : "Import failed.")}</td>
          </tr>)}</tbody>
        </table>
      </div>}
      <Pagination count={data.count} offset={offset} limit={50} loading={loading} onPage={setOffset} />
    </>}
  </div>;
}
