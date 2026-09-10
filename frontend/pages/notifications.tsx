import { useState } from "react";
import Link from "next/link";
import { apiPost } from "../lib/api";
import { useApiResource } from "../lib/use-api-resource";
import { ErrorNotice, Pagination } from "../components/feedback";

type Delivery = {
  id: string; finding_id: string | null; channel: string;
  status: "pending" | "processing" | "sent" | "failed" | "needs_review";
  attempts: number; last_error: string | null; external_id: string | null; external_url: string | null;
  created_at: string; updated_at: string; next_attempt_at: string | null;
};
function externalLink(value: string | null) {
  if (!value) return null;
  try { const url = new URL(value); return ["http:", "https:"].includes(url.protocol) ? url.href : null; } catch { return null; }
}

export default function NotificationsPage() {
  const [offset, setOffset] = useState(0);
  const [confirmed, setConfirmed] = useState<Record<string, boolean>>({});
  const [retrying, setRetrying] = useState<string | null>(null);
  const [actionError, setActionError] = useState("");
  const [success, setSuccess] = useState("");
  const { data, error, loading, reload } = useApiResource<{ count: number; results: Delivery[] }>("/notifications", { offset, limit: 50 });
  const retry = async (delivery: Delivery) => {
    if (retrying || (delivery.status === "needs_review" && !confirmed[delivery.id])) return;
    setRetrying(delivery.id); setActionError(""); setSuccess("");
    const confirmedNoIssue = delivery.status === "needs_review" && confirmed[delivery.id] === true;
    setConfirmed((current) => ({ ...current, [delivery.id]: false }));
    try {
      await apiPost(`/notifications/${delivery.id}/retry`, { confirmed_no_issue: confirmedNoIssue });
      setSuccess("Delivery queued for retry. Refresh to check its progress.");
      reload();
    } catch (reason) { setActionError(reason instanceof Error ? reason.message : "Could not queue delivery"); }
    finally { setRetrying(null); }
  };
  return <div className="space-y-4">
    <div className="flex flex-wrap items-center justify-between gap-3"><h1 className="text-2xl font-semibold">Notification delivery</h1><button className="button-secondary" onClick={reload} disabled={loading || Boolean(retrying)}>Refresh</button></div>
    <p className="text-sm text-gray-600 dark:text-gray-400">Track queued notifications and confirmed deliveries. A queued notification has not been delivered yet.</p>
    <ErrorNotice message={error} retry={reload} /><ErrorNotice message={actionError} />
    {success && <p role="status" className="text-sm text-green-700 dark:text-green-300">{success}</p>}
    {loading && <p role="status">Loading delivery history…</p>}
    {data && <>
      {!data.results.length ? <p>No notification deliveries recorded.</p> : <div className="space-y-3">{data.results.map((delivery) => {
        const href = externalLink(delivery.external_url);
        return <article key={delivery.id} className="space-y-3 rounded-xl border bg-white p-4 dark:border-gray-700 dark:bg-gray-800">
          <div className="flex flex-wrap items-center justify-between gap-3"><h2 className="font-semibold capitalize">{delivery.channel} · {delivery.status.replaceAll("_", " ")}</h2><span className="text-sm">{delivery.attempts} attempt(s)</span></div>
          <p className="text-xs text-gray-600 dark:text-gray-400">Updated {new Date(delivery.updated_at).toLocaleString()}{delivery.next_attempt_at && delivery.status === "pending" ? ` · Next attempt ${new Date(delivery.next_attempt_at).toLocaleString()}` : ""}</p>
          {delivery.last_error && <p className="break-words text-sm">{delivery.last_error}</p>}
          <div className="flex flex-wrap gap-3 text-sm">
            {delivery.finding_id && <Link href={`/findings/${delivery.finding_id}`} className="text-indigo-600 underline dark:text-indigo-400">View finding</Link>}
            {href && <a href={href} target="_blank" rel="noopener noreferrer" className="text-indigo-600 underline dark:text-indigo-400">{delivery.external_id || "View external issue"}</a>}
          </div>
          {delivery.status === "needs_review" && <div className="space-y-2 rounded-lg bg-amber-50 p-3 text-sm text-amber-900 dark:bg-amber-900/20 dark:text-amber-200">
            <p>The delivery result is uncertain. Check Jira for an existing issue before retrying to avoid creating a duplicate.</p>
            <label className="flex items-start gap-2"><input type="checkbox" className="mt-1" checked={confirmed[delivery.id] || false} onChange={(event) => setConfirmed({ ...confirmed, [delivery.id]: event.target.checked })} />I checked Jira and confirmed no issue was created.</label>
          </div>}
          {(delivery.status === "failed" || delivery.status === "needs_review") && <button className="button-secondary" disabled={Boolean(retrying) || (delivery.status === "needs_review" && !confirmed[delivery.id])} onClick={() => retry(delivery)}>{retrying === delivery.id ? "Queueing…" : "Retry delivery"}</button>}
        </article>;
      })}</div>}
      <Pagination count={data.count} offset={offset} limit={50} loading={loading || Boolean(retrying)} onPage={(next) => { setConfirmed({}); setOffset(next); }} />
    </>}
  </div>;
}
