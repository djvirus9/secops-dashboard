import { useRouter } from "next/router";
import { useEffect, useState } from "react";
import Link from "next/link";
import { apiGet, apiPatch, apiPost } from "../../lib/api";
import { ErrorNotice } from "../../components/feedback";

type Comment = {
  id: string;
  author: string;
  content: string;
  action_type: string | null;
  created_at: string;
};

type Finding = {
  id: string;
  fingerprint: string;
  tool: string;
  title: string;
  severity: string;
  asset: string;
  project?: string;
  component?: string | null;
  component_version?: string | null;
  asset_id: string | null;
  exposure: string;
  criticality: string;
  status: string;
  assignee: string | null;
  risk_score: number;
  occurrences: number;
  description: string | null;
  recommendation: string | null;
  cwe_id: number | null;
  cve_id: string | null;
  cvss_score: number | null;
  file_path: string | null;
  line_number: number | null;
  references: string[];
  tags: string[];
  first_seen: string;
  last_seen: string;
  signal_id: string;
  comments: Comment[];
  notifications?: { id: string; channel: string; status: string; last_error?: string | null }[];
};

const STATUS_OPTIONS = ["open", "investigating", "resolved", "closed"];

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

function safeReference(value: string): string | null {
  try {
    const parsed = new URL(value);
    return parsed.protocol === "https:" || parsed.protocol === "http:" ? parsed.href : null;
  } catch {
    return null;
  }
}

export default function FindingDetailPage() {
  const router = useRouter();
  const { id } = router.query;

  const [finding, setFinding] = useState<Finding | null>(null);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState("");
  const [actionError, setActionError] = useState("");
  const [success, setSuccess] = useState("");
  const [loadRevision, setLoadRevision] = useState(0);

  const [newStatus, setNewStatus] = useState("");
  const [newAssignee, setNewAssignee] = useState("");
  const [newComment, setNewComment] = useState("");
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!id) return;
    const controller = new AbortController();
    setLoading(true);
    setErr("");
    setActionError("");
    setFinding(null);
    apiGet<Finding>(`/findings/${id}`, { signal: controller.signal })
      .then((data) => {
        if (controller.signal.aborted) return;
        setFinding(data);
        setNewStatus(data.status);
        setNewAssignee(data.assignee || "");
      })
      .catch((error) => { if (!controller.signal.aborted) setErr(String(error?.message || error)); })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [id, loadRevision]);

  const refreshActivity = async (findingId: string) => {
    try {
      const refreshed = await apiGet<Finding>(`/findings/${findingId}`);
      setFinding(refreshed);
    } catch {
      setActionError("Saved successfully, but activity could not be refreshed. Refresh the finding to see the latest activity.");
    }
  };

  const handleUpdateFinding = async () => {
    if (!finding || saving) return;
    setSaving(true);
    setActionError("");
    setSuccess("");
    try {
      const updates: { status?: string; assignee?: string } = {};
      if (newStatus !== finding.status) updates.status = newStatus;
      if (newAssignee !== (finding.assignee || "")) updates.assignee = newAssignee;
      if (Object.keys(updates).length > 0) {
        const result = await apiPatch<{ finding: { status: string; assignee: string | null } }>(`/findings/${finding.id}`, updates);
        setFinding({ ...finding, ...result.finding });
        setNewStatus(result.finding.status);
        setNewAssignee(result.finding.assignee || "");
        setSuccess("Finding updated.");
        await refreshActivity(finding.id);
      }
    } catch (error: unknown) {
      setActionError(error instanceof Error ? error.message : "Could not update finding");
    } finally {
      setSaving(false);
    }
  };

  const handleAddComment = async () => {
    if (!finding || !newComment.trim() || saving) return;
    setSaving(true);
    setActionError("");
    setSuccess("");
    try {
      const result = await apiPost<{ comment: Comment }>(`/findings/${finding.id}/comments`, { content: newComment.trim() });
      setFinding({ ...finding, comments: [result.comment, ...finding.comments] });
      setNewComment("");
      setSuccess("Comment added.");
      await refreshActivity(finding.id);
    } catch (error: unknown) {
      setActionError(error instanceof Error ? error.message : "Could not add comment");
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return <div className="text-gray-600 dark:text-gray-300">Loading...</div>;
  }

  if (err) return <ErrorNotice message={err} retry={() => setLoadRevision((value) => value + 1)} />;

  if (!finding) {
    return <div className="text-gray-600 dark:text-gray-300">Finding not found</div>;
  }

  return (
    <div className="space-y-6">
      <ErrorNotice message={actionError} />
      {success && <p role="status" className="text-sm text-green-700 dark:text-green-300">{success}</p>}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <Link href="/findings" className="text-indigo-600 dark:text-indigo-400 hover:underline">
          &larr; Back to Findings
        </Link>
        <button className="button-secondary" disabled={saving} onClick={() => setLoadRevision((value) => value + 1)}>Refresh finding</button>
      </div>

      <div className="bg-white dark:bg-gray-800 rounded-xl border dark:border-gray-700 shadow-xs p-6 space-y-4">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h1 className="break-words text-2xl font-semibold text-gray-900 dark:text-white">{finding.title}</h1>
            <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
              {finding.tool} &middot; {finding.project && `${finding.project} / `}{finding.asset}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <span className={`px-3 py-1 rounded-full text-sm font-medium ${SEVERITY_COLORS[finding.severity] || "bg-gray-400"}`}>
              {finding.severity.toUpperCase()}
            </span>
            <span className={`px-3 py-1 rounded-full text-sm font-medium ${STATUS_COLORS[finding.status] || ""}`}>
              {finding.status}
            </span>
          </div>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 pt-4 border-t dark:border-gray-700">
          <div>
            <div className="text-xs text-gray-500 dark:text-gray-400 uppercase">Risk Score</div>
            <div className="text-xl font-bold text-gray-900 dark:text-white">{finding.risk_score}</div>
          </div>
          <div>
            <div className="text-xs text-gray-500 dark:text-gray-400 uppercase">Occurrences</div>
            <div className="text-xl font-bold text-gray-900 dark:text-white">{finding.occurrences}</div>
          </div>
          <div>
            <div className="text-xs text-gray-500 dark:text-gray-400 uppercase">Exposure</div>
            <div className="text-gray-900 dark:text-white">{finding.exposure}</div>
          </div>
          <div>
            <div className="text-xs text-gray-500 dark:text-gray-400 uppercase">Criticality</div>
            <div className="text-gray-900 dark:text-white">{finding.criticality}</div>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-4 pt-4 border-t dark:border-gray-700">
          <div>
            <div className="text-xs text-gray-500 dark:text-gray-400 uppercase">First Seen</div>
            <div className="text-gray-900 dark:text-white text-sm">{new Date(finding.first_seen).toLocaleString()}</div>
          </div>
          <div>
            <div className="text-xs text-gray-500 dark:text-gray-400 uppercase">Last Seen</div>
            <div className="text-gray-900 dark:text-white text-sm">{new Date(finding.last_seen).toLocaleString()}</div>
          </div>
        </div>

        {(finding.file_path || finding.cve_id || finding.cwe_id || finding.cvss_score) && (
          <div className="grid grid-cols-1 gap-4 border-t pt-4 dark:border-gray-700 md:grid-cols-4">
            {finding.file_path && (
              <div className="md:col-span-2">
                <div className="text-xs uppercase text-gray-500 dark:text-gray-400">Location</div>
                <div className="break-all font-mono text-sm text-gray-900 dark:text-white">
                  {finding.file_path}{finding.line_number ? `:${finding.line_number}` : ""}
                </div>
              </div>
            )}
            {finding.cve_id && <Detail label="CVE" value={finding.cve_id} />}
            {finding.cwe_id && <Detail label="CWE" value={`CWE-${finding.cwe_id}`} />}
            {finding.cvss_score !== null && <Detail label="CVSS" value={finding.cvss_score} />}
          </div>
        )}

        {(finding.component || finding.component_version) && <p className="break-words text-sm"><strong>Component:</strong> {finding.component || "Unknown"}{finding.component_version && ` @ ${finding.component_version}`}</p>}
        {finding.description && (
          <div className="border-t pt-4 dark:border-gray-700">
            <h2 className="text-sm font-semibold text-gray-900 dark:text-white">Description</h2>
            <p className="mt-1 whitespace-pre-wrap text-sm text-gray-700 dark:text-gray-300">{finding.description}</p>
          </div>
        )}

        {finding.recommendation && (
          <div className="border-t pt-4 dark:border-gray-700">
            <h2 className="text-sm font-semibold text-gray-900 dark:text-white">Recommendation</h2>
            <p className="mt-1 whitespace-pre-wrap text-sm text-gray-700 dark:text-gray-300">{finding.recommendation}</p>
          </div>
        )}

        {finding.tags.length > 0 && (
          <div className="flex flex-wrap gap-2 border-t pt-4 dark:border-gray-700">
            {finding.tags.map((tag) => (
              <span key={tag} className="rounded-sm bg-gray-100 px-2 py-1 text-xs text-gray-700 dark:bg-gray-700 dark:text-gray-200">
                {tag}
              </span>
            ))}
          </div>
        )}

        {finding.references.length > 0 && (
          <div className="border-t pt-4 dark:border-gray-700">
            <h2 className="text-sm font-semibold text-gray-900 dark:text-white">References</h2>
            <ul className="mt-2 list-disc space-y-1 pl-5 text-sm">
              {finding.references.map((reference) => {
                const href = safeReference(reference);
                return (
                  <li key={reference} className="break-all text-gray-700 dark:text-gray-300">
                    {href ? <a href={href} rel="noopener noreferrer" target="_blank" className="text-indigo-600 hover:underline dark:text-indigo-400">{reference}</a> : reference}
                  </li>
                );
              })}
            </ul>
          </div>
        )}
      </div>

      <div className="bg-white dark:bg-gray-800 rounded-xl border dark:border-gray-700 shadow-xs p-6 space-y-4">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Triage Actions</h2>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label htmlFor="finding-status" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Status</label>
            <select
              id="finding-status"
              disabled={saving}
              value={newStatus}
              onChange={(e) => setNewStatus(e.target.value)}
              className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
            >
              {STATUS_OPTIONS.map((s) => (
                <option key={s} value={s}>{s}</option>
              ))}
            </select>
          </div>
          <div>
            <label htmlFor="finding-assignee" className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Assignee</label>
            <input
              type="text"
              id="finding-assignee"
              maxLength={255}
              disabled={saving}
              value={newAssignee}
              onChange={(e) => setNewAssignee(e.target.value)}
              placeholder="e.g., john@company.com"
              className="w-full px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
            />
          </div>
        </div>

        <button
          onClick={handleUpdateFinding}
          disabled={saving || (newStatus === finding.status && newAssignee === (finding.assignee || ""))}
          className="px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {saving ? "Saving..." : "Update Finding"}
        </button>
      </div>

      {Boolean(finding.notifications?.length) && <section className="rounded-xl border bg-white p-5 dark:border-gray-700 dark:bg-gray-800"><h2 className="font-semibold">Notification delivery</h2><ul className="my-3 space-y-1 text-sm">{finding.notifications?.map((delivery) => <li key={delivery.id}>{delivery.channel}: {delivery.status.replaceAll("_", " ")}</li>)}</ul><Link href="/notifications" className="text-sm text-indigo-600 underline dark:text-indigo-400">Review delivery status</Link></section>}
      <div className="bg-white dark:bg-gray-800 rounded-xl border dark:border-gray-700 shadow-xs p-6 space-y-4">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Activity &amp; Comments</h2>

        <div className="space-y-4 border-b dark:border-gray-700 pb-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
            <input
              type="text"
              aria-label="Comment"
              maxLength={10000}
              disabled={saving}
              value={newComment}
              onChange={(e) => setNewComment(e.target.value)}
              placeholder="Add a comment..."
              className="md:col-span-2 px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
            />
            <button
              onClick={handleAddComment}
              disabled={saving || !newComment.trim()}
              className="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              Add Comment
            </button>
          </div>
        </div>

        <div className="space-y-3">
          {finding.comments.length === 0 ? (
            <div className="text-gray-500 dark:text-gray-400 text-sm">No activity yet</div>
          ) : (
            finding.comments.map((c) => (
              <div key={c.id} className="flex gap-3 p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg">
                <div className="w-8 h-8 rounded-full bg-indigo-500 flex items-center justify-center text-white text-sm font-medium">
                  {c.author.charAt(0).toUpperCase()}
                </div>
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-medium text-gray-900 dark:text-white">{c.author}</span>
                    {c.action_type === "update" && (
                      <span className="text-xs px-2 py-0.5 rounded-sm bg-blue-100 dark:bg-blue-900/50 text-blue-700 dark:text-blue-300">
                        system
                      </span>
                    )}
                    <span className="text-xs text-gray-500 dark:text-gray-400">
                      {new Date(c.created_at).toLocaleString()}
                    </span>
                  </div>
                  <p className="break-words text-gray-700 dark:text-gray-300 text-sm mt-1">{c.content}</p>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}

function Detail({ label, value }: { label: string; value: string | number }) {
  return (
    <div>
      <div className="text-xs uppercase text-gray-500 dark:text-gray-400">{label}</div>
      <div className="text-sm text-gray-900 dark:text-white">{value}</div>
    </div>
  );
}
