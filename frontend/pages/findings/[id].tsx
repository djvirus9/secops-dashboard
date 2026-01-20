import { useRouter } from "next/router";
import { useEffect, useState } from "react";
import Link from "next/link";
import { apiGet, apiPatch, apiPost } from "../../lib/api";

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
  asset_id: string | null;
  exposure: string;
  criticality: string;
  status: string;
  assignee: string | null;
  risk_score: number;
  occurrences: number;
  first_seen: string;
  last_seen: string;
  signal_id: string;
  comments: Comment[];
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

export default function FindingDetailPage() {
  const router = useRouter();
  const { id } = router.query;

  const [finding, setFinding] = useState<Finding | null>(null);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState("");

  const [newStatus, setNewStatus] = useState("");
  const [newAssignee, setNewAssignee] = useState("");
  const [newComment, setNewComment] = useState("");
  const [commentAuthor, setCommentAuthor] = useState("");
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!id) return;
    setLoading(true);
    apiGet<Finding>(`/findings/${id}`)
      .then((data) => {
        setFinding(data);
        setNewStatus(data.status);
        setNewAssignee(data.assignee || "");
      })
      .catch((e) => setErr(String(e?.message || e)))
      .finally(() => setLoading(false));
  }, [id]);

  const handleUpdateFinding = async () => {
    if (!finding) return;
    setSaving(true);
    try {
      const updates: { status?: string; assignee?: string } = {};
      if (newStatus !== finding.status) updates.status = newStatus;
      if (newAssignee !== (finding.assignee || "")) updates.assignee = newAssignee;

      if (Object.keys(updates).length > 0) {
        await apiPatch(`/findings/${finding.id}`, updates);
        const refreshed = await apiGet<Finding>(`/findings/${finding.id}`);
        setFinding(refreshed);
        setNewStatus(refreshed.status);
        setNewAssignee(refreshed.assignee || "");
      }
    } catch (e: any) {
      setErr(String(e?.message || e));
    } finally {
      setSaving(false);
    }
  };

  const handleAddComment = async () => {
    if (!finding || !newComment.trim() || !commentAuthor.trim()) return;
    setSaving(true);
    try {
      await apiPost(`/findings/${finding.id}/comments`, {
        author: commentAuthor.trim(),
        content: newComment.trim(),
      });
      const refreshed = await apiGet<Finding>(`/findings/${finding.id}`);
      setFinding(refreshed);
      setNewComment("");
    } catch (e: any) {
      setErr(String(e?.message || e));
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return <div className="text-gray-600 dark:text-gray-300">Loading...</div>;
  }

  if (err) {
    return (
      <div className="p-4 rounded bg-red-50 dark:bg-red-900/40 border border-red-300 dark:border-red-700 text-gray-900 dark:text-white">
        Error: {err}
      </div>
    );
  }

  if (!finding) {
    return <div className="text-gray-600 dark:text-gray-300">Finding not found</div>;
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4">
        <Link href="/findings" className="text-indigo-600 dark:text-indigo-400 hover:underline">
          &larr; Back to Findings
        </Link>
      </div>

      <div className="bg-white dark:bg-gray-800 rounded-xl border dark:border-gray-700 shadow-sm p-6 space-y-4">
        <div className="flex items-start justify-between gap-4">
          <div>
            <h1 className="text-2xl font-semibold text-gray-900 dark:text-white">{finding.title}</h1>
            <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
              {finding.tool} &middot; {finding.asset}
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
      </div>

      <div className="bg-white dark:bg-gray-800 rounded-xl border dark:border-gray-700 shadow-sm p-6 space-y-4">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Triage Actions</h2>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Status</label>
            <select
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
            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">Assignee</label>
            <input
              type="text"
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

      <div className="bg-white dark:bg-gray-800 rounded-xl border dark:border-gray-700 shadow-sm p-6 space-y-4">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Activity &amp; Comments</h2>

        <div className="space-y-4 border-b dark:border-gray-700 pb-4">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-2">
            <input
              type="text"
              value={commentAuthor}
              onChange={(e) => setCommentAuthor(e.target.value)}
              placeholder="Your name"
              className="px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
            />
            <input
              type="text"
              value={newComment}
              onChange={(e) => setNewComment(e.target.value)}
              placeholder="Add a comment..."
              className="md:col-span-2 px-3 py-2 rounded-lg border border-gray-300 dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
            />
            <button
              onClick={handleAddComment}
              disabled={saving || !newComment.trim() || !commentAuthor.trim()}
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
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <span className="font-medium text-gray-900 dark:text-white">{c.author}</span>
                    {c.action_type === "update" && (
                      <span className="text-xs px-2 py-0.5 rounded bg-blue-100 dark:bg-blue-900/50 text-blue-700 dark:text-blue-300">
                        system
                      </span>
                    )}
                    <span className="text-xs text-gray-500 dark:text-gray-400">
                      {new Date(c.created_at).toLocaleString()}
                    </span>
                  </div>
                  <p className="text-gray-700 dark:text-gray-300 text-sm mt-1">{c.content}</p>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
