import { useAuth } from "../../lib/auth";
import { useRouter } from "next/router";
import { useEffect, useState } from "react";
import Link from "next/link";
import { apiDelete, apiGet, apiPatch, apiPost } from "../../lib/api";
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
  priority_score: number;
  priority_reasons: { factor: string; points: number }[];
  occurrences: number;
  description: string | null;
  recommendation: string | null;
  cwe_id: number | null;
  cve_id: string | null;
  cvss_score: number | null;
  kev: boolean;
  kev_date_added: string | null;
  kev_due_date: string | null;
  kev_ransomware: boolean;
  epss_score: number | null;
  epss_percentile: number | null;
  intelligence_updated_at: string | null;
  file_path: string | null;
  line_number: number | null;
  references: string[];
  tags: string[];
  first_seen: string;
  last_seen: string;
  remediation_due_at: string | null;
  resolved_at: string | null;
  sla_status: "complete" | "accepted" | "untracked" | "overdue" | "due_soon" | "on_track";
  risk_acceptance: { status: "active" | "expired" | "none"; accepted_at: string | null; expires_at: string | null; accepted_by: string | null; reason: string | null };
  workflow: { disposition_reason: string | null; duplicate_of_id: string | null; verification_requested_at: string | null; verified_at: string | null; verified_by: string | null };
  signal_id: string;
  comments: Comment[];
  notifications?: { id: string; channel: string; status: string; last_error?: string | null }[];
};

const STATUS_OPTIONS = ["open", "investigating", "verification_pending", "resolved", "closed", "false_positive", "duplicate"];

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
  verification_pending: "bg-blue-100 text-blue-800 dark:bg-blue-900/50 dark:text-blue-200",
  resolved: "bg-green-100 text-green-800 dark:bg-green-900/50 dark:text-green-200",
  closed: "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200",
  false_positive: "bg-purple-100 text-purple-800 dark:bg-purple-900/50 dark:text-purple-200",
  duplicate: "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200",
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
  const { canWrite, isAdmin } = useAuth();
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
  const [dispositionReason, setDispositionReason] = useState("");
  const [duplicateOfId, setDuplicateOfId] = useState("");
  const [newComment, setNewComment] = useState("");
  const [acceptanceReason, setAcceptanceReason] = useState("");
  const [acceptanceExpiry, setAcceptanceExpiry] = useState("");
  const [minimumExpiry, setMinimumExpiry] = useState("");
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
        const defaultExpiry = new Date();
        setMinimumExpiry(defaultExpiry.toISOString().slice(0, 10));
        defaultExpiry.setUTCDate(defaultExpiry.getUTCDate() + 30);
        setAcceptanceExpiry((data.risk_acceptance.expires_at || defaultExpiry.toISOString()).slice(0, 10));
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
      const updates: { status?: string; assignee?: string; reason?: string; duplicate_of_id?: string } = {};
      if (newStatus !== finding.status) {
        updates.status = newStatus;
        if (["false_positive", "duplicate"].includes(newStatus)) updates.reason = dispositionReason.trim();
        if (newStatus === "duplicate") updates.duplicate_of_id = duplicateOfId.trim();
      }
      if (newAssignee !== (finding.assignee || "")) updates.assignee = newAssignee;
      if (Object.keys(updates).length > 0) {
        const result = await apiPatch<{ finding: Partial<Finding> & { status: string; assignee: string | null } }>(`/findings/${finding.id}`, updates);
        setFinding({ ...finding, ...result.finding });
        setNewStatus(result.finding.status);
        setNewAssignee(result.finding.assignee || "");
        setDispositionReason(""); setDuplicateOfId("");
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

  const handleAcceptRisk = async () => {
    if (!finding || saving || acceptanceReason.trim().length < 20 || !acceptanceExpiry) return;
    setSaving(true); setActionError(""); setSuccess("");
    try {
      await apiPost(`/findings/${finding.id}/risk-acceptance`, {
        reason: acceptanceReason.trim(), expires_at: `${acceptanceExpiry}T23:59:59Z`,
      });
      setAcceptanceReason(""); setSuccess("Risk acceptance recorded with an expiry.");
      await refreshActivity(finding.id);
    } catch (error) { setActionError(error instanceof Error ? error.message : "Could not accept risk"); }
    finally { setSaving(false); }
  };

  const handleRevokeAcceptance = async () => {
    if (!finding || saving) return;
    setSaving(true); setActionError(""); setSuccess("");
    try {
      await apiDelete(`/findings/${finding.id}/risk-acceptance`);
      setSuccess("Risk acceptance revoked."); await refreshActivity(finding.id);
    } catch (error) { setActionError(error instanceof Error ? error.message : "Could not revoke risk acceptance"); }
    finally { setSaving(false); }
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
            {finding.kev && <span className="rounded-full bg-red-700 px-3 py-1 text-sm font-semibold text-white">KEV</span>}
            <span className={`px-3 py-1 rounded-full text-sm font-medium ${SEVERITY_COLORS[finding.severity] || "bg-gray-400"}`}>
              {finding.severity.toUpperCase()}
            </span>
            <span className={`px-3 py-1 rounded-full text-sm font-medium ${STATUS_COLORS[finding.status] || ""}`}>
              {finding.status.replaceAll("_", " ")}
            </span>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-4 border-t pt-4 dark:border-gray-700 md:grid-cols-5">
          <div>
            <div className="text-xs text-gray-500 dark:text-gray-400 uppercase">Priority</div>
            <div className="text-xl font-bold text-indigo-700 dark:text-indigo-300">{finding.priority_score}/100</div>
          </div>
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

        <div className="grid gap-4 border-t pt-4 dark:border-gray-700 md:grid-cols-[1fr_1fr]">
          <div>
            <h2 className="text-sm font-semibold text-gray-900 dark:text-white">Why this priority?</h2>
            <ul className="mt-2 space-y-1 text-sm text-gray-700 dark:text-gray-300">{finding.priority_reasons.map(reason => <li key={reason.factor} className="flex justify-between gap-4"><span>{reason.factor}</span><strong>+{reason.points}</strong></li>)}</ul>
          </div>
          <div>
            <h2 className="text-sm font-semibold text-gray-900 dark:text-white">Remediation deadline</h2>
            <p className="mt-2 text-sm text-gray-700 dark:text-gray-300">{finding.remediation_due_at ? new Date(finding.remediation_due_at).toLocaleString() : "Not tracked"}</p>
            <span className={`mt-2 inline-block rounded-full px-2.5 py-1 text-xs font-semibold ${finding.sla_status === "overdue" ? "bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-200" : finding.sla_status === "accepted" ? "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-200" : "bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-200"}`}>{finding.sla_status.replace("_", " ")}</span>
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

        {finding.cve_id && <div className="grid gap-4 border-t pt-4 dark:border-gray-700 md:grid-cols-4">
          <Detail label="CISA KEV" value={finding.kev ? "Known exploited" : "Not listed"} />
          <Detail label="EPSS probability" value={finding.epss_score === null ? "Not enriched" : `${(finding.epss_score * 100).toFixed(2)}%`} />
          <Detail label="EPSS percentile" value={finding.epss_percentile === null ? "Not enriched" : `${(finding.epss_percentile * 100).toFixed(1)}th`} />
          <Detail label="Intelligence updated" value={finding.intelligence_updated_at ? new Date(finding.intelligence_updated_at).toLocaleString() : "Never"} />
          {finding.kev_due_date && <Detail label="CISA due date" value={finding.kev_due_date} />}
          {finding.kev_ransomware && <Detail label="Ransomware use" value="Known" />}
        </div>}

        {(finding.component || finding.component_version) && <p className="break-words text-sm"><strong>Component:</strong> {finding.component || "Unknown"}{finding.component_version && ` @ ${finding.component_version}`}</p>}
        {(finding.workflow.disposition_reason || finding.workflow.verification_requested_at || finding.workflow.verified_at) && <div className="grid gap-3 border-t pt-4 text-sm dark:border-gray-700 md:grid-cols-2"><div><h2 className="font-semibold">Remediation workflow</h2>{finding.workflow.verification_requested_at && <p className="mt-1">Verification requested {new Date(finding.workflow.verification_requested_at).toLocaleString()}</p>}{finding.workflow.verified_at && <p className="mt-1">Verified {new Date(finding.workflow.verified_at).toLocaleString()} by {finding.workflow.verified_by}</p>}{finding.workflow.disposition_reason && <p className="mt-1 whitespace-pre-wrap">{finding.workflow.disposition_reason}</p>}</div>{finding.workflow.duplicate_of_id && <div><div className="text-xs uppercase text-gray-500">Canonical finding</div><Link className="break-all text-indigo-600 underline dark:text-indigo-400" href={`/findings/${finding.workflow.duplicate_of_id}`}>{finding.workflow.duplicate_of_id}</Link></div>}</div>}
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

      {canWrite && <div className="bg-white dark:bg-gray-800 rounded-xl border dark:border-gray-700 shadow-xs p-6 space-y-4">
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
                <option key={s} value={s}>{s.replaceAll("_", " ")}</option>
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

        {["false_positive", "duplicate"].includes(newStatus) && <div className="grid gap-3 rounded-lg border border-amber-300 bg-amber-50 p-4 dark:border-amber-800 dark:bg-amber-950/30 md:grid-cols-2"><label className="grid gap-1 text-sm">Decision reason<textarea className="input min-h-24" minLength={20} maxLength={2000} required value={dispositionReason} onChange={event => setDispositionReason(event.target.value)} placeholder="Explain the validation evidence and why this disposition is correct (minimum 20 characters)." /></label>{newStatus === "duplicate" && <label className="grid content-start gap-1 text-sm">Canonical finding ID<input className="input" required pattern="[0-9a-fA-F-]{36}" value={duplicateOfId} onChange={event => setDuplicateOfId(event.target.value)} placeholder="UUID of the original finding" /></label>}</div>}

        <button
          onClick={handleUpdateFinding}
          disabled={saving || (newStatus === finding.status && newAssignee === (finding.assignee || "")) || (["false_positive", "duplicate"].includes(newStatus) && dispositionReason.trim().length < 20) || (newStatus === "duplicate" && !duplicateOfId.trim())}
          className="px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {saving ? "Saving..." : "Update Finding"}
        </button>
      </div>}

      {isAdmin && <section className="rounded-xl border bg-white p-6 shadow-xs dark:border-gray-700 dark:bg-gray-800">
        <div className="flex flex-wrap items-start justify-between gap-3"><div><h2 className="text-lg font-semibold text-gray-900 dark:text-white">Risk acceptance</h2><p className="mt-1 text-sm text-gray-600 dark:text-gray-300">An acceptance does not lower the technical priority. It pauses SLA escalation until its recorded expiry.</p></div>{finding.risk_acceptance.status !== "none" && <span className={`rounded-full px-2.5 py-1 text-xs font-semibold ${finding.risk_acceptance.status === "active" ? "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-200" : "bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-200"}`}>{finding.risk_acceptance.status}</span>}</div>
        {finding.risk_acceptance.status !== "none" && <div className="mt-4 rounded-lg bg-gray-50 p-4 text-sm dark:bg-gray-900/50"><p>{finding.risk_acceptance.reason}</p><p className="mt-2 text-xs text-gray-500 dark:text-gray-400">Approved by {finding.risk_acceptance.accepted_by} · expires {finding.risk_acceptance.expires_at ? new Date(finding.risk_acceptance.expires_at).toLocaleString() : "unknown"}</p><button className="button-secondary mt-3" disabled={saving} onClick={() => void handleRevokeAcceptance()}>Revoke acceptance</button></div>}
        <div className="mt-4 grid gap-3 md:grid-cols-[1fr_12rem_auto]"><label className="grid gap-1 text-sm">Business justification<textarea className="input min-h-24" maxLength={2000} value={acceptanceReason} onChange={event => setAcceptanceReason(event.target.value)} placeholder="Explain the business reason, compensating controls, and owner (minimum 20 characters)." /></label><label className="grid content-start gap-1 text-sm">Expires<input className="input" type="date" value={acceptanceExpiry} min={minimumExpiry || undefined} onChange={event => setAcceptanceExpiry(event.target.value)} /></label><div className="flex items-end"><button className="rounded-lg bg-amber-600 px-4 py-2 text-sm font-medium text-white disabled:opacity-50" disabled={saving || acceptanceReason.trim().length < 20 || !acceptanceExpiry} onClick={() => void handleAcceptRisk()}>{finding.risk_acceptance.status === "none" ? "Accept risk" : "Replace acceptance"}</button></div></div>
      </section>}

      {isAdmin && Boolean(finding.notifications?.length) && <section className="rounded-xl border bg-white p-5 dark:border-gray-700 dark:bg-gray-800"><h2 className="font-semibold">Notification delivery</h2><ul className="my-3 space-y-1 text-sm">{finding.notifications?.map((delivery) => <li key={delivery.id}>{delivery.channel}: {delivery.status.replaceAll("_", " ")}</li>)}</ul><Link href="/notifications" className="text-sm text-indigo-600 underline dark:text-indigo-400">Review delivery status</Link></section>}
      <div className="bg-white dark:bg-gray-800 rounded-xl border dark:border-gray-700 shadow-xs p-6 space-y-4">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Activity &amp; Comments</h2>

        {canWrite && <div className="space-y-4 border-b dark:border-gray-700 pb-4">
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
        </div>}

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
