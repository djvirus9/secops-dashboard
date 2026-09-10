import { useMemo, useState } from "react";
import { apiPost } from "../lib/api";
import Link from "next/link";
import { useApiResource } from "../lib/use-api-resource";
import { ErrorNotice } from "../components/feedback";

type Health = { status: string };
type Summary = {
  total_findings: number;
  active_findings: number;
  resolved_findings: number;
  critical_findings: number;
  assets: number;
  active_by_severity: Record<string, number>;
};
type SubmitResult = {
  accepted: boolean;
  deduped: boolean;
  finding_id: string;
  risk_score: number;
  occurrences: number;
};

export default function Dashboard() {
  const { data: health, error: healthErr, loading: healthLoading, reload: reloadHealth } = useApiResource<Health>("/health");
  const { data: summary, error: summaryError, loading: summaryLoading, reload: loadSummary } = useApiResource<Summary>("/dashboard/summary");
  const [project, setProject] = useState("");

  const [tool, setTool] = useState("nuclei");
  const [severity, setSeverity] = useState("high");
  const [title, setTitle] = useState("Open redirect");
  const [asset, setAsset] = useState("api.prod.example.com");
  const [exposure, setExposure] = useState("internet");
  const [criticality, setCriticality] = useState("high");

  const [submitRes, setSubmitRes] = useState<SubmitResult | null>(null);
  const [submitErr, setSubmitErr] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const payload = useMemo(
    () => ({ tool, severity, title, asset, exposure, criticality, project }),
    [tool, severity, title, asset, exposure, criticality, project]
  );

  const submit = async () => {
    try {
      setSubmitting(true);
      setSubmitErr(null);
      setSubmitRes(null);

      const result = await apiPost<SubmitResult>("/ingest/signal", payload);
      setSubmitRes(result);
      loadSummary();
    } catch (error: unknown) {
      setSubmitErr(error instanceof Error ? error.message : "Submit failed");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold text-gray-900 dark:text-white">Dashboard</h1>
        <p className="text-sm text-gray-600 dark:text-gray-400">Vulnerability management dashboard — ingest, triage, and track findings across your stack.</p>
      </div>

      <ErrorNotice message={summaryError} retry={loadSummary} />
      <ErrorNotice message={healthErr} retry={reloadHealth} />
      {summaryLoading && <p role="status" className="text-sm">Loading summary…</p>}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
        <Card title="API Status">
          {health ? (
            <div className="space-y-2">
              <div className="inline-flex rounded-full border dark:border-gray-600 px-2 py-1 text-sm text-gray-900 dark:text-white">✅ {health.status}</div>
              <div className="text-xs text-gray-500 dark:text-gray-400">API available</div>
            </div>
          ) : (
            <div className="space-y-2">
              <div className="rounded-md border border-red-300 bg-red-50 dark:bg-red-900/20 dark:border-red-800 p-3 text-sm text-gray-900 dark:text-white">
                {healthLoading ? "Checking API…" : "API unavailable"}<br />
                <span className="text-xs text-gray-600 dark:text-gray-400">{healthErr}</span>
              </div>
            </div>
          )}
        </Card>
        <MetricCard label="Active" value={summary?.active_findings} tone="text-orange-600 dark:text-orange-400" />
        <MetricCard label="Critical" value={summary?.critical_findings} tone="text-red-600 dark:text-red-400" />
        <MetricCard label="Resolved" value={summary?.resolved_findings} tone="text-green-600 dark:text-green-400" />
        <MetricCard label="Assets" value={summary?.assets} tone="text-indigo-600 dark:text-indigo-400" />
      </div>

      <div className="flex flex-wrap gap-3 text-sm"><Link href="/findings" className="button-secondary">Triage findings</Link><Link href="/integrations" className="button-secondary">Import scan results</Link></div>
      <details className="rounded-xl border p-4 dark:border-gray-700"><summary className="cursor-pointer font-medium">Send a manual signal</summary>
      <div className="mt-4 grid gap-4 md:grid-cols-2">
        <Card title="Manual signal">
          <div className="grid gap-3">
            <Field label="Project"><input className="input" value={project} onChange={(event) => setProject(event.target.value)} placeholder="e.g., payments-api" /></Field>
            <Field label="Tool">
              <input className="w-full rounded-md border dark:border-gray-600 px-3 py-2 text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-white" value={tool} onChange={(e) => setTool(e.target.value)} />
            </Field>

            <div className="grid gap-3 md:grid-cols-2">
              <Field label="Severity">
                <select className="w-full rounded-md border dark:border-gray-600 px-3 py-2 text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-white" aria-label="Severity" value={severity} onChange={(e) => setSeverity(e.target.value)}>
                  <option value="info">info</option>
                  <option value="low">low</option>
                  <option value="medium">medium</option>
                  <option value="high">high</option>
                  <option value="critical">critical</option>
                </select>
              </Field>
              <Field label="Exposure">
                <select className="w-full rounded-md border dark:border-gray-600 px-3 py-2 text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-white" aria-label="Exposure" value={exposure} onChange={(e) => setExposure(e.target.value)}>
                  <option value="internal">internal</option>
                  <option value="internet">internet</option>
                </select>
              </Field>
            </div>

            <div className="grid gap-3 md:grid-cols-2">
              <Field label="Criticality">
                <select className="w-full rounded-md border dark:border-gray-600 px-3 py-2 text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-white" aria-label="Criticality" value={criticality} onChange={(e) => setCriticality(e.target.value)}>
                  <option value="low">low</option>
                  <option value="medium">medium</option>
                  <option value="high">high</option>
                </select>
              </Field>
              <Field label="Asset">
                <input className="w-full rounded-md border dark:border-gray-600 px-3 py-2 text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-white" value={asset} onChange={(e) => setAsset(e.target.value)} />
              </Field>
            </div>

            <Field label="Title">
              <input className="w-full rounded-md border dark:border-gray-600 px-3 py-2 text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-white" value={title} onChange={(e) => setTitle(e.target.value)} />
            </Field>

            <button
              onClick={submit}
              disabled={submitting}
              className="rounded-md bg-black dark:bg-white px-4 py-2 text-sm font-medium text-white dark:text-black disabled:opacity-60"
            >
              {submitting ? "Submitting..." : "Submit"}
            </button>

            {submitErr && <div className="rounded-md border border-red-300 bg-red-50 dark:bg-red-900/20 dark:border-red-800 p-3 text-sm text-gray-900 dark:text-white">❌ {submitErr}</div>}
            {submitRes && (
              <div className="rounded-md border dark:border-gray-600 bg-white dark:bg-gray-700 p-3">
                <div className="text-sm font-medium text-gray-900 dark:text-white">Response</div>
                <pre className="mt-2 overflow-auto rounded-md bg-gray-50 dark:bg-gray-800 p-3 text-xs text-gray-900 dark:text-gray-100">
{JSON.stringify(submitRes, null, 2)}
                </pre>
              </div>
            )}
          </div>
        </Card>

        <Card title="Payload Preview">
          <pre className="overflow-auto rounded-md bg-gray-50 dark:bg-gray-800 p-4 text-xs text-gray-900 dark:text-gray-100">
{JSON.stringify(payload, null, 2)}
          </pre>
          <p className="mt-2 text-xs text-gray-500 dark:text-gray-400">This becomes normalized into Finding + Risk on the backend.</p>
        </Card>
      </div>
      </details>
    </div>
  );
}

function Card({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-xl border dark:border-gray-700 bg-white dark:bg-gray-800 p-5 shadow-xs">
      <div className="mb-3 text-sm font-semibold text-gray-900 dark:text-white">{title}</div>
      {children}
    </div>
  );
}

function MetricCard({ label, value, tone }: { label: string; value?: number; tone: string }) {
  return (
    <Card title={label}>
      <div className={`text-3xl font-bold ${tone}`}>{value ?? "—"}</div>
    </Card>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="grid gap-1">
      <span className="text-xs font-medium text-gray-600 dark:text-gray-400">{label}</span>
      {children}
    </label>
  );
}
