import { useAuth } from "../lib/auth";
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
  urgent_findings: number;
  known_exploited_findings: number;
  aging_buckets: Record<string, number>;
  priority_buckets: Record<string, number>;
  sla: { tracked: number; overdue: number; accepted: number; on_track: number; compliance_percent: number };
  top_assets: { project: string; asset: string; active_findings: number; priority_sum: number; max_priority: number }[];
  trend: { date: string; new: number; resolved: number }[];
  generated_at: string;
};
type SubmitResult = {
  accepted: boolean;
  deduped: boolean;
  finding_id: string;
  risk_score: number;
  priority_score: number;
  occurrences: number;
};

export default function Dashboard() {
  const { canWrite } = useAuth();
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
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[.18em] text-indigo-600 dark:text-indigo-400">Remediation command center</p>
          <h1 className="mt-1 text-3xl font-semibold tracking-tight text-gray-950 dark:text-white">Security posture at a glance</h1>
          <p className="mt-1 text-sm text-gray-600 dark:text-gray-400">Prioritize exploited risk, watch remediation deadlines, and measure whether the backlog is moving.</p>
        </div>
        {summary && <p className="text-xs text-gray-500 dark:text-gray-400">{summary.assets} assets · {summary.resolved_findings} completed · updated {new Date(summary.generated_at).toLocaleTimeString()}</p>}
      </div>

      <ErrorNotice message={summaryError} retry={loadSummary} />
      <ErrorNotice message={healthErr} retry={reloadHealth} />
      {summaryLoading && <p role="status" className="text-sm">Loading summary…</p>}
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-6">
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
        <MetricCard label="Active backlog" value={summary?.active_findings} tone="text-gray-950 dark:text-white" />
        <MetricCard label="Urgent priority" value={summary?.urgent_findings} tone="text-red-600 dark:text-red-400" />
        <MetricCard label="Known exploited" value={summary?.known_exploited_findings} tone="text-orange-600 dark:text-orange-400" />
        <MetricCard label="Overdue SLA" value={summary?.sla.overdue} tone="text-rose-700 dark:text-rose-300" />
        <MetricCard label="SLA compliance" value={summary?.sla.compliance_percent} suffix="%" tone="text-emerald-700 dark:text-emerald-300" />
      </div>

      {summary && <div className="grid gap-4 xl:grid-cols-[1.35fr_.65fr]">
        <Card title="New vs resolved · last 14 days">
          <TrendChart rows={summary.trend} />
        </Card>
        <Card title="Remediation SLA">
          <div className="mb-4 flex items-end justify-between"><span className="text-4xl font-semibold text-gray-950 dark:text-white">{summary.sla.compliance_percent}%</span><span className="text-xs text-gray-500 dark:text-gray-400">non-accepted findings in SLA</span></div>
          <HorizontalBars values={[
            ["On track", summary.sla.on_track, "bg-emerald-500"],
            ["Overdue", summary.sla.overdue, "bg-rose-500"],
            ["Accepted", summary.sla.accepted, "bg-amber-500"],
          ]} />
          <Link href={{ pathname: "/findings", query: { sla: "overdue", sort: "priority_desc" } }} className="mt-4 inline-block text-sm font-medium text-indigo-600 hover:underline dark:text-indigo-400">Review overdue findings →</Link>
        </Card>
      </div>}

      {summary && <div className="grid gap-4 lg:grid-cols-3">
        <Card title="Priority distribution">
          <HorizontalBars values={[
            ["Urgent · 80–100", summary.priority_buckets.urgent, "bg-red-600"],
            ["High · 60–79", summary.priority_buckets.high, "bg-orange-500"],
            ["Elevated · 40–59", summary.priority_buckets.elevated, "bg-amber-400"],
            ["Standard · below 40", summary.priority_buckets.standard, "bg-slate-400"],
          ]} />
        </Card>
        <Card title="Backlog age">
          <HorizontalBars values={[
            ["0–7 days", summary.aging_buckets["0_7_days"], "bg-indigo-500"],
            ["8–30 days", summary.aging_buckets["8_30_days"], "bg-blue-500"],
            ["31–90 days", summary.aging_buckets["31_90_days"], "bg-amber-500"],
            ["Over 90 days", summary.aging_buckets.over_90_days, "bg-rose-500"],
          ]} />
        </Card>
        <Card title="Highest-priority assets">
          {summary.top_assets.length === 0 ? <p className="text-sm text-gray-500 dark:text-gray-400">No active findings.</p> : <ol className="space-y-3">
            {summary.top_assets.map((item, index) => <li key={`${item.project}:${item.asset}`} className="flex items-center gap-3">
              <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-gray-100 text-xs font-semibold text-gray-600 dark:bg-gray-700 dark:text-gray-200">{index + 1}</span>
              <div className="min-w-0 flex-1"><p className="truncate text-sm font-medium text-gray-900 dark:text-white">{item.asset}</p><p className="truncate text-xs text-gray-500 dark:text-gray-400">{item.project || "Default project"} · {item.active_findings} active</p></div>
              <span className="text-sm font-semibold text-gray-900 dark:text-white">{item.max_priority}</span>
            </li>)}
          </ol>}
        </Card>
      </div>}

      <div className="flex flex-wrap gap-3 text-sm"><Link href="/findings" className="button-secondary">Triage findings</Link><Link href="/remediation" className="button-secondary">Remediation intelligence</Link>{canWrite && <Link href="/integrations" className="button-secondary">Import scan results</Link>}</div>
      {canWrite && <details className="rounded-xl border p-4 dark:border-gray-700"><summary className="cursor-pointer font-medium">Send a manual signal</summary>
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
      </details>}
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

function MetricCard({ label, value, suffix = "", tone }: { label: string; value?: number; suffix?: string; tone: string }) {
  return (
    <Card title={label}>
      <div className={`text-3xl font-bold ${tone}`}>{value ?? "—"}{value !== undefined ? suffix : ""}</div>
    </Card>
  );
}

function HorizontalBars({ values }: { values: [string, number, string][] }) {
  const max = Math.max(1, ...values.map(([, value]) => value));
  return <div className="space-y-3">{values.map(([label, value, color]) => <div key={label}>
    <div className="mb-1 flex justify-between text-xs text-gray-600 dark:text-gray-300"><span>{label}</span><strong>{value}</strong></div>
    <div className="h-2 overflow-hidden rounded-full bg-gray-100 dark:bg-gray-700"><div className={`h-full rounded-full ${color}`} style={{ width: `${Math.max(value ? 4 : 0, value / max * 100)}%` }} /></div>
  </div>)}</div>;
}

function TrendChart({ rows }: { rows: { date: string; new: number; resolved: number }[] }) {
  const max = Math.max(1, ...rows.flatMap(row => [row.new, row.resolved]));
  return <div>
    <div className="mb-4 flex gap-4 text-xs text-gray-600 dark:text-gray-300"><span><i className="mr-1 inline-block h-2 w-2 rounded-full bg-indigo-500" />New</span><span><i className="mr-1 inline-block h-2 w-2 rounded-full bg-emerald-500" />Completed</span></div>
    <div className="flex h-40 items-end gap-1" aria-label="Fourteen-day new and completed findings chart">
      {rows.map((row, index) => <div key={row.date} className="flex h-full min-w-0 flex-1 flex-col justify-end" title={`${row.date}: ${row.new} new, ${row.resolved} completed`}>
        <div className="flex h-[8rem] items-end justify-center gap-px"><span className="w-2 rounded-t bg-indigo-500" style={{ height: `${row.new / max * 100}%` }} /><span className="w-2 rounded-t bg-emerald-500" style={{ height: `${row.resolved / max * 100}%` }} /></div>
        {(index === 0 || index === rows.length - 1) && <span className="mt-2 truncate text-[.6rem] text-gray-500">{new Date(`${row.date}T00:00:00`).toLocaleDateString(undefined, { month: "short", day: "numeric" })}</span>}
      </div>)}
    </div>
  </div>;
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="grid gap-1">
      <span className="text-xs font-medium text-gray-600 dark:text-gray-400">{label}</span>
      {children}
    </label>
  );
}
