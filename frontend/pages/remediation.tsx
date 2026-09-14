import Head from "next/head";
import { useEffect, useState } from "react";
import { useAuth } from "../lib/auth";
import { apiPost, apiPut } from "../lib/api";
import { useApiResource } from "../lib/use-api-resource";
import { ErrorNotice } from "../components/feedback";


type Source = {
  source: "cisa_kev" | "first_epss";
  enabled: boolean;
  interval_hours: number;
  status: string;
  record_count: number;
  last_synced_at: string | null;
  next_sync_at: string;
  stale: boolean;
  last_error: string | null;
};
type IntelligenceStatus = { sources: Source[] };
type Policy = {
  project: string;
  critical_days: number;
  high_days: number;
  medium_days: number;
  low_days: number;
  info_days: number;
  kev_days: number;
  updated_at: string | null;
};
type Policies = { policies: Policy[] };

const defaultPolicy: Policy = {
  project: "", critical_days: 7, high_days: 30, medium_days: 90,
  low_days: 180, info_days: 365, kev_days: 7, updated_at: null,
};
const sourceNames = { cisa_kev: "CISA Known Exploited Vulnerabilities", first_epss: "FIRST EPSS" };

export default function RemediationPage() {
  const { isAdmin } = useAuth();
  const intelligence = useApiResource<IntelligenceStatus>("/intelligence/status");
  const policies = useApiResource<Policies>("/remediation/policies");
  const [form, setForm] = useState(defaultPolicy);
  const [busy, setBusy] = useState(false);
  const [actionError, setActionError] = useState("");
  const [success, setSuccess] = useState("");

  useEffect(() => {
    const fallback = policies.data?.policies.find(policy => policy.project === "");
    if (fallback) setForm(fallback);
  }, [policies.data]);

  async function run(action: () => Promise<unknown>, message: string) {
    setBusy(true); setActionError(""); setSuccess("");
    try {
      await action();
      setSuccess(message);
      intelligence.reload(); policies.reload();
    } catch (error) {
      setActionError(error instanceof Error ? error.message : "The remediation action failed");
    } finally { setBusy(false); }
  }

  return <div className="space-y-6">
    <Head><title>Remediation Intelligence | SecOps Dashboard</title></Head>
    <header className="grid gap-5 lg:grid-cols-[1.25fr_.75fr] lg:items-end">
      <div>
        <p className="text-xs font-semibold uppercase tracking-[.18em] text-indigo-600 dark:text-indigo-400">Exposure intelligence</p>
        <h1 className="mt-1 text-3xl font-semibold tracking-tight text-gray-950 dark:text-white">Prioritize what attackers are likely to use</h1>
        <p className="mt-2 max-w-3xl text-sm leading-6 text-gray-600 dark:text-gray-300">Combine severity, asset context, known exploitation, exploit probability, and remediation deadlines without hiding the decision behind a model.</p>
      </div>
      <div className="rounded-xl border border-indigo-200 bg-indigo-50 p-4 text-sm leading-6 text-indigo-950 dark:border-indigo-900 dark:bg-indigo-950/40 dark:text-indigo-100">External records are treated as untrusted cached data. Feed URLs are fixed in code, responses are bounded and validated, and sync failures never erase the last successful evidence.</div>
    </header>

    <ErrorNotice message={intelligence.error || policies.error || actionError} retry={() => { intelligence.reload(); policies.reload(); }} />
    {success && <p role="status" className="rounded-lg border border-emerald-200 bg-emerald-50 p-3 text-sm text-emerald-800 dark:border-emerald-900 dark:bg-emerald-950/30 dark:text-emerald-200">{success}</p>}

    <section aria-labelledby="sources-title">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
        <h2 id="sources-title" className="text-xl font-semibold text-gray-950 dark:text-white">Intelligence sources</h2>
        {isAdmin && <button className="button-secondary" disabled={busy} onClick={() => void run(
          () => apiPost("/intelligence/sync", { sources: ["cisa_kev", "first_epss"] }),
          "Both intelligence refreshes were queued.",
        )}>{busy ? "Working…" : "Refresh both sources"}</button>}
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        {intelligence.data?.sources.map(source => <article key={source.source} className="rounded-xl border bg-white p-5 shadow-xs dark:border-gray-700 dark:bg-gray-800">
          <div className="flex flex-wrap items-start justify-between gap-3"><div><h3 className="font-semibold text-gray-950 dark:text-white">{sourceNames[source.source]}</h3><p className="mt-1 text-xs text-gray-500 dark:text-gray-400">{source.source === "cisa_kev" ? "Evidence of exploitation in the wild" : "Probability and percentile of exploitation in the next 30 days"}</p></div><StatusBadge source={source} /></div>
          <dl className="mt-5 grid grid-cols-2 gap-4 text-sm"><Metric label="Cached records" value={source.record_count.toLocaleString()} /><Metric label="Refresh interval" value={`${source.interval_hours} hours`} /><Metric label="Last successful sync" value={source.last_synced_at ? new Date(source.last_synced_at).toLocaleString() : "Never"} /><Metric label="Next scheduled check" value={source.enabled || source.status === "queued" || source.status === "syncing" ? new Date(source.next_sync_at).toLocaleString() : "Not scheduled"} /></dl>
          {source.last_error && <p className="mt-4 rounded-lg bg-red-50 p-3 text-xs text-red-800 dark:bg-red-950/30 dark:text-red-200">{source.last_error}</p>}
          {isAdmin && <div className="mt-4 flex flex-wrap gap-2 border-t pt-4 dark:border-gray-700"><button className="button-secondary" disabled={busy} onClick={() => void run(
            () => apiPut(`/intelligence/status/${source.source}`, { enabled: !source.enabled, interval_hours: source.interval_hours }),
            `${sourceNames[source.source]} ${source.enabled ? "scheduled refresh disabled" : "enabled and queued"}.`,
          )}>{source.enabled ? "Disable schedule" : "Enable scheduled refresh"}</button><button className="button-secondary" disabled={busy} onClick={() => void run(
            () => apiPost("/intelligence/sync", { sources: [source.source] }), "Refresh queued.",
          )}>Refresh now</button></div>}
        </article>)}
      </div>
    </section>

    <section className="grid gap-4 xl:grid-cols-[1.1fr_.9fr]" aria-labelledby="policy-title">
      <div className="min-w-0 rounded-xl border bg-white p-5 shadow-xs dark:border-gray-700 dark:bg-gray-800">
        <h2 id="policy-title" className="text-xl font-semibold text-gray-950 dark:text-white">Remediation SLA policies</h2>
        <p className="mt-1 text-sm text-gray-600 dark:text-gray-300">The default policy applies everywhere; an exact project policy overrides it.</p>
        <div className="mt-4 overflow-x-auto"><table className="min-w-full text-sm"><thead><tr className="border-b text-left dark:border-gray-700">{["Project", "Critical", "High", "Medium", "Low", "Info", "KEV"].map(value => <th key={value} className="p-2">{value}</th>)}</tr></thead><tbody>{policies.data?.policies.map(policy => <tr key={policy.project} className="border-b last:border-0 dark:border-gray-700"><td className="p-2 font-medium">{policy.project || "Default"}</td><td className="p-2">{policy.critical_days}d</td><td className="p-2">{policy.high_days}d</td><td className="p-2">{policy.medium_days}d</td><td className="p-2">{policy.low_days}d</td><td className="p-2">{policy.info_days}d</td><td className="p-2">{policy.kev_days}d</td></tr>)}</tbody></table></div>
      </div>

      <div className="min-w-0 rounded-xl border bg-white p-5 shadow-xs dark:border-gray-700 dark:bg-gray-800">
        <h2 className="text-xl font-semibold text-gray-950 dark:text-white">Explainable priority</h2>
        <p className="mt-1 text-sm text-gray-600 dark:text-gray-300">The score is capped at 100 and every point is visible on the finding.</p>
        <dl className="mt-4 space-y-2 text-sm">{[["Critical / high / medium / low / info", "+40 / 30 / 20 / 10 / 5"], ["CISA KEV", "+30"], ["Internet exposed", "+15"], ["High-criticality asset", "+10"], ["EPSS ≥ 90th percentile", "+10"]].map(([label, value]) => <div key={label} className="flex justify-between gap-4 border-b pb-2 last:border-0 dark:border-gray-700"><dt>{label}</dt><dd className="font-semibold">{value}</dd></div>)}</dl>
      </div>
    </section>

    {isAdmin && <section className="rounded-xl border bg-white p-5 shadow-xs dark:border-gray-700 dark:bg-gray-800">
      <h2 className="text-xl font-semibold text-gray-950 dark:text-white">Create or update a policy</h2>
      <form className="mt-4 grid gap-3 sm:grid-cols-2 lg:grid-cols-4" onSubmit={event => { event.preventDefault(); void run(
        () => apiPut("/remediation/policies", form), `${form.project || "Default"} policy saved and existing deadlines recalculated.`,
      ); }}>
        <label className="grid gap-1 text-sm lg:col-span-2">Project override<input className="input" maxLength={255} value={form.project} onChange={event => setForm({ ...form, project: event.target.value })} placeholder="Leave empty for the default policy" /></label>
        {(["critical_days", "high_days", "medium_days", "low_days", "info_days", "kev_days"] as const).map(name => <label key={name} className="grid gap-1 text-sm">{name.replace("_days", "").replace("kev", "KEV")} days<input className="input" type="number" min="1" max={name === "kev_days" ? 365 : 3650} value={form[name]} onChange={event => setForm({ ...form, [name]: Number(event.target.value) })} /></label>)}
        <div className="flex items-end"><button type="submit" className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white disabled:opacity-50" disabled={busy}>{busy ? "Saving…" : "Save policy"}</button></div>
      </form>
    </section>}
  </div>;
}

function Metric({ label, value }: { label: string; value: string }) {
  return <div><dt className="text-xs text-gray-500 dark:text-gray-400">{label}</dt><dd className="mt-1 break-words font-medium text-gray-900 dark:text-white">{value}</dd></div>;
}

function StatusBadge({ source }: { source: Source }) {
  const label = !source.enabled && !["queued", "syncing"].includes(source.status) ? "disabled" : source.status === "syncing" || source.status === "queued" ? source.status : source.stale ? "stale" : source.status;
  const color = label === "succeeded" ? "bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-200" : label === "failed" || label === "stale" ? "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-200" : label === "disabled" ? "bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-200" : "bg-blue-100 text-blue-800 dark:bg-blue-950 dark:text-blue-200";
  return <span className={`rounded-full px-2.5 py-1 text-xs font-semibold ${color}`}>{label.replace("_", " ")}</span>;
}
