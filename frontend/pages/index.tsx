import { useEffect, useMemo, useState } from "react";

type Health = { status: string };

const API = {
  health: "/api/health",
  ingest: "/api/ingest/signal",
  findings: "/api/findings",
  risks: "/api/risks",
};

export default function Dashboard() {
  const [health, setHealth] = useState<Health | null>(null);
  const [healthErr, setHealthErr] = useState<string | null>(null);

  const [tool, setTool] = useState("nuclei");
  const [severity, setSeverity] = useState("high");
  const [title, setTitle] = useState("Open redirect");
  const [asset, setAsset] = useState("api.prod.example.com");
  const [exposure, setExposure] = useState("internet");
  const [criticality, setCriticality] = useState("high");

  const [submitRes, setSubmitRes] = useState<any>(null);
  const [submitErr, setSubmitErr] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const payload = useMemo(
    () => ({ tool, severity, title, asset, exposure, criticality }),
    [tool, severity, title, asset, exposure, criticality]
  );

  useEffect(() => {
    const run = async () => {
      try {
        setHealthErr(null);
        const r = await fetch(API.health);
        const j = await r.json();
        if (!r.ok) throw new Error(j?.detail || `HTTP ${r.status}`);
        setHealth(j);
      } catch (e: any) {
        setHealth(null);
        setHealthErr(e?.message || "Failed to reach API");
      }
    };
    run();
  }, []);

  const submit = async () => {
    try {
      setSubmitting(true);
      setSubmitErr(null);
      setSubmitRes(null);

      const r = await fetch(API.ingest, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const j = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(j?.detail || `HTTP ${r.status}`);
      setSubmitRes(j);
    } catch (e: any) {
      setSubmitErr(e?.message || "Submit failed");
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold">Dashboard</h1>
        <p className="text-sm text-gray-600">API health + ingest test + live wiring (MVP).</p>
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <Card title="API Status">
          {health ? (
            <div className="space-y-2">
              <div className="inline-flex rounded-full border px-2 py-1 text-sm">✅ {health.status}</div>
              <div className="text-xs text-gray-500">via Next rewrites: /api → http://localhost:8000</div>
            </div>
          ) : (
            <div className="space-y-2">
              <div className="rounded-md border border-red-300 bg-red-50 p-3 text-sm">
                ❌ Not reachable<br />
                <span className="text-xs text-gray-600">{healthErr || "Start backend on port 8000"}</span>
              </div>
            </div>
          )}
        </Card>

        <Card title="Endpoints">
          <ul className="space-y-1 text-sm">
            <li className="font-mono">{API.health}</li>
            <li className="font-mono">{API.ingest}</li>
            <li className="font-mono">{API.findings}</li>
            <li className="font-mono">{API.risks}</li>
          </ul>
        </Card>

        <Card title="What’s next">
          <ol className="list-decimal pl-5 text-sm text-gray-600 space-y-1">
            <li>Persist to Postgres</li>
            <li>Asset inventory + ownership</li>
            <li>Correlation + dedupe</li>
            <li>Jira/Slack integrations</li>
          </ol>
        </Card>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <Card title="Send Test Signal">
          <div className="grid gap-3">
            <Field label="Tool">
              <input className="w-full rounded-md border px-3 py-2 text-sm" value={tool} onChange={(e) => setTool(e.target.value)} />
            </Field>

            <div className="grid gap-3 md:grid-cols-2">
              <Field label="Severity">
                <select className="w-full rounded-md border px-3 py-2 text-sm" value={severity} onChange={(e) => setSeverity(e.target.value)}>
                  <option value="info">info</option>
                  <option value="low">low</option>
                  <option value="medium">medium</option>
                  <option value="high">high</option>
                  <option value="critical">critical</option>
                </select>
              </Field>
              <Field label="Exposure">
                <select className="w-full rounded-md border px-3 py-2 text-sm" value={exposure} onChange={(e) => setExposure(e.target.value)}>
                  <option value="internal">internal</option>
                  <option value="internet">internet</option>
                </select>
              </Field>
            </div>

            <div className="grid gap-3 md:grid-cols-2">
              <Field label="Criticality">
                <select className="w-full rounded-md border px-3 py-2 text-sm" value={criticality} onChange={(e) => setCriticality(e.target.value)}>
                  <option value="low">low</option>
                  <option value="medium">medium</option>
                  <option value="high">high</option>
                </select>
              </Field>
              <Field label="Asset">
                <input className="w-full rounded-md border px-3 py-2 text-sm" value={asset} onChange={(e) => setAsset(e.target.value)} />
              </Field>
            </div>

            <Field label="Title">
              <input className="w-full rounded-md border px-3 py-2 text-sm" value={title} onChange={(e) => setTitle(e.target.value)} />
            </Field>

            <button
              onClick={submit}
              disabled={submitting}
              className="rounded-md bg-black px-4 py-2 text-sm font-medium text-white disabled:opacity-60"
            >
              {submitting ? "Submitting..." : "Submit"}
            </button>

            {submitErr && <div className="rounded-md border border-red-300 bg-red-50 p-3 text-sm">❌ {submitErr}</div>}
            {submitRes && (
              <div className="rounded-md border bg-white p-3">
                <div className="text-sm font-medium">Response</div>
                <pre className="mt-2 overflow-auto rounded-md bg-gray-50 p-3 text-xs">
{JSON.stringify(submitRes, null, 2)}
                </pre>
              </div>
            )}
          </div>
        </Card>

        <Card title="Payload Preview">
          <pre className="overflow-auto rounded-md bg-gray-50 p-4 text-xs">
{JSON.stringify(payload, null, 2)}
          </pre>
          <p className="mt-2 text-xs text-gray-500">This becomes normalized into Finding + Risk on the backend.</p>
        </Card>
      </div>
    </div>
  );
}

function Card({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-xl border bg-white p-5 shadow-sm">
      <div className="mb-3 text-sm font-semibold">{title}</div>
      {children}
    </div>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="grid gap-1">
      <span className="text-xs font-medium text-gray-600">{label}</span>
      {children}
    </label>
  );
}
