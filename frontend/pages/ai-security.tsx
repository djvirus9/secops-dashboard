import { useEffect, useMemo, useState } from "react";
import Head from "next/head";
import { apiGet, apiPost } from "../lib/api";

type LabMode = "prompt_only" | "policy_enforced";
type Disposition =
  | "executed"
  | "allowed"
  | "blocked"
  | "approval_required"
  | "sanitized"
  | "rate_limited";

type Scenario = {
  id: string;
  title: string;
  kind: "attack" | "benign";
  risk: string;
  atlas_technique: string;
  entry_point: string;
  attack_input: string;
  proposed_action: string;
  expected_control: string;
  requester_tenant: string;
};

type Catalog = {
  simulation: true;
  count: number;
  scenarios: Scenario[];
};

type Evaluation = {
  simulation: true;
  method: string;
  corpus_size: number;
  attack_cases: number;
  benign_cases: number;
  prompt_only: {
    attack_successes: number;
    attack_success_rate: number;
  };
  policy_enforced: {
    attack_successes: number;
    attack_success_rate: number;
    benign_allowed: number;
    false_refusals: number;
    false_refusal_rate: number;
  };
};

type ControlEvent = {
  control: string;
  result: "observed" | "missed" | "blocked" | "approval" | "sanitized" | "limited";
  detail: string;
};

type RunResult = {
  simulation: true;
  scenario_id: string;
  scenario_title: string;
  kind: "attack" | "benign";
  risk: string;
  atlas_technique: string;
  mode: LabMode;
  disposition: Disposition;
  attack_succeeded: boolean;
  rendered_output: string;
  controls: ControlEvent[];
  explanation: string;
};

const dispositionLabels: Record<Disposition, string> = {
  executed: "Unsafe plan executed",
  allowed: "Authorized read allowed",
  blocked: "Blocked",
  approval_required: "Approval required",
  sanitized: "Rendered safely",
  rate_limited: "Budget enforced",
};

const dispositionStyles: Record<Disposition, string> = {
  executed: "bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-200",
  allowed: "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-200",
  blocked: "bg-emerald-100 text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-200",
  approval_required: "bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-200",
  sanitized: "bg-blue-100 text-blue-800 dark:bg-blue-900/40 dark:text-blue-200",
  rate_limited: "bg-violet-100 text-violet-800 dark:bg-violet-900/40 dark:text-violet-200",
};

export default function AiSecurity() {
  const [catalog, setCatalog] = useState<Catalog | null>(null);
  const [evaluation, setEvaluation] = useState<Evaluation | null>(null);
  const [selectedId, setSelectedId] = useState("");
  const [mode, setMode] = useState<LabMode>("policy_enforced");
  const [result, setResult] = useState<RunResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    Promise.all([
      apiGet<Catalog>("/ai-security/scenarios"),
      apiGet<Evaluation>("/ai-security/evaluation"),
    ])
      .then(([nextCatalog, nextEvaluation]) => {
        setCatalog(nextCatalog);
        setEvaluation(nextEvaluation);
        setSelectedId(nextCatalog.scenarios[0]?.id || "");
      })
      .catch((requestError: Error) => setError(requestError.message))
      .finally(() => setLoading(false));
  }, []);

  const scenario = useMemo(
    () => catalog?.scenarios.find((item) => item.id === selectedId) || null,
    [catalog, selectedId]
  );

  const runScenario = async () => {
    if (!selectedId) return;
    setRunning(true);
    setError("");
    try {
      const nextResult = await apiPost<RunResult>("/ai-security/run", {
        scenario_id: selectedId,
        mode,
      });
      setResult(nextResult);
    } catch (requestError: any) {
      setError(requestError?.message || "The simulation could not be run.");
    } finally {
      setRunning(false);
    }
  };

  const chooseScenario = (id: string) => {
    setSelectedId(id);
    setResult(null);
  };

  if (loading) {
    return <p className="text-gray-600 dark:text-gray-300">Loading the synthetic evaluation corpus…</p>;
  }

  if (!catalog || !evaluation) {
    return (
      <div role="alert" className="rounded-xl border border-red-200 bg-red-50 p-5 text-red-800 dark:border-red-900 dark:bg-red-950/40 dark:text-red-200">
        {error || "The AI security lab is unavailable."}
      </div>
    );
  }

  return (
    <div className="space-y-8">
      <Head>
        <title>AI Security Lab | SecOps Dashboard</title>
        <meta name="description" content="A synthetic red-team lab for testing deterministic controls around AI-generated SecOps plans." />
      </Head>
      <header className="grid gap-6 lg:grid-cols-[1.25fr_.75fr] lg:items-end">
        <div>
          <p className="text-xs font-semibold uppercase tracking-[.18em] text-indigo-600 dark:text-indigo-400">
            Synthetic red-team lab
          </p>
          <h1 className="mt-2 text-3xl font-semibold tracking-tight text-gray-950 dark:text-white sm:text-4xl">
            Secure AI SecOps Copilot
          </h1>
          <p className="mt-4 max-w-3xl text-base leading-7 text-gray-600 dark:text-gray-300">
            Test what happens after a model proposes a risky retrieval, response, or tool call. The policy gateway—not the prompt—decides what the application can do.
          </p>
        </div>
        <p className="rounded-xl border border-indigo-200 bg-indigo-50 p-4 text-sm leading-6 text-indigo-900 dark:border-indigo-900 dark:bg-indigo-950/40 dark:text-indigo-100">
          No AI provider is contacted and no candidate tool is executed. Every tenant, finding, recipient, and credential is synthetic.
        </p>
      </header>

      <section aria-labelledby="measured-results">
        <div className="mb-3 flex flex-wrap items-end justify-between gap-2">
          <h2 id="measured-results" className="text-xl font-semibold text-gray-900 dark:text-white">Measured control behavior</h2>
          <p className="text-xs text-gray-500 dark:text-gray-400">Deterministic corpus · {evaluation.corpus_size} scenarios</p>
        </div>
        <dl className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <div className="rounded-xl border bg-white p-5 shadow-sm dark:border-gray-700 dark:bg-gray-800">
            <dt className="text-xs text-gray-500 dark:text-gray-400">Adversarial plans</dt>
            <dd className="mt-1 text-3xl font-semibold text-gray-950 dark:text-white">{evaluation.attack_cases}</dd>
          </div>
          <div className="rounded-xl border bg-white p-5 shadow-sm dark:border-gray-700 dark:bg-gray-800">
            <dt className="text-xs text-gray-500 dark:text-gray-400">Prompt-only success</dt>
            <dd className="mt-1 text-3xl font-semibold text-red-700 dark:text-red-300">{evaluation.prompt_only.attack_success_rate}%</dd>
          </div>
          <div className="rounded-xl border bg-white p-5 shadow-sm dark:border-gray-700 dark:bg-gray-800">
            <dt className="text-xs text-gray-500 dark:text-gray-400">Policy-enforced success</dt>
            <dd className="mt-1 text-3xl font-semibold text-emerald-700 dark:text-emerald-300">{evaluation.policy_enforced.attack_success_rate}%</dd>
          </div>
          <div className="rounded-xl border bg-white p-5 shadow-sm dark:border-gray-700 dark:bg-gray-800">
            <dt className="text-xs text-gray-500 dark:text-gray-400">Benign false refusals</dt>
            <dd className="mt-1 text-3xl font-semibold text-emerald-700 dark:text-emerald-300">{evaluation.policy_enforced.false_refusals}</dd>
          </div>
        </dl>
        <p className="mt-3 text-xs leading-5 text-gray-500 dark:text-gray-400">{evaluation.method} Results apply only to the bundled corpus, not to a live model.</p>
      </section>

      <section aria-labelledby="run-lab" className="overflow-hidden rounded-2xl border bg-white shadow-sm dark:border-gray-700 dark:bg-gray-800">
        <div className="border-b p-5 dark:border-gray-700 sm:p-6">
          <h2 id="run-lab" className="text-xl font-semibold text-gray-900 dark:text-white">Run a candidate agent plan</h2>
          <p className="mt-2 text-sm text-gray-600 dark:text-gray-300">Select an attack or benign control, then compare an instruction-only baseline with deterministic enforcement.</p>
        </div>

        <div className="grid lg:grid-cols-[.8fr_1.2fr]">
          <div className="border-b bg-gray-50 p-4 dark:border-gray-700 dark:bg-gray-900/40 lg:border-b-0 lg:border-r">
            <p className="mb-3 text-xs font-semibold uppercase tracking-wider text-gray-500 dark:text-gray-400">Scenario corpus</p>
            <div className="space-y-2">
              {catalog.scenarios.map((item) => (
                <button
                  key={item.id}
                  type="button"
                  onClick={() => chooseScenario(item.id)}
                  aria-pressed={selectedId === item.id}
                  className={`w-full rounded-lg border p-3 text-left transition-colors ${
                    selectedId === item.id
                      ? "border-indigo-500 bg-indigo-50 dark:border-indigo-400 dark:bg-indigo-950/40"
                      : "border-gray-200 bg-white hover:border-indigo-300 dark:border-gray-700 dark:bg-gray-800 dark:hover:border-indigo-600"
                  }`}
                >
                  <span className={`text-[.65rem] font-semibold uppercase tracking-wider ${item.kind === "attack" ? "text-red-700 dark:text-red-300" : "text-emerald-700 dark:text-emerald-300"}`}>
                    {item.kind}
                  </span>
                  <strong className="mt-1 block text-sm leading-5 text-gray-900 dark:text-white">{item.title}</strong>
                  <span className={`mt-1 block text-xs ${selectedId === item.id ? "text-gray-700 dark:text-gray-200" : "text-gray-500 dark:text-gray-400"}`}>{item.risk}</span>
                </button>
              ))}
            </div>
          </div>

          <div className="min-w-0 p-5 sm:p-6">
            {scenario && (
              <>
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <p className="text-xs font-semibold text-indigo-600 dark:text-indigo-400">{scenario.entry_point}</p>
                    <h3 className="mt-1 text-xl font-semibold text-gray-950 dark:text-white">{scenario.title}</h3>
                  </div>
                  <span className="rounded-full bg-gray-100 px-3 py-1 text-xs text-gray-700 dark:bg-gray-700 dark:text-gray-200">{scenario.risk}</span>
                </div>

                <dl className="mt-5 grid gap-3 text-sm sm:grid-cols-2">
                  <div className="rounded-lg bg-gray-50 p-4 dark:bg-gray-900/50">
                    <dt className="text-xs font-semibold uppercase tracking-wider text-gray-500 dark:text-gray-400">Untrusted input</dt>
                    <dd className="mt-2 leading-6 text-gray-800 dark:text-gray-200">{scenario.attack_input}</dd>
                  </div>
                  <div className="rounded-lg bg-gray-50 p-4 dark:bg-gray-900/50">
                    <dt className="text-xs font-semibold uppercase tracking-wider text-gray-500 dark:text-gray-400">Candidate plan</dt>
                    <dd className="mt-2 leading-6 text-gray-800 dark:text-gray-200">{scenario.proposed_action}</dd>
                  </div>
                </dl>

                <fieldset className="mt-5">
                  <legend className="text-xs font-semibold uppercase tracking-wider text-gray-500 dark:text-gray-400">Enforcement mode</legend>
                  <div className="mt-2 inline-flex rounded-lg border p-1 dark:border-gray-600">
                    {(["prompt_only", "policy_enforced"] as LabMode[]).map((item) => (
                      <button
                        key={item}
                        type="button"
                        onClick={() => { setMode(item); setResult(null); }}
                        aria-pressed={mode === item}
                        className={`rounded-md px-3 py-2 text-sm font-medium ${mode === item ? "bg-gray-950 text-white dark:bg-white dark:text-gray-950" : "text-gray-600 hover:bg-gray-100 dark:text-gray-300 dark:hover:bg-gray-700"}`}
                      >
                        {item === "prompt_only" ? "Prompt-only" : "Policy-enforced"}
                      </button>
                    ))}
                  </div>
                </fieldset>

                <button
                  type="button"
                  onClick={runScenario}
                  disabled={running}
                  className="mt-4 rounded-lg bg-indigo-600 px-4 py-2.5 text-sm font-semibold text-white hover:bg-indigo-700 disabled:cursor-wait disabled:opacity-60"
                >
                  {running ? "Evaluating…" : "Run simulation"}
                </button>

                {error && <p role="alert" className="mt-4 text-sm text-red-700 dark:text-red-300">{error}</p>}

                <div className="mt-5 min-h-32" aria-live="polite" aria-atomic="true">
                  {!result ? (
                    <div className="rounded-lg border border-dashed p-5 text-sm text-gray-500 dark:border-gray-600 dark:text-gray-400">
                      Run the scenario to inspect the policy decision and control trace.
                    </div>
                  ) : (
                    <div className="space-y-4 rounded-xl border p-5 dark:border-gray-600" data-lab-result>
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className={`rounded-full px-3 py-1 text-xs font-semibold ${dispositionStyles[result.disposition]}`}>
                          {dispositionLabels[result.disposition]}
                        </span>
                        <span className="text-xs text-gray-500 dark:text-gray-400">{result.mode === "prompt_only" ? "Prompt-only baseline" : "Policy gateway"}</span>
                      </div>
                      <p className="text-sm leading-6 text-gray-800 dark:text-gray-200">{result.explanation}</p>
                      <div>
                        <h4 className="text-xs font-semibold uppercase tracking-wider text-gray-500 dark:text-gray-400">Control trace</h4>
                        <ol className="mt-2 space-y-2">
                          {result.controls.map((control, index) => (
                            <li key={`${control.control}-${index}`} className="rounded-lg bg-gray-50 p-3 text-sm dark:bg-gray-900/50">
                              <strong className="text-gray-900 dark:text-white">{control.control}</strong>
                              <span className="ml-2 text-xs uppercase text-indigo-600 dark:text-indigo-400">{control.result}</span>
                              <p className="mt-1 text-xs leading-5 text-gray-600 dark:text-gray-300">{control.detail}</p>
                            </li>
                          ))}
                        </ol>
                      </div>
                      <div>
                        <h4 className="text-xs font-semibold uppercase tracking-wider text-gray-500 dark:text-gray-400">Rendered output</h4>
                        <pre className="mt-2 overflow-x-auto whitespace-pre-wrap break-words rounded-lg bg-gray-950 p-3 text-xs leading-5 text-gray-100">{result.rendered_output}</pre>
                      </div>
                    </div>
                  )}
                </div>
              </>
            )}
          </div>
        </div>
      </section>

      <section className="grid gap-4 md:grid-cols-3" aria-labelledby="control-boundary">
        <h2 id="control-boundary" className="sr-only">Control boundary</h2>
        {[
          ["Before generation", "Authorize retrieval by tenant and label scanner or runbook content as untrusted."],
          ["Before execution", "Validate exact tool schemas, restrict capabilities, and stage write actions for approval."],
          ["Before rendering", "Redact planted secrets, encode active markup, and preserve an auditable decision trace."],
        ].map(([title, copy]) => (
          <article key={title} className="rounded-xl border bg-white p-5 dark:border-gray-700 dark:bg-gray-800">
            <h3 className="font-semibold text-gray-900 dark:text-white">{title}</h3>
            <p className="mt-2 text-sm leading-6 text-gray-600 dark:text-gray-300">{copy}</p>
          </article>
        ))}
      </section>
    </div>
  );
}
