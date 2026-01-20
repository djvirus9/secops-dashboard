import { useEffect, useState } from "react";
import { apiGet, apiPost } from "../lib/api";

type IntegrationStatus = {
  slack: {
    configured: boolean;
    description: string;
  };
  jira: {
    configured: boolean;
    description: string;
    project_key: string | null;
  };
};

type Parser = {
  name: string;
  display_name: string;
  category: string;
  file_types: string[];
  description: string;
};

type ParsersResponse = {
  count: number;
  categories: string[];
  parsers: Parser[];
  by_category: Record<string, Parser[]>;
};

type ImportResult = {
  ok: boolean;
  imported: number;
  new_findings: number;
  deduplicated: number;
  message: string;
};

const CATEGORY_LABELS: Record<string, string> = {
  sast: "Static Analysis (SAST)",
  dast: "Dynamic Analysis (DAST)",
  sca: "Software Composition (SCA)",
  infrastructure: "Infrastructure as Code",
  container: "Container Security",
  cloud: "Cloud Security",
  secrets: "Secrets Detection",
  generic: "Generic Formats",
  bugbounty: "Bug Bounty Platforms",
  network: "Network Scanning",
  mobile: "Mobile Security",
  other: "Other Tools",
};

const CATEGORY_COLORS: Record<string, string> = {
  sast: "bg-purple-100 text-purple-800 dark:bg-purple-900/50 dark:text-purple-200",
  dast: "bg-red-100 text-red-800 dark:bg-red-900/50 dark:text-red-200",
  sca: "bg-orange-100 text-orange-800 dark:bg-orange-900/50 dark:text-orange-200",
  infrastructure: "bg-blue-100 text-blue-800 dark:bg-blue-900/50 dark:text-blue-200",
  container: "bg-cyan-100 text-cyan-800 dark:bg-cyan-900/50 dark:text-cyan-200",
  cloud: "bg-sky-100 text-sky-800 dark:bg-sky-900/50 dark:text-sky-200",
  secrets: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/50 dark:text-yellow-200",
  generic: "bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200",
  bugbounty: "bg-pink-100 text-pink-800 dark:bg-pink-900/50 dark:text-pink-200",
  network: "bg-teal-100 text-teal-800 dark:bg-teal-900/50 dark:text-teal-200",
  mobile: "bg-indigo-100 text-indigo-800 dark:bg-indigo-900/50 dark:text-indigo-200",
  other: "bg-slate-100 text-slate-800 dark:bg-slate-700 dark:text-slate-200",
};

export default function Integrations() {
  const [status, setStatus] = useState<IntegrationStatus | null>(null);
  const [parsers, setParsers] = useState<ParsersResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [testingSlack, setTestingSlack] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; message: string } | null>(null);
  const [activeTab, setActiveTab] = useState<"notifications" | "scanners" | "import">("notifications");
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null);
  const [scanContent, setScanContent] = useState("");
  const [selectedParser, setSelectedParser] = useState("");
  const [defaultAsset, setDefaultAsset] = useState("");
  const [importing, setImporting] = useState(false);
  const [importResult, setImportResult] = useState<ImportResult | null>(null);

  useEffect(() => {
    Promise.all([
      apiGet<IntegrationStatus>("/integrations"),
      apiGet<ParsersResponse>("/parsers"),
    ])
      .then(([intStatus, parsersData]) => {
        setStatus(intStatus);
        setParsers(parsersData);
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  const handleTestSlack = async () => {
    setTestingSlack(true);
    setTestResult(null);
    try {
      const result = await apiPost<{ ok: boolean; message: string }>("/integrations/slack/test", {});
      setTestResult(result);
    } catch (e: any) {
      setTestResult({ ok: false, message: e?.message || "Failed to send test" });
    } finally {
      setTestingSlack(false);
    }
  };

  const handleImport = async () => {
    if (!scanContent.trim()) return;
    
    setImporting(true);
    setImportResult(null);
    try {
      const result = await apiPost<ImportResult>("/import/scan", {
        content: scanContent,
        parser: selectedParser || undefined,
        default_asset: defaultAsset || undefined,
      });
      setImportResult(result);
      if (result.ok && result.imported > 0) {
        setScanContent("");
      }
    } catch (e: any) {
      setImportResult({ ok: false, imported: 0, new_findings: 0, deduplicated: 0, message: e?.message || "Import failed" });
    } finally {
      setImporting(false);
    }
  };

  const filteredParsers = selectedCategory && parsers
    ? parsers.parsers.filter(p => p.category === selectedCategory)
    : parsers?.parsers || [];

  if (loading) {
    return <div className="text-gray-600 dark:text-gray-300">Loading...</div>;
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold text-gray-900 dark:text-white">Integrations</h1>
        <div className="flex gap-2">
          <button
            onClick={() => setActiveTab("notifications")}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
              activeTab === "notifications"
                ? "bg-indigo-600 text-white"
                : "bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600"
            }`}
          >
            Notifications
          </button>
          <button
            onClick={() => setActiveTab("scanners")}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
              activeTab === "scanners"
                ? "bg-indigo-600 text-white"
                : "bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600"
            }`}
          >
            Scanners ({parsers?.count || 0})
          </button>
          <button
            onClick={() => setActiveTab("import")}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
              activeTab === "import"
                ? "bg-indigo-600 text-white"
                : "bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600"
            }`}
          >
            Import Scans
          </button>
        </div>
      </div>

      {activeTab === "notifications" && (
        <>
          <p className="text-sm text-gray-600 dark:text-gray-400">
            Configure external integrations to receive notifications when critical or high severity findings are detected.
          </p>

          <div className="grid gap-6 md:grid-cols-2">
            <div className="rounded-xl border dark:border-gray-700 bg-white dark:bg-gray-800 p-6 shadow-sm">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-lg bg-purple-100 dark:bg-purple-900/50 flex items-center justify-center">
                    <svg className="w-6 h-6 text-purple-600 dark:text-purple-400" fill="currentColor" viewBox="0 0 24 24">
                      <path d="M5.042 15.165a2.528 2.528 0 0 1-2.52 2.523A2.528 2.528 0 0 1 0 15.165a2.527 2.527 0 0 1 2.522-2.52h2.52v2.52zM6.313 15.165a2.527 2.527 0 0 1 2.521-2.52 2.527 2.527 0 0 1 2.521 2.52v6.313A2.528 2.528 0 0 1 8.834 24a2.528 2.528 0 0 1-2.521-2.522v-6.313zM8.834 5.042a2.528 2.528 0 0 1-2.521-2.52A2.528 2.528 0 0 1 8.834 0a2.528 2.528 0 0 1 2.521 2.522v2.52H8.834zM8.834 6.313a2.528 2.528 0 0 1 2.521 2.521 2.528 2.528 0 0 1-2.521 2.521H2.522A2.528 2.528 0 0 1 0 8.834a2.528 2.528 0 0 1 2.522-2.521h6.312zM18.956 8.834a2.528 2.528 0 0 1 2.522-2.521A2.528 2.528 0 0 1 24 8.834a2.528 2.528 0 0 1-2.522 2.521h-2.522V8.834zM17.688 8.834a2.528 2.528 0 0 1-2.523 2.521 2.527 2.527 0 0 1-2.52-2.521V2.522A2.527 2.527 0 0 1 15.165 0a2.528 2.528 0 0 1 2.523 2.522v6.312zM15.165 18.956a2.528 2.528 0 0 1 2.523 2.522A2.528 2.528 0 0 1 15.165 24a2.527 2.527 0 0 1-2.52-2.522v-2.522h2.52zM15.165 17.688a2.527 2.527 0 0 1-2.52-2.523 2.526 2.526 0 0 1 2.52-2.52h6.313A2.527 2.527 0 0 1 24 15.165a2.528 2.528 0 0 1-2.522 2.523h-6.313z"/>
                    </svg>
                  </div>
                  <div>
                    <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Slack</h2>
                    <p className="text-xs text-gray-500 dark:text-gray-400">{status?.slack.description}</p>
                  </div>
                </div>
                <span className={`px-3 py-1 rounded-full text-xs font-medium ${
                  status?.slack.configured 
                    ? "bg-green-100 text-green-800 dark:bg-green-900/50 dark:text-green-200" 
                    : "bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-300"
                }`}>
                  {status?.slack.configured ? "Connected" : "Not configured"}
                </span>
              </div>

              {status?.slack.configured ? (
                <div className="space-y-3">
                  <p className="text-sm text-green-600 dark:text-green-400">
                    Slack webhook is configured. Notifications will be sent for critical and high severity findings.
                  </p>
                  <button
                    onClick={handleTestSlack}
                    disabled={testingSlack}
                    className="px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 disabled:opacity-50 text-sm"
                  >
                    {testingSlack ? "Sending..." : "Send Test Notification"}
                  </button>
                  {testResult && (
                    <p className={`text-sm ${testResult.ok ? "text-green-600 dark:text-green-400" : "text-red-600 dark:text-red-400"}`}>
                      {testResult.message}
                    </p>
                  )}
                </div>
              ) : (
                <div className="space-y-3">
                  <p className="text-sm text-gray-600 dark:text-gray-400">
                    To enable Slack notifications, add the following secret:
                  </p>
                  <div className="bg-gray-50 dark:bg-gray-900 rounded-lg p-3 font-mono text-sm">
                    <code className="text-gray-800 dark:text-gray-200">SLACK_WEBHOOK_URL</code>
                  </div>
                  <p className="text-xs text-gray-500 dark:text-gray-400">
                    Create an <a href="https://api.slack.com/messaging/webhooks" target="_blank" rel="noopener noreferrer" className="text-indigo-600 dark:text-indigo-400 hover:underline">Incoming Webhook</a> in your Slack workspace and add the URL as a secret.
                  </p>
                </div>
              )}
            </div>

            <div className="rounded-xl border dark:border-gray-700 bg-white dark:bg-gray-800 p-6 shadow-sm">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-lg bg-blue-100 dark:bg-blue-900/50 flex items-center justify-center">
                    <svg className="w-6 h-6 text-blue-600 dark:text-blue-400" fill="currentColor" viewBox="0 0 24 24">
                      <path d="M11.571 11.513H0a5.218 5.218 0 0 0 5.232 5.215h2.13v2.057A5.215 5.215 0 0 0 12.575 24V12.518a1.005 1.005 0 0 0-1.005-1.005zm5.723-5.756H5.736a5.215 5.215 0 0 0 5.215 5.214h2.129v2.058a5.218 5.218 0 0 0 5.215 5.214V6.758a1.001 1.001 0 0 0-1.001-1.001zM23.013 0H11.455a5.215 5.215 0 0 0 5.215 5.215h2.129v2.057A5.215 5.215 0 0 0 24 12.483V1.005A1.005 1.005 0 0 0 23.013 0z"/>
                    </svg>
                  </div>
                  <div>
                    <h2 className="text-lg font-semibold text-gray-900 dark:text-white">Jira</h2>
                    <p className="text-xs text-gray-500 dark:text-gray-400">{status?.jira.description}</p>
                  </div>
                </div>
                <span className={`px-3 py-1 rounded-full text-xs font-medium ${
                  status?.jira.configured 
                    ? "bg-green-100 text-green-800 dark:bg-green-900/50 dark:text-green-200" 
                    : "bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-300"
                }`}>
                  {status?.jira.configured ? "Connected" : "Not configured"}
                </span>
              </div>

              {status?.jira.configured ? (
                <div className="space-y-3">
                  <p className="text-sm text-green-600 dark:text-green-400">
                    Jira is configured. New critical/high findings will create issues in project: <strong>{status.jira.project_key}</strong>
                  </p>
                </div>
              ) : (
                <div className="space-y-3">
                  <p className="text-sm text-gray-600 dark:text-gray-400">
                    To enable Jira integration, add the following secrets:
                  </p>
                  <div className="bg-gray-50 dark:bg-gray-900 rounded-lg p-3 font-mono text-xs space-y-1">
                    <div><code className="text-gray-800 dark:text-gray-200">JIRA_BASE_URL</code> <span className="text-gray-500">(e.g., https://yourcompany.atlassian.net)</span></div>
                    <div><code className="text-gray-800 dark:text-gray-200">JIRA_EMAIL</code> <span className="text-gray-500">(your Atlassian email)</span></div>
                    <div><code className="text-gray-800 dark:text-gray-200">JIRA_API_TOKEN</code> <span className="text-gray-500">(API token from Atlassian)</span></div>
                    <div><code className="text-gray-800 dark:text-gray-200">JIRA_PROJECT_KEY</code> <span className="text-gray-500">(e.g., SEC)</span></div>
                  </div>
                  <p className="text-xs text-gray-500 dark:text-gray-400">
                    Create an <a href="https://id.atlassian.com/manage-profile/security/api-tokens" target="_blank" rel="noopener noreferrer" className="text-indigo-600 dark:text-indigo-400 hover:underline">API token</a> in your Atlassian account settings.
                  </p>
                </div>
              )}
            </div>
          </div>
        </>
      )}

      {activeTab === "scanners" && (
        <>
          <p className="text-sm text-gray-600 dark:text-gray-400">
            Supported security scanners and tools. Import scan results from any of these {parsers?.count} tools.
          </p>

          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => setSelectedCategory(null)}
              className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                selectedCategory === null
                  ? "bg-indigo-600 text-white"
                  : "bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600"
              }`}
            >
              All ({parsers?.count})
            </button>
            {parsers?.categories.map(cat => (
              <button
                key={cat}
                onClick={() => setSelectedCategory(cat)}
                className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                  selectedCategory === cat
                    ? "bg-indigo-600 text-white"
                    : "bg-gray-100 text-gray-700 dark:bg-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-600"
                }`}
              >
                {CATEGORY_LABELS[cat] || cat} ({parsers?.by_category[cat]?.length || 0})
              </button>
            ))}
          </div>

          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
            {filteredParsers.map(parser => (
              <div
                key={parser.name}
                className="rounded-xl border dark:border-gray-700 bg-white dark:bg-gray-800 p-4 shadow-sm hover:shadow-md transition-shadow"
              >
                <div className="flex items-start justify-between mb-2">
                  <h3 className="font-semibold text-gray-900 dark:text-white">{parser.display_name}</h3>
                  <span className={`px-2 py-0.5 rounded text-xs font-medium ${CATEGORY_COLORS[parser.category] || CATEGORY_COLORS.generic}`}>
                    {parser.category}
                  </span>
                </div>
                <p className="text-sm text-gray-600 dark:text-gray-400 mb-3">{parser.description}</p>
                <div className="flex flex-wrap gap-1">
                  {parser.file_types.map(ft => (
                    <span key={ft} className="px-2 py-0.5 bg-gray-100 dark:bg-gray-700 rounded text-xs text-gray-600 dark:text-gray-300">
                      .{ft}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </>
      )}

      {activeTab === "import" && (
        <>
          <p className="text-sm text-gray-600 dark:text-gray-400">
            Import scan results from any supported security tool. Paste the scan output below and we'll automatically detect the format.
          </p>

          <div className="rounded-xl border dark:border-gray-700 bg-white dark:bg-gray-800 p-6 shadow-sm">
            <div className="space-y-4">
              <div className="grid gap-4 md:grid-cols-2">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Parser (optional - auto-detect if empty)
                  </label>
                  <select
                    value={selectedParser}
                    onChange={(e) => setSelectedParser(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg border dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  >
                    <option value="">Auto-detect</option>
                    {parsers?.parsers.map(p => (
                      <option key={p.name} value={p.name}>{p.display_name} ({p.category})</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                    Default Asset (optional)
                  </label>
                  <input
                    type="text"
                    value={defaultAsset}
                    onChange={(e) => setDefaultAsset(e.target.value)}
                    placeholder="e.g., api.prod.example.com"
                    className="w-full px-3 py-2 rounded-lg border dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-400"
                  />
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                  Scan Output (JSON, XML, CSV, or JSONL)
                </label>
                <textarea
                  value={scanContent}
                  onChange={(e) => setScanContent(e.target.value)}
                  placeholder='Paste your scan results here...\n\nExamples:\n- Semgrep JSON output\n- OWASP ZAP XML/JSON\n- Trivy scan results\n- Nuclei JSONL output\n- npm audit JSON'
                  rows={12}
                  className="w-full px-3 py-2 rounded-lg border dark:border-gray-600 bg-white dark:bg-gray-700 text-gray-900 dark:text-white placeholder-gray-400 font-mono text-sm"
                />
              </div>

              <div className="flex items-center gap-4">
                <button
                  onClick={handleImport}
                  disabled={importing || !scanContent.trim()}
                  className="px-6 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 disabled:opacity-50 font-medium"
                >
                  {importing ? "Importing..." : "Import Scan Results"}
                </button>

                {importResult && (
                  <div className={`flex-1 p-3 rounded-lg ${
                    importResult.ok 
                      ? "bg-green-50 dark:bg-green-900/20 text-green-800 dark:text-green-200"
                      : "bg-red-50 dark:bg-red-900/20 text-red-800 dark:text-red-200"
                  }`}>
                    <p className="text-sm font-medium">{importResult.message}</p>
                    {importResult.ok && importResult.imported > 0 && (
                      <p className="text-xs mt-1">
                        {importResult.new_findings} new findings, {importResult.deduplicated} deduplicated
                      </p>
                    )}
                  </div>
                )}
              </div>
            </div>
          </div>

          <div className="rounded-xl border dark:border-gray-700 bg-white dark:bg-gray-800 p-6 shadow-sm">
            <h3 className="text-lg font-semibold text-gray-900 dark:text-white mb-3">Quick Start Examples</h3>
            <div className="grid gap-4 md:grid-cols-2">
              <div className="p-4 bg-gray-50 dark:bg-gray-900 rounded-lg">
                <h4 className="font-medium text-gray-900 dark:text-white mb-2">Semgrep</h4>
                <code className="text-xs text-gray-600 dark:text-gray-400">semgrep --json --output results.json</code>
              </div>
              <div className="p-4 bg-gray-50 dark:bg-gray-900 rounded-lg">
                <h4 className="font-medium text-gray-900 dark:text-white mb-2">Trivy</h4>
                <code className="text-xs text-gray-600 dark:text-gray-400">trivy image --format json image:tag</code>
              </div>
              <div className="p-4 bg-gray-50 dark:bg-gray-900 rounded-lg">
                <h4 className="font-medium text-gray-900 dark:text-white mb-2">Nuclei</h4>
                <code className="text-xs text-gray-600 dark:text-gray-400">nuclei -u target -jsonl -o results.jsonl</code>
              </div>
              <div className="p-4 bg-gray-50 dark:bg-gray-900 rounded-lg">
                <h4 className="font-medium text-gray-900 dark:text-white mb-2">npm audit</h4>
                <code className="text-xs text-gray-600 dark:text-gray-400">npm audit --json</code>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
