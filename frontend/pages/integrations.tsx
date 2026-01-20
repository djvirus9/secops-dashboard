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

export default function Integrations() {
  const [status, setStatus] = useState<IntegrationStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [testingSlack, setTestingSlack] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; message: string } | null>(null);

  useEffect(() => {
    apiGet<IntegrationStatus>("/integrations")
      .then(setStatus)
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

  if (loading) {
    return <div className="text-gray-600 dark:text-gray-300">Loading...</div>;
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-semibold text-gray-900 dark:text-white">Integrations</h1>
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

      <div className="rounded-xl border dark:border-gray-700 bg-white dark:bg-gray-800 p-6 shadow-sm">
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white mb-3">How it works</h2>
        <ul className="space-y-2 text-sm text-gray-600 dark:text-gray-400">
          <li className="flex items-start gap-2">
            <span className="text-indigo-500 mt-0.5">1.</span>
            <span>When a new finding with <strong>critical</strong> or <strong>high</strong> severity is ingested, notifications are triggered.</span>
          </li>
          <li className="flex items-start gap-2">
            <span className="text-indigo-500 mt-0.5">2.</span>
            <span><strong>Slack</strong>: Sends a formatted message with finding details to your configured channel.</span>
          </li>
          <li className="flex items-start gap-2">
            <span className="text-indigo-500 mt-0.5">3.</span>
            <span><strong>Jira</strong>: Creates a new issue with severity-based priority, linked to the finding.</span>
          </li>
          <li className="flex items-start gap-2">
            <span className="text-indigo-500 mt-0.5">4.</span>
            <span>Repeat occurrences of the same finding also trigger Slack notifications (but not new Jira issues).</span>
          </li>
        </ul>
      </div>
    </div>
  );
}
