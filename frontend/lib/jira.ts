export type JiraLink = {
  finding_id: string; issue_key: string; url: string; remote_status: string | null;
  remote_status_category: string | null; remote_assignee: string | null;
  remote_updated_at: string | null; last_synced_at: string | null; next_sync_at: string | null;
  status: "idle" | "queued" | "syncing" | "failed" | "needs_review";
  operation: "pull" | "push_status" | "push_assignee"; last_error: string | null;
};
export type JiraProgress = {
  configured: boolean; enabled: boolean; link: JiraLink | null;
  push_preview: { local_status: string; local_assignee: string | null; status_target_category: "new" | "indeterminate" | "done" | null; assignee_mapped: boolean };
  note: string;
};
export function safeJiraUrl(value: string): string | null {
  try { const url = new URL(value); return url.protocol === "https:" && !url.username && !url.password ? url.href : null; }
  catch { return null; }
}
