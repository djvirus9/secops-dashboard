import { useEffect, useState } from "react";
import { apiGet } from "./api";

export type EligibleUser = { id: string; username: string; role: string };
export type Ownership = { status: "assigned" | "unassigned" | "invalid_assignee"; team_id: string | null; team_name: string | null };
export type OwnershipRule = { project: string; team_id: string | null; team_name: string | null; enabled: boolean; default_assignee: string | null; ready: boolean; warning: string | null };

/** Only offer users eligible for every selected project. The backend rechecks on save. */
export function useEligibleAssignees(projects: string[], enabled = true) {
  const key = JSON.stringify([...new Set(projects)].sort());
  const [users, setUsers] = useState<EligibleUser[]>([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [truncated, setTruncated] = useState(false);
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    setUsers([]); setError(""); setTruncated(false);
    if (!enabled) { setLoading(false); return; }
    setLoading(true);
    Promise.all((JSON.parse(key) as string[]).map(project => apiGet<{ count: number; results: EligibleUser[] }>("/ownership/assignees", { query: { project, limit: 200 }, signal: controller.signal })))
      .then(pages => {
        if (controller.signal.aborted) return;
        setTruncated(pages.some(page => page.count > page.results.length));
        setUsers((pages[0]?.results || []).filter(user => pages.every(page => page.results.some(candidate => candidate.id === user.id))));
      })
      .catch(reason => { if (!controller.signal.aborted) setError(reason instanceof Error ? reason.message : "Unable to load eligible assignees"); })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [key, enabled, revision]);
  return { users, error, loading, truncated, reload: () => setRevision(value => value + 1) };
}
