export const initialFilters = { q: "", severity: "", status: "", assignee: "", tool: "", project: "", kev: "", sla: "", sort: "priority_desc" };
export type FindingFilters = typeof initialFilters;
export function readFilters(source: Record<string, unknown>): FindingFilters {
  const result = { ...initialFilters };
  for (const key of Object.keys(result) as (keyof FindingFilters)[]) {
    if (typeof source[key] === "string") result[key] = (source[key] as string).slice(0, 500);
  }
  if (!["", "info", "low", "medium", "high", "critical"].includes(result.severity)) result.severity = "";
  if (!["", "open", "investigating", "resolved", "closed"].includes(result.status)) result.status = "";
  if (!["", "true", "false"].includes(result.kev)) result.kev = "";
  if (!["", "overdue", "due_soon", "accepted", "on_track"].includes(result.sla)) result.sla = "";
  if (!["priority_desc", "risk_desc", "last_seen_desc"].includes(result.sort)) result.sort = "priority_desc";
  return result;
}
export function filterQuery(filters: FindingFilters, offset = 0): Record<string, string> {
  return Object.fromEntries([...Object.entries(filters).filter(([, value]) => value !== ""), ...(offset ? [["offset", String(offset)]] : [])]);
}
