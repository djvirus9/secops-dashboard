import { useCallback, useEffect, useState } from "react";
import { apiGet, type ApiQuery } from "./api";

/** Cancel superseded reads so an older filter response cannot overwrite the current page. */
export function useApiResource<T>(path: string, query?: ApiQuery) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [revision, setRevision] = useState(0);
  const queryKey = JSON.stringify(query || {});
  const reload = useCallback(() => setRevision((value) => value + 1), []);
  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError("");
    setData(null);
    apiGet<T>(path, { query: JSON.parse(queryKey), signal: controller.signal })
      .then((result) => { if (!controller.signal.aborted) setData(result); })
      .catch((reason) => {
        if (!controller.signal.aborted) setError(reason instanceof Error ? reason.message : "Unable to load data");
      })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [path, queryKey, revision]);
  return { data, error, loading, reload };
}
