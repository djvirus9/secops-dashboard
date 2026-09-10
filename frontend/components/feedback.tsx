export function ErrorNotice({ message, retry }: { message: string; retry?: () => void }) {
  if (!message) return null;
  return <div role="alert" className="rounded-lg border border-red-300 bg-red-50 p-3 text-sm text-red-900 dark:border-red-800 dark:bg-red-900/20 dark:text-red-200">
    <p className="break-words">{message}</p>
    {retry && <button type="button" onClick={retry} className="mt-2 font-semibold underline">Retry</button>}
  </div>;
}

export function Pagination({ count, offset, limit, loading, onPage }: {
  count: number; offset: number; limit: number; loading: boolean; onPage: (offset: number) => void;
}) {
  return <nav aria-label="Pagination" className="flex flex-wrap items-center justify-between gap-3 text-sm text-gray-700 dark:text-gray-300">
    <p role="status">{count ? `${offset + 1}–${Math.min(offset + limit, count)} of ${count}` : "0 results"}</p>
    <div className="flex gap-2">
      <button className="button-secondary" onClick={() => onPage(Math.max(0, offset - limit))} disabled={loading || offset === 0}>Previous</button>
      <button className="button-secondary" onClick={() => onPage(offset + limit)} disabled={loading || offset + limit >= count}>Next</button>
    </div>
  </nav>;
}
