import { memo, useEffect, useState } from "react";
import { api } from "../api.js";
import { Loading, ErrorBanner } from "../components/Feedback.jsx";
import { PageHeader, Card, Badge, Button } from "../components/ui/index.js";

const ENTITY_TYPES = ["alert", "incident", "event"];

function BookmarkRow({ bookmark, onDelete }) {
  const [deleting, setDeleting] = useState(false);

  const handleDelete = async () => {
    setDeleting(true);
    try {
      await api.request(`/api/bookmarks/${bookmark.id}`, { method: "DELETE" });
      onDelete(bookmark.id);
    } catch {
      setDeleting(false);
    }
  };

  return (
    <div className="flex items-start justify-between gap-4 rounded-[var(--radius-xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] p-4 transition-all hover:border-[var(--border-strong)] hover:shadow-md">
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2.5">
          <Badge severity={bookmark.entity_type === "alert" ? "high" : bookmark.entity_type === "incident" ? "critical" : "info"} size="sm">
            {bookmark.entity_type}
          </Badge>
          <span className="font-mono text-[11px] text-[var(--fg-muted)]">#{bookmark.entity_id}</span>
        </div>
        {bookmark.note && (
          <p className="mt-2 text-[13px] text-[var(--fg-secondary)] leading-relaxed">{bookmark.note}</p>
        )}
        <p className="mt-1.5 text-[11px] text-[var(--fg-muted)]">
          Bookmarked {new Date(bookmark.created_at).toLocaleString()}
        </p>
      </div>
      <Button variant="danger-ghost" size="xs" onClick={handleDelete} disabled={deleting}>
        {deleting ? "..." : "Remove"}
      </Button>
    </div>
  );
}

function Bookmarks() {
  const [bookmarks, setBookmarks] = useState(null);
  const [error, setError] = useState("");
  const [filter, setFilter] = useState("");

  const load = () => {
    setError("");
    api
      .request("/api/bookmarks")
      .then((data) => setBookmarks(data.items || data))
      .catch((e) => setError(e.message));
  };

  useEffect(() => { load(); }, []);

  const handleDelete = (id) => {
    setBookmarks((prev) => (prev || []).filter((b) => b.id !== id));
  };

  const filtered = bookmarks
    ? filter
      ? bookmarks.filter((b) => b.entity_type === filter)
      : bookmarks
    : [];

  return (
    <div className="space-y-6 pb-10">
      <PageHeader
        title="Bookmarks"
        subtitle="Saved alerts, incidents, and events for quick access"
        label="Workspace"
      />

      {error && <ErrorBanner message={error} onRetry={load} />}

      {!bookmarks && !error && <Loading label="Loading bookmarks" />}

      {bookmarks && (
        <>
          <div className="flex items-center gap-3 rounded-[var(--radius-2xl)] border border-[var(--border-default)] bg-[var(--bg-surface)] p-4">
            <span className="text-[11px] font-semibold uppercase tracking-[var(--tracking-wider)] text-[var(--fg-muted)]">Filter</span>
            <div className="h-4 w-px bg-[var(--border-default)]" />
            {ENTITY_TYPES.map((t) => (
              <button
                key={t}
                type="button"
                onClick={() => setFilter(filter === t ? "" : t)}
                className={`rounded-lg px-3 py-1.5 text-[12px] font-medium transition-all ${
                  filter === t
                    ? "bg-[var(--accent-cyan)]/10 text-[var(--accent-cyan)] border border-[var(--accent-cyan)]/30"
                    : "bg-[var(--bg-inset)] text-[var(--fg-muted)] border border-[var(--border-default)] hover:text-[var(--fg-secondary)]"
                }`}
              >
                {t}
              </button>
            ))}
            <span className="ml-auto text-[11px] text-[var(--fg-muted)]">
              {filtered.length} bookmark{filtered.length !== 1 ? "s" : ""}
            </span>
          </div>

          {filtered.length === 0 ? (
            <Card className="flex flex-col items-center justify-center py-16 text-center">
              <div className="mb-4 flex h-14 w-14 items-center justify-center rounded-[var(--radius-2xl)] bg-[var(--bg-surface-active)]">
                <span className="text-2xl">&#9734;</span>
              </div>
              <h3 className="text-base font-semibold text-[var(--fg-primary)]">No bookmarks yet</h3>
              <p className="mt-1.5 max-w-sm text-sm text-[var(--fg-muted)] leading-relaxed">
                Bookmark alerts, incidents, or events to quickly access them later.
              </p>
            </Card>
          ) : (
            <div className="space-y-2">
              {filtered.map((b) => (
                <BookmarkRow key={b.id} bookmark={b} onDelete={handleDelete} />
              ))}
            </div>
          )}
        </>
      )}
    </div>
  );
}

export default memo(Bookmarks);
