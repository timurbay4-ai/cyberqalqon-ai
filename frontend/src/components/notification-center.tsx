import { useCallback, useEffect, useState } from "react";

import type { PageId } from "../layouts/app-shell";
import type { BackendApi } from "../types/api";
import type { AnalystNotification } from "../types/notifications";
import { formatTimestamp } from "../utils/format";

export function NotificationCenter({ api, refreshKey, onNavigate }: { api: BackendApi; refreshKey: string; onNavigate(page: PageId, detail?: { alert?: string; incident?: string; case?: string }): void }) {
  const [open, setOpen] = useState(false);
  const [items, setItems] = useState<AnalystNotification[]>([]);
  const [unread, setUnread] = useState(0);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback((signal?: AbortSignal) => {
    setLoading(true); setError(null);
    return api.listNotifications(25, false, signal)
      .then((response) => { setItems(response.items); setUnread(response.unread_count); })
      .catch((reason: unknown) => {
        if (reason instanceof DOMException && reason.name === "AbortError") return;
        setError(reason instanceof Error ? reason.message : "Notifications could not be loaded.");
      })
      .finally(() => setLoading(false));
  }, [api]);

  useEffect(() => {
    const controller = new AbortController();
    void load(controller.signal);
    return () => controller.abort();
  }, [load, refreshKey]);

  const openTarget = async (notification: AnalystNotification) => {
    if (!notification.read_at) {
      try {
        const updated = await api.markNotificationRead(notification.notification_id);
        setItems((current) => current.map((item) => item.notification_id === updated.notification_id ? updated : item));
        setUnread((current) => Math.max(0, current - 1));
      } catch (reason) { setError(reason instanceof Error ? reason.message : "Notification could not be marked read."); return; }
    }
    setOpen(false);
    if (notification.target_type === "alert") onNavigate("alerts", { alert: notification.target_id });
    else if (notification.target_type === "incident") onNavigate("incidents", { incident: notification.target_id });
    else if (notification.target_type === "case") onNavigate("cases", { case: notification.target_id });
    else onNavigate("operations");
  };

  const markAll = async () => {
    setBusy(true); setError(null);
    try {
      await api.markAllNotificationsRead();
      setUnread(0);
      setItems((current) => current.map((item) => ({ ...item, read_at: item.read_at ?? new Date().toISOString() })));
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Notifications could not be updated."); }
    finally { setBusy(false); }
  };

  return (
    <div className="notification-center">
      <button className="notification-trigger" type="button" aria-label={`Notifications${unread ? `, ${unread} unread` : ""}`} aria-expanded={open} onClick={() => { setOpen((current) => !current); if (!open) void load(); }}>♢{unread > 0 && <span>{unread > 99 ? "99+" : unread}</span>}</button>
      {open && <section className="notification-popover" aria-label="Notifications"><header><div><span className="eyebrow">SOC inbox</span><h2>Notifications</h2></div><button className="button button--ghost" type="button" disabled={busy || unread === 0} onClick={() => { void markAll(); }}>Mark all read</button></header>
        {loading && items.length === 0 && <p className="muted-copy">Loading notifications…</p>}
        {error && <p className="inline-error" role="alert">{error} <button type="button" onClick={() => { void load(); }}>Retry</button></p>}
        {!loading && !error && items.length === 0 && <p className="muted-copy">No persisted notifications.</p>}
        {items.length > 0 && <ol>{items.map((item) => <li className={item.read_at ? "" : "is-unread"} key={item.notification_id}><button type="button" onClick={() => { void openTarget(item); }}><strong>{item.title}</strong><span>{item.preview}</span><time dateTime={item.created_at}>{formatTimestamp(item.created_at)}</time></button></li>)}</ol>}
      </section>}
    </div>
  );
}
