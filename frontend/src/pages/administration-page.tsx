import { FormEvent, useEffect, useState } from "react";

import { StatePanel } from "../components/state-panel";
import type { BackendApi } from "../types/api";
import type { AnalystPrincipal, AnalystPublic, AnalystSessionStatus, SecurityAuditEvent } from "../types/auth";
import { formatTimestamp, humanize } from "../utils/format";
import { DEFAULT_PREFERENCES, type AnalystPreferences } from "../types/preferences";


export function AdministrationPage({ api, analyst, preferences = DEFAULT_PREFERENCES, onPreferencesChange = () => undefined }: { api: BackendApi; analyst: AnalystPrincipal; preferences?: AnalystPreferences; onPreferencesChange?(preferences: AnalystPreferences): void }) {
  const [session, setSession] = useState<AnalystSessionStatus | null>(null);
  const [analysts, setAnalysts] = useState<AnalystPublic[] | null>(null);
  const [audit, setAudit] = useState<SecurityAuditEvent[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [revision, setRevision] = useState(0);
  const [passwords, setPasswords] = useState({ current: "", next: "", confirm: "" });
  const [preferenceDraft, setPreferenceDraft] = useState(preferences);
  const [auditFilters, setAuditFilters] = useState({ search: "", action: "", targetType: "", outcome: "" });
  const [auditFilterRevision, setAuditFilterRevision] = useState(0);

  useEffect(() => setPreferenceDraft(preferences), [preferences]);

  useEffect(() => {
    const controller = new AbortController();
    setError(null);
    const requests: Promise<unknown>[] = [api.getSessionStatus(controller.signal).then(setSession)];
    if (analyst.role === "ADMIN") {
      requests.push(api.listAnalysts(controller.signal).then(setAnalysts));
      requests.push(api.listAuditEvents(100, controller.signal, {
        search: auditFilters.search.trim() || undefined,
        action: auditFilters.action.trim() || undefined,
        targetType: auditFilters.targetType.trim() || undefined,
        outcome: (auditFilters.outcome || undefined) as "SUCCESS" | "DENIED" | "FAILURE" | undefined,
      }).then((page) => setAudit(page.items)));
    }
    Promise.all(requests).catch((reason: unknown) => {
      if (!(reason instanceof DOMException && reason.name === "AbortError")) setError(reason instanceof Error ? reason.message : "Administration data unavailable.");
    });
    return () => controller.abort();
  }, [api, analyst.role, revision, auditFilterRevision]);

  const changePassword = async (event: FormEvent) => {
    event.preventDefault(); setError(null); setMessage(null);
    if (passwords.next !== passwords.confirm) { setError("New password confirmation does not match."); return; }
    setBusy(true);
    try {
      await api.changePassword({ current_password: passwords.current, new_password: passwords.next });
      setPasswords({ current: "", next: "", confirm: "" });
      setMessage("Password changed. Other sessions were revoked."); setRevision((value) => value + 1);
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Password could not be changed."); }
    finally { setBusy(false); }
  };

  const revokeOthers = async () => {
    setBusy(true); setError(null); setMessage(null);
    try { await api.revokeOtherSessions(); setMessage("Other sessions revoked."); setRevision((value) => value + 1); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Sessions could not be revoked."); }
    finally { setBusy(false); }
  };

  const savePreferences = async (event: FormEvent) => {
    event.preventDefault(); setBusy(true); setError(null); setMessage(null);
    try {
      const updated = await api.updatePreferences({ ...preferenceDraft, expected_version: preferences.version });
      onPreferencesChange(updated); setPreferenceDraft(updated); setMessage("Analyst preferences saved.");
    } catch (reason) { setError(reason instanceof Error ? reason.message : "Preferences could not be saved."); }
    finally { setBusy(false); }
  };

  const resetPreferences = async () => {
    setBusy(true); setError(null); setMessage(null);
    try { const updated = await api.resetPreferences(preferences.version); onPreferencesChange(updated); setPreferenceDraft(updated); setMessage("Analyst preferences restored to defaults."); }
    catch (reason) { setError(reason instanceof Error ? reason.message : "Preferences could not be reset."); }
    finally { setBusy(false); }
  };

  return <section className="page-column">
    <header className="page-header"><div><span className="eyebrow">Security settings</span><h1>Administration</h1><p>Account state, session controls, and append-only security audit evidence.</p></div></header>
    {error && <StatePanel kind="error" title="Administration action failed" message={error} actionLabel="Retry" onAction={() => setRevision((value) => value + 1)} />}
    {message && <div className="success-banner" role="status">{message}</div>}
    <div className="overview-grid">
      <article className="panel"><header className="panel__header"><div><span className="eyebrow">Current account</span><h2>Session security</h2></div></header>
        {!session ? <p className="muted-copy">Loading session state…</p> : <dl className="metadata-grid"><div><dt>Active sessions</dt><dd>{session.active_sessions}</dd></div><div><dt>Current expiry</dt><dd>{formatTimestamp(session.current_expires_at)}</dd></div><div><dt>Role</dt><dd>{analyst.role}</dd></div></dl>}
        <button className="button button--secondary" type="button" disabled={busy || !session || session.active_sessions <= 1} onClick={() => { void revokeOthers(); }}>Revoke other sessions</button>
      </article>
      <form className="panel password-form" onSubmit={changePassword}><header className="panel__header"><div><span className="eyebrow">Credentials</span><h2>Change password</h2></div></header>
        <label className="filter-field"><span>Current password</span><input type="password" autoComplete="current-password" required maxLength={1024} value={passwords.current} onChange={(event) => setPasswords((current) => ({ ...current, current: event.target.value }))} /></label>
        <label className="filter-field"><span>New password</span><input type="password" autoComplete="new-password" required minLength={12} maxLength={128} value={passwords.next} onChange={(event) => setPasswords((current) => ({ ...current, next: event.target.value }))} /></label>
        <label className="filter-field"><span>Confirm new password</span><input type="password" autoComplete="new-password" required minLength={12} maxLength={128} value={passwords.confirm} onChange={(event) => setPasswords((current) => ({ ...current, confirm: event.target.value }))} /></label>
        <button className="button button--primary" type="submit" disabled={busy}>{busy ? "Updating…" : "Change password"}</button>
      </form>
    </div>
    <form className="panel" onSubmit={savePreferences}><header className="panel__header"><div><span className="eyebrow">Per-user defaults</span><h2>Analyst preferences</h2></div></header>
      <div className="filter-grid">
        <label className="filter-field"><span>Dashboard range</span><select value={preferenceDraft.dashboard_range} onChange={(event) => setPreferenceDraft((current) => ({ ...current, dashboard_range: event.target.value as AnalystPreferences["dashboard_range"] }))}><option value="24h">24 hours</option><option value="7d">7 days</option><option value="30d">30 days</option></select></label>
        <label className="filter-field"><span>Discover page size</span><select value={preferenceDraft.discover_page_size} onChange={(event) => setPreferenceDraft((current) => ({ ...current, discover_page_size: Number(event.target.value) as 25 | 50 | 100 }))}><option>25</option><option>50</option><option>100</option></select></label>
        <label className="filter-field"><span>Alert page size</span><select value={preferenceDraft.alert_page_size} onChange={(event) => setPreferenceDraft((current) => ({ ...current, alert_page_size: Number(event.target.value) as 25 | 50 | 100 }))}><option>25</option><option>50</option><option>100</option></select></label>
        <label className="filter-field"><span>Incident page size</span><select value={preferenceDraft.incident_page_size} onChange={(event) => setPreferenceDraft((current) => ({ ...current, incident_page_size: Number(event.target.value) as 25 | 50 | 100 }))}><option>25</option><option>50</option><option>100</option></select></label>
        <label className="filter-field"><span>Table density</span><select value={preferenceDraft.table_density} onChange={(event) => setPreferenceDraft((current) => ({ ...current, table_density: event.target.value as AnalystPreferences["table_density"] }))}><option value="COMFORTABLE">Comfortable</option><option value="COMPACT">Compact</option></select></label>
        <label className="filter-field"><span>Default alert sort</span><select value={preferenceDraft.alert_default_sort} onChange={(event) => setPreferenceDraft((current) => ({ ...current, alert_default_sort: event.target.value as AnalystPreferences["alert_default_sort"] }))}><option value="time_desc">Newest first</option><option value="time_asc">Oldest first</option><option value="severity_desc">Highest severity</option><option value="severity_asc">Lowest severity</option><option value="activity_desc">Recent activity</option></select></label>
      </div><div className="filter-actions"><button className="button button--primary" type="submit" disabled={busy}>Save preferences</button><button className="button button--secondary" type="button" disabled={busy} onClick={() => { void resetPreferences(); }}>Restore defaults</button></div>
    </form>
    {analyst.role === "ADMIN" && <>
      <article className="panel"><header className="panel__header"><div><span className="eyebrow">RBAC</span><h2>Analyst accounts</h2></div></header>
        {!analysts ? <p className="muted-copy">Loading accounts…</p> : <div className="table-frame"><table className="data-table"><thead><tr><th>Analyst</th><th>Role</th><th>Permissions</th><th>Status</th><th>Updated</th></tr></thead><tbody>{analysts.map((item) => <tr key={item.analyst_id}><td><strong>{item.display_name}</strong><span className="cell-subtle">{item.username} · {item.analyst_id}</span></td><td>{item.role}</td><td>{item.role === "ADMIN" ? "SOC read · incident write · analyst manage" : item.role === "ANALYST" ? "SOC read · incident write" : "SOC read"}</td><td><span className={`health-pill health-pill--${item.is_active ? "active" : "stale"}`}>{item.is_active ? "ACTIVE" : "DISABLED"}</span></td><td>{formatTimestamp(item.updated_at)}</td></tr>)}</tbody></table></div>}
      </article>
      <article className="panel"><header className="panel__header"><div><span className="eyebrow">Append-only evidence</span><h2>Security audit</h2></div></header>
        <div className="filter-grid"><label className="filter-field filter-field--wide"><span>Search action, actor, or target</span><input type="search" maxLength={200} value={auditFilters.search} onChange={(event) => setAuditFilters((current) => ({ ...current, search: event.target.value }))} /></label><label className="filter-field"><span>Exact action</span><input maxLength={100} value={auditFilters.action} onChange={(event) => setAuditFilters((current) => ({ ...current, action: event.target.value }))} /></label><label className="filter-field"><span>Target type</span><input maxLength={64} value={auditFilters.targetType} onChange={(event) => setAuditFilters((current) => ({ ...current, targetType: event.target.value }))} /></label><label className="filter-field"><span>Outcome</span><select value={auditFilters.outcome} onChange={(event) => setAuditFilters((current) => ({ ...current, outcome: event.target.value }))}><option value="">Any</option><option value="SUCCESS">Success</option><option value="DENIED">Denied</option><option value="FAILURE">Failure</option></select></label></div><div className="filter-actions"><button className="button button--secondary" type="button" onClick={() => setAuditFilterRevision((value) => value + 1)}>Apply audit filters</button><button className="button button--ghost" type="button" onClick={() => { setAuditFilters({ search: "", action: "", targetType: "", outcome: "" }); setAuditFilterRevision((value) => value + 1); }}>Clear</button></div>
        {!audit ? <p className="muted-copy">Loading audit evidence…</p> : audit.length === 0 ? <p className="muted-copy">No v0.2 security audit events have been recorded.</p> : <div className="table-frame"><table className="data-table"><thead><tr><th>Time</th><th>Action</th><th>Actor</th><th>Target</th><th>Outcome</th></tr></thead><tbody>{audit.map((item) => <tr key={item.audit_id}><td>{formatTimestamp(item.occurred_at)}</td><td>{humanize(item.action)}</td><td>{item.actor_display}</td><td>{item.target_type}{item.target_id ? ` · ${item.target_id}` : ""}</td><td><span className={`health-pill health-pill--${item.outcome === "SUCCESS" ? "active" : "stale"}`}>{item.outcome}</span></td></tr>)}</tbody></table></div>}
      </article>
    </>}
  </section>;
}
