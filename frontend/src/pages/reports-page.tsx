import { FormEvent, useEffect, useMemo, useState } from "react";

import { StatePanel } from "../components/state-panel";
import type { BackendApi } from "../types/api";
import type { ReportCount, SecurityActivityReport } from "../types/siem";
import { formatTimestamp, humanize, toApiTimestamp } from "../utils/format";

type Range = "24h" | "7d" | "30d" | "custom";
function rangeStart(range: Exclude<Range, "custom">) { const hours = range === "24h" ? 24 : range === "7d" ? 168 : 720; return new Date(Date.now() - hours * 3_600_000).toISOString(); }
function localInput(value: Date) { const offset = value.getTimezoneOffset() * 60_000; return new Date(value.getTime() - offset).toISOString().slice(0, 16); }
function Counts({ title, rows }: { title: string; rows: ReportCount[] }) { return <article className="panel"><header className="panel__header"><h2>{title}</h2></header>{rows.length ? <div className="report-counts">{rows.map((row) => <div key={row.name}><span>{humanize(row.name)}</span><strong>{row.count}</strong></div>)}</div> : <p className="muted-copy">No matching data.</p>}</article>; }

export function ReportsPage({ api }: { api: BackendApi }) {
  const [range, setRange] = useState<Range>("24h"); const [report, setReport] = useState<SecurityActivityReport | null>(null); const [error, setError] = useState<string | null>(null); const [revision, setRevision] = useState(0);
  const [customStart, setCustomStart] = useState(() => localInput(new Date(Date.now() - 24 * 3_600_000)));
  const [customEnd, setCustomEnd] = useState(() => localInput(new Date()));
  const [draft, setDraft] = useState({ severityMin: "", severityMax: "", host: "", ruleId: "" });
  const [applied, setApplied] = useState(draft);
  const [exportBusy, setExportBusy] = useState<"csv" | "json" | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);
  const [exportSuccess, setExportSuccess] = useState<string | null>(null);
  const start = useMemo(() => range === "custom" ? toApiTimestamp(customStart) ?? "" : rangeStart(range), [customStart, range, revision]); const end = useMemo(() => range === "custom" ? toApiTimestamp(customEnd) ?? "" : new Date().toISOString(), [customEnd, range, revision]);
  const rangeError = useMemo(() => {
    if (!start || !end) return "Choose valid start and end timestamps.";
    const duration = new Date(end).getTime() - new Date(start).getTime();
    if (duration < 0) return "Report start must not be after the end.";
    if (duration > 31 * 24 * 3_600_000) return "Report range must not exceed 31 days.";
    return null;
  }, [end, start]);
  const query = useMemo(() => ({ startTime: start, endTime: end, severityMin: applied.severityMin === "" ? undefined : Number(applied.severityMin), severityMax: applied.severityMax === "" ? undefined : Number(applied.severityMax), host: applied.host.trim() || undefined, ruleId: applied.ruleId.trim() || undefined }), [start, end, applied]);
  useEffect(() => { if (rangeError) { setReport(null); setError(rangeError); return; } const controller = new AbortController(); setReport(null); setError(null); api.getSecurityActivityReport(query, controller.signal).then(setReport).catch((reason: unknown) => { if (!(reason instanceof DOMException && reason.name === "AbortError")) setError(reason instanceof Error ? reason.message : "Report unavailable."); }); return () => controller.abort(); }, [api, query, rangeError]);
  const exportUrl = (format: "csv" | "json") => { const parameters = new URLSearchParams(); parameters.set("start_time", start); parameters.set("end_time", end); if (query.severityMin != null) parameters.set("severity_min", String(query.severityMin)); if (query.severityMax != null) parameters.set("severity_max", String(query.severityMax)); if (query.host) parameters.set("host", query.host); if (query.ruleId) parameters.set("rule_id", query.ruleId); return `/api/v1/reports/security-activity.${format}?${parameters}`; };
  const download = async (format: "csv" | "json") => {
    if (rangeError) { setExportError(rangeError); return; }
    setExportBusy(format); setExportError(null); setExportSuccess(null);
    try {
      const file = await api.downloadSecurityActivityReport(query, format);
      const href = URL.createObjectURL(file.blob);
      const anchor = document.createElement("a"); anchor.href = href; anchor.download = file.filename; anchor.click();
      URL.revokeObjectURL(href);
      setExportSuccess(`${file.filename} downloaded.`);
    } catch (reason) { setExportError(reason instanceof Error ? reason.message : "Report export failed."); }
    finally { setExportBusy(null); }
  };
  const apply = (event: FormEvent) => { event.preventDefault(); setApplied(draft); };
  return <section className="page-column"><header className="page-header"><div><span className="eyebrow">Evidence export</span><h1>Security reports</h1><p>Bounded real activity summaries. CSV cells are neutralized against spreadsheet formula execution.</p></div><div className="header-actions"><label className="compact-select"><span>Range</span><select value={range} onChange={(event) => setRange(event.target.value as Range)}><option value="24h">Last 24 hours</option><option value="7d">Last 7 days</option><option value="30d">Last 30 days</option><option value="custom">Custom range</option></select></label><a className="button button--primary" aria-disabled={Boolean(exportBusy || rangeError)} href={exportUrl("csv")} download onClick={(event) => { event.preventDefault(); if (!exportBusy && !rangeError) void download("csv"); }}>{exportBusy === "csv" ? "Exporting CSV…" : "Export CSV"}</a><a className="button button--secondary" aria-disabled={Boolean(exportBusy || rangeError)} href={exportUrl("json")} download onClick={(event) => { event.preventDefault(); if (!exportBusy && !rangeError) void download("json"); }}>{exportBusy === "json" ? "Exporting JSON…" : "Export JSON"}</a></div></header>
    <form className="panel report-filters" onSubmit={apply}>{range === "custom" && <><label className="filter-field"><span>Start</span><input type="datetime-local" required value={customStart} onChange={(event) => setCustomStart(event.target.value)} /></label><label className="filter-field"><span>End</span><input type="datetime-local" required value={customEnd} onChange={(event) => setCustomEnd(event.target.value)} /></label></>}<label className="filter-field"><span>Minimum severity</span><input type="number" min="0" max="16" value={draft.severityMin} onChange={(event) => setDraft((current) => ({ ...current, severityMin: event.target.value }))} /></label><label className="filter-field"><span>Maximum severity</span><input type="number" min="0" max="16" value={draft.severityMax} onChange={(event) => setDraft((current) => ({ ...current, severityMax: event.target.value }))} /></label><label className="filter-field"><span>Host / agent</span><input maxLength={255} value={draft.host} onChange={(event) => setDraft((current) => ({ ...current, host: event.target.value }))} /></label><label className="filter-field"><span>Rule ID</span><input maxLength={128} value={draft.ruleId} onChange={(event) => setDraft((current) => ({ ...current, ruleId: event.target.value }))} /></label><button className="button button--secondary" type="submit">Apply filters</button></form>
    {exportError && <p className="form-message form-message--error" role="alert">{exportError}</p>}{exportSuccess && <p className="form-message form-message--success" role="status">{exportSuccess}</p>}
    {!report && !error && <StatePanel kind="loading" title="Building report" message="Running bounded report queries…" />}
    {error && <StatePanel kind="unavailable" title="Report unavailable" message={error} actionLabel="Retry" onAction={() => setRevision((value) => value + 1)} />}
    {report && <><p className="muted-copy">Generated {formatTimestamp(report.generated_at)} · {formatTimestamp(report.start_time)} to {formatTimestamp(report.end_time)} · display timezone {Intl.DateTimeFormat().resolvedOptions().timeZone || "local browser timezone"}</p><p className="report-filter-summary"><strong>Applied filters:</strong> severity {report.filters.severity_min ?? 0}–{report.filters.severity_max ?? 16}; host {report.filters.host ?? "any"}; rule {report.filters.rule_id ?? "any"}</p>{report.total_events === 0 && report.total_alerts === 0 && report.total_incidents === 0 && <p className="stale-warning">The report completed successfully but no matching activity exists in this range.</p>}<div className="metric-grid"><article className="metric-card"><span>Events</span><strong>{report.total_events}</strong></article><article className="metric-card"><span>Alerts</span><strong>{report.total_alerts}</strong></article><article className="metric-card"><span>Incidents</span><strong>{report.total_incidents}</strong></article><article className="metric-card"><span>Authentication failures</span><strong>{report.authentication_failures}</strong><small>Only where telemetry identifies failure</small></article><article className="metric-card"><span>FIM events</span><strong>{report.file_integrity_events}</strong></article></div><div className="overview-grid"><Counts title="Event sources" rows={report.event_sources} /><Counts title="Alert severity" rows={report.alert_severities} /><Counts title="Top detection rules" rows={report.top_rules} /><Counts title="Host activity" rows={report.host_activity} /></div></>}
  </section>;
}
