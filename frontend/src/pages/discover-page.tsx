import { FormEvent, useEffect, useMemo, useState } from "react";

import { EventDetail } from "../components/event-detail";
import { Pagination } from "../components/pagination";
import { SeverityBadge } from "../components/severity-badge";
import { StatePanel } from "../components/state-panel";
import type { BackendApi, SecurityEventListResponse } from "../types/api";
import { EVENT_SOURCE_TYPES, type EventQuery, type SavedEventSearch, type SavedEventSearchQuery, type SecurityEventDetail, type SecurityEventSummary } from "../types/events";
import { formatTimestamp, humanize } from "../utils/format";
import { DEFAULT_PREFERENCES, DISCOVER_COLUMNS, type AnalystPreferences, type DiscoverColumn } from "../types/preferences";

type Preset = "15m" | "1h" | "24h" | "7d" | "custom";

interface FilterValues {
  preset: Preset;
  startTime: string;
  endTime: string;
  search: string;
  sourceIp: string;
  destinationIp: string;
  hostname: string;
  username: string;
  eventId: string;
  ruleId: string;
  eventCategory: string;
  outcome: string;
  sourceType: string;
  severityMin: string;
  severityMax: string;
  sort: "newest" | "oldest";
}

const EMPTY_FILTERS: FilterValues = {
  preset: "24h", startTime: "", endTime: "", search: "", sourceIp: "", destinationIp: "",
  hostname: "", username: "", eventId: "", ruleId: "", sourceType: "", severityMin: "",
  eventCategory: "", outcome: "", severityMax: "", sort: "newest",
};

const PRESET_MINUTES: Record<Exclude<Preset, "custom">, 15 | 60 | 1440 | 10080> = {
  "15m": 15, "1h": 60, "24h": 1440, "7d": 10080,
};

const URL_FILTER_KEYS = ["range", "from", "to", "source_type", "rule_id", "category", "outcome", "severity_min", "severity_max", "sort"];

function filtersFromUrl(): FilterValues {
  const parameters = new URLSearchParams(window.location.search);
  const range = parameters.get("range");
  const preset: Preset = range === "15m" || range === "1h" || range === "7d" || range === "custom" ? range : "24h";
  return {
    ...EMPTY_FILTERS,
    preset,
    startTime: preset === "custom" ? parameters.get("from") ?? "" : "",
    endTime: preset === "custom" ? parameters.get("to") ?? "" : "",
    sourceType: EVENT_SOURCE_TYPES.includes(parameters.get("source_type") as never) ? parameters.get("source_type")! : "",
    ruleId: parameters.get("rule_id") ?? "",
    eventCategory: parameters.get("category") ?? "",
    outcome: parameters.get("outcome") ?? "",
    severityMin: parameters.get("severity_min") ?? "",
    severityMax: parameters.get("severity_max") ?? "",
    sort: parameters.get("sort") === "oldest" ? "oldest" : "newest",
  };
}

function updateDiscoverHistory(values: FilterValues): void {
  const url = new URL(window.location.href);
  URL_FILTER_KEYS.forEach((key) => url.searchParams.delete(key));
  url.searchParams.set("view", "discover");
  url.searchParams.delete("event");
  if (values.preset !== "24h") url.searchParams.set("range", values.preset);
  if (values.preset === "custom") {
    if (values.startTime) url.searchParams.set("from", values.startTime);
    if (values.endTime) url.searchParams.set("to", values.endTime);
  }
  if (values.sourceType) url.searchParams.set("source_type", values.sourceType);
  if (values.ruleId) url.searchParams.set("rule_id", values.ruleId);
  if (values.eventCategory) url.searchParams.set("category", values.eventCategory);
  if (values.outcome) url.searchParams.set("outcome", values.outcome);
  if (values.severityMin) url.searchParams.set("severity_min", values.severityMin);
  if (values.severityMax) url.searchParams.set("severity_max", values.severityMax);
  if (values.sort !== "newest") url.searchParams.set("sort", values.sort);
  window.history.pushState({ cyberqalqonDiscover: values }, "", url);
}

function presetRange(preset: Preset): { startTime?: string; endTime?: string } {
  if (preset === "custom") return {};
  const end = new Date();
  const duration = { "15m": 15 * 60_000, "1h": 60 * 60_000, "24h": 24 * 60 * 60_000, "7d": 7 * 24 * 60 * 60_000 }[preset];
  return { startTime: new Date(end.getTime() - duration).toISOString(), endTime: end.toISOString() };
}

function customTimestamp(value: string): string | undefined {
  if (!value) return undefined;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? undefined : parsed.toISOString();
}

function eventQuery(values: FilterValues): EventQuery {
  const range = values.preset === "custom"
    ? { startTime: customTimestamp(values.startTime), endTime: customTimestamp(values.endTime) }
    : presetRange(values.preset);
  return {
    ...range,
    search: values.search.trim() || undefined,
    sourceIp: values.sourceIp.trim() || undefined,
    destinationIp: values.destinationIp.trim() || undefined,
    hostname: values.hostname.trim() || undefined,
    username: values.username.trim() || undefined,
    eventId: values.eventId.trim() || undefined,
    ruleId: values.ruleId.trim() || undefined,
    eventCategory: values.eventCategory.trim() || undefined,
    outcome: values.outcome.trim() || undefined,
    sourceType: (values.sourceType || undefined) as EventQuery["sourceType"],
    severityMin: values.severityMin === "" ? undefined : Number(values.severityMin),
    severityMax: values.severityMax === "" ? undefined : Number(values.severityMax),
    sort: values.sort,
    limit: 25,
  };
}

function savedQuery(values: FilterValues): SavedEventSearchQuery {
  const query = eventQuery(values);
  const { startTime, endTime, limit: _limit, ...filters } = query;
  if (values.preset === "custom") return { ...filters, startTime, endTime };
  return { ...filters, relativeMinutes: PRESET_MINUTES[values.preset] };
}

function savedValues(saved: SavedEventSearch): FilterValues {
  const query = saved.query;
  const presetByMinutes: Partial<Record<number, Preset>> = { 15: "15m", 60: "1h", 1440: "24h", 10080: "7d" };
  const preset = query.relativeMinutes ? (presetByMinutes[query.relativeMinutes] ?? "custom") : "custom";
  const localValue = (value?: string) => value ? new Date(value).toISOString().slice(0, 16) : "";
  return {
    preset,
    startTime: localValue(query.startTime), endTime: localValue(query.endTime),
    search: query.search ?? "", sourceIp: query.sourceIp ?? "", destinationIp: query.destinationIp ?? "",
    hostname: query.hostname ?? "", username: query.username ?? "", eventId: query.eventId ?? "",
    ruleId: query.ruleId ?? "", eventCategory: query.eventCategory ?? "", outcome: query.outcome ?? "",
    sourceType: query.sourceType ?? "", severityMin: query.severityMin == null ? "" : String(query.severityMin),
    severityMax: query.severityMax == null ? "" : String(query.severityMax), sort: query.sort ?? "newest",
  };
}

const COLUMN_LABELS: Record<DiscoverColumn, string> = { time: "Time", source: "Source", host: "Host", identity: "Identity / network", rule: "Rule", event: "Event" };

function EventsTable({ events, selectedId, onSelect, columns, compact }: { events: SecurityEventSummary[]; selectedId: string | null; onSelect(id: string): void; columns: DiscoverColumn[]; compact: boolean }) {
  const cell = (column: DiscoverColumn, event: SecurityEventSummary) => {
    if (column === "time") return <td key={column}><button className="row-select" type="button" onClick={(click) => { click.stopPropagation(); onSelect(event.event_id); }}>{formatTimestamp(event.timestamp)}</button></td>;
    if (column === "source") return <td key={column}><span className="source-pill">{humanize(event.source_type)}</span>{event.severity != null && <SeverityBadge level={event.severity} />}</td>;
    if (column === "host") return <td key={column}><strong>{event.hostname ?? event.agent_name ?? "Unknown"}</strong><small>{event.agent_id ? `Agent ${event.agent_id}` : "No agent ID"}</small></td>;
    if (column === "identity") return <td key={column}><span className="mono">{event.source_ip ?? "—"}{event.source_port ? `:${event.source_port}` : ""}</span><small>{event.username ?? "No username"}</small></td>;
    if (column === "rule") return <td key={column}><span className="mono">{event.rule_id ?? "—"}</span><small>{event.event_code ? `Event ${event.event_code}` : event.event_category ?? "No category"}</small></td>;
    return <td key={column}><strong>{event.message}</strong><small className="mono">{event.event_id}</small></td>;
  };
  return (
    <div className="table-frame"><table className={`data-table events-table${compact ? " data-table--compact" : ""}`}>
      <thead><tr>{columns.map((column) => <th scope="col" key={column}>{COLUMN_LABELS[column]}</th>)}</tr></thead>
      <tbody>{events.map((event) => (
        <tr className={selectedId === event.event_id ? "is-selected" : undefined} key={event.event_id} onClick={() => onSelect(event.event_id)}>
          {columns.map((column) => cell(column, event))}
        </tr>
      ))}</tbody>
    </table></div>
  );
}

export function DiscoverPage({ api, preferences = DEFAULT_PREFERENCES, onPreferencesChange = () => undefined, openEventId, onOpenAlert, onOpenIncident }: { api: BackendApi; preferences?: AnalystPreferences; onPreferencesChange?(preferences: AnalystPreferences): void; openEventId?: string | null; onOpenAlert(id: string): void; onOpenIncident(id: string): void }) {
  const initialFilters = filtersFromUrl();
  const [draft, setDraft] = useState<FilterValues>(initialFilters);
  const [applied, setApplied] = useState<FilterValues>(initialFilters);
  const [pageSize, setPageSize] = useState(preferences.discover_page_size);
  const [cursor, setCursor] = useState<string | undefined>();
  const [cursorStack, setCursorStack] = useState<Array<string | undefined>>([]);
  const [data, setData] = useState<SecurityEventListResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [revision, setRevision] = useState(0);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<SecurityEventDetail | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [savedSearches, setSavedSearches] = useState<SavedEventSearch[]>([]);
  const [selectedSavedId, setSelectedSavedId] = useState("");
  const [saveName, setSaveName] = useState("");
  const [renameName, setRenameName] = useState("");
  const [savedError, setSavedError] = useState<string | null>(null);
  const [savedBusy, setSavedBusy] = useState(false);
  const [preferenceError, setPreferenceError] = useState<string | null>(null);
  const query = useMemo(() => ({ ...eventQuery(applied), limit: pageSize, cursor }), [applied, cursor, pageSize]);

  useEffect(() => { setSelectedId(openEventId ?? null); }, [openEventId]);
  useEffect(() => setPageSize(preferences.discover_page_size), [preferences.discover_page_size]);

  useEffect(() => {
    const close = () => { const url = new URL(window.location.href); url.searchParams.delete("event"); window.history.replaceState(window.history.state, "", url); setSelectedId(null); };
    window.addEventListener("cyberqalqon:escape", close);
    return () => window.removeEventListener("cyberqalqon:escape", close);
  }, []);

  useEffect(() => {
    const restore = (event: PopStateEvent) => {
      const next = (event.state as { cyberqalqonDiscover?: FilterValues } | null)?.cyberqalqonDiscover ?? filtersFromUrl();
      setDraft(next); setApplied(next); setCursor(undefined); setCursorStack([]);
      setSelectedId(new URLSearchParams(window.location.search).get("event"));
    };
    window.addEventListener("popstate", restore);
    return () => window.removeEventListener("popstate", restore);
  }, []);

  const refreshSavedSearches = () => api.listSavedEventSearches().then(setSavedSearches);

  useEffect(() => {
    const controller = new AbortController();
    api.listSavedEventSearches(controller.signal).then(setSavedSearches).catch((reason: unknown) => {
      if (!(reason instanceof DOMException && reason.name === "AbortError")) setSavedError(reason instanceof Error ? reason.message : "Saved searches unavailable.");
    });
    return () => controller.abort();
  }, [api]);

  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    setLoading(true); setError(null);
    api.listEvents(query, controller.signal)
      .then((response) => { if (active) setData(response); })
      .catch((reason: unknown) => {
        if (!active || (reason instanceof DOMException && reason.name === "AbortError")) return;
        setError(reason instanceof Error ? reason.message : "Security events could not be loaded.");
      })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; controller.abort(); };
  }, [api, query, revision]);

  useEffect(() => {
    if (!selectedId) { setDetail(null); setDetailError(null); return; }
    const controller = new AbortController();
    let active = true;
    setDetail(null); setDetailError(null);
    api.getEvent(selectedId, controller.signal)
      .then((response) => { if (active) setDetail(response); })
      .catch((reason: unknown) => { if (active) setDetailError(reason instanceof Error ? reason.message : "Event detail unavailable."); });
    return () => { active = false; controller.abort(); };
  }, [api, selectedId]);

  const apply = (event: FormEvent) => {
    event.preventDefault();
    setApplied(draft); setCursor(undefined); setCursorStack([]); updateDiscoverHistory(draft);
  };
  const field = (name: keyof FilterValues) => ({
    value: draft[name],
    onChange: (event: React.ChangeEvent<HTMLInputElement | HTMLSelectElement>) => setDraft((current) => ({ ...current, [name]: event.target.value })),
  });
  const loadSaved = (savedSearchId: string) => {
    setSelectedSavedId(savedSearchId);
    const saved = savedSearches.find((item) => item.saved_search_id === savedSearchId);
    if (!saved) return;
    const values = savedValues(saved);
    setDraft(values); setApplied(values); setCursor(undefined); setCursorStack([]); setSavedError(null); setRenameName(saved.name); updateDiscoverHistory(values);
  };
  const saveCurrent = async () => {
    if (!saveName.trim()) { setSavedError("Enter a name before saving this search."); return; }
    setSavedBusy(true); setSavedError(null);
    try {
      const saved = await api.saveEventSearch({ name: saveName.trim(), query: savedQuery(draft) });
      await refreshSavedSearches(); setSelectedSavedId(saved.saved_search_id); setSaveName("");
    } catch (reason) { setSavedError(reason instanceof Error ? reason.message : "Search could not be saved."); }
    finally { setSavedBusy(false); }
  };
  const deleteSaved = async () => {
    if (!selectedSavedId) return;
    setSavedBusy(true); setSavedError(null);
    try { await api.deleteSavedEventSearch(selectedSavedId); setSelectedSavedId(""); await refreshSavedSearches(); }
    catch (reason) { setSavedError(reason instanceof Error ? reason.message : "Saved search could not be deleted."); }
    finally { setSavedBusy(false); }
  };
  const renameSaved = async () => {
    const selected = savedSearches.find((item) => item.saved_search_id === selectedSavedId);
    if (!selected) return;
    if (!renameName.trim()) { setSavedError("Enter a name before renaming this search."); return; }
    setSavedBusy(true); setSavedError(null);
    try { await api.updateSavedEventSearch(selected.saved_search_id, { name: renameName.trim(), query: selected.query }); await refreshSavedSearches(); }
    catch (reason) { setSavedError(reason instanceof Error ? reason.message : "Saved search could not be renamed."); }
    finally { setSavedBusy(false); }
  };

  const activeFilters = Object.entries(applied).filter(([key, value]) => {
    if (key === "preset") return value !== "24h";
    if (key === "sort") return value !== "newest";
    return value !== "";
  }) as Array<[keyof FilterValues, string]>;
  const removeFilter = (name: keyof FilterValues) => {
    const next = { ...applied, [name]: EMPTY_FILTERS[name] };
    if (name === "preset") { next.startTime = ""; next.endTime = ""; }
    setDraft(next); setApplied(next); setCursor(undefined); setCursorStack([]); updateDiscoverHistory(next);
  };
  const clearFilters = () => {
    setDraft(EMPTY_FILTERS); setApplied(EMPTY_FILTERS); setCursor(undefined); setCursorStack([]); updateDiscoverHistory(EMPTY_FILTERS);
  };
  const selectEvent = (eventId: string) => {
    const url = new URL(window.location.href); url.searchParams.set("view", "discover"); url.searchParams.set("event", eventId);
    window.history.pushState({ cyberqalqonDiscover: applied }, "", url); setSelectedId(eventId);
  };
  const closeEvent = () => {
    const url = new URL(window.location.href); url.searchParams.delete("event");
    window.history.replaceState({ cyberqalqonDiscover: applied }, "", url); setSelectedId(null);
  };
  const persistPreferences = async (changes: Partial<Omit<AnalystPreferences, "version">>) => {
    setPreferenceError(null);
    try {
      const updated = await api.updatePreferences({ ...preferences, ...changes, expected_version: preferences.version });
      onPreferencesChange(updated);
    } catch (reason) { setPreferenceError(reason instanceof Error ? reason.message : "Column preferences could not be saved."); }
  };
  const toggleColumn = (column: DiscoverColumn) => {
    if (column === "time" || column === "event") return;
    const columns = preferences.discover_columns.includes(column)
      ? preferences.discover_columns.filter((item) => item !== column)
      : [...preferences.discover_columns, column];
    void persistPreferences({ discover_columns: columns });
  };
  const moveColumn = (column: DiscoverColumn, direction: -1 | 1) => {
    const columns = [...preferences.discover_columns];
    const index = columns.indexOf(column); const target = index + direction;
    if (index < 0 || target < 0 || target >= columns.length) return;
    [columns[index], columns[target]] = [columns[target], columns[index]];
    void persistPreferences({ discover_columns: columns });
  };

  return (
    <div className="page-grid page-grid--discover">
      <section className="page-column">
        <header className="page-header"><div><span className="eyebrow">Discover</span><h1>Security event explorer</h1><p>Bounded Wazuh archive events and alert evidence. Filters execute server-side.</p></div><div className="page-header__metric"><strong>{data?.page.total ?? "—"}</strong><span>matching events</span></div></header>
        <section className="panel saved-searches" aria-label="Saved searches">
          <div><label className="filter-field"><span>Saved search</span><select value={selectedSavedId} onChange={(event) => loadSaved(event.target.value)}><option value="">Choose a saved search</option>{savedSearches.map((saved) => <option key={saved.saved_search_id} value={saved.saved_search_id}>{saved.name}</option>)}</select></label><button className="button button--secondary" type="button" disabled={!selectedSavedId || savedBusy} onClick={() => { void deleteSaved(); }}>Delete</button></div>
          <div><label className="filter-field"><span>Save current filters as</span><input maxLength={100} value={saveName} onChange={(event) => setSaveName(event.target.value)} placeholder="Investigation view" /></label><button className="button button--secondary" type="button" disabled={savedBusy} onClick={() => { void saveCurrent(); }}>{savedBusy ? "Working…" : "Save"}</button></div>
          {selectedSavedId && <div><label className="filter-field"><span>Rename selected search</span><input maxLength={100} value={renameName} onChange={(event) => setRenameName(event.target.value)} /></label><button className="button button--secondary" type="button" disabled={savedBusy} onClick={() => { void renameSaved(); }}>Rename</button></div>}
          {savedError && <p className="inline-error" role="alert">{savedError}</p>}
        </section>
        <section className="panel column-controls" aria-label="Discover column settings"><div className="section-heading"><div><h2>Table layout</h2><p>Column order and density are stored for your analyst account.</p></div><button className="button button--ghost" type="button" onClick={() => { void persistPreferences({ discover_columns: [...DISCOVER_COLUMNS], table_density: "COMFORTABLE" }); }}>Restore defaults</button></div><div className="column-controls__list">{DISCOVER_COLUMNS.map((column) => { const visible = preferences.discover_columns.includes(column); const index = preferences.discover_columns.indexOf(column); const essential = column === "time" || column === "event"; return <span className="column-control" key={column}><label><input type="checkbox" checked={visible} disabled={essential} onChange={() => toggleColumn(column)} />{COLUMN_LABELS[column]}</label>{visible && <><button type="button" aria-label={`Move ${COLUMN_LABELS[column]} left`} disabled={index <= 0} onClick={() => moveColumn(column, -1)}>←</button><button type="button" aria-label={`Move ${COLUMN_LABELS[column]} right`} disabled={index === preferences.discover_columns.length - 1} onClick={() => moveColumn(column, 1)}>→</button></>}</span>; })}</div><label className="filter-field"><span>Density</span><select value={preferences.table_density} onChange={(event) => { void persistPreferences({ table_density: event.target.value as AnalystPreferences["table_density"] }); }}><option value="COMFORTABLE">Comfortable</option><option value="COMPACT">Compact</option></select></label>{preferenceError && <p className="inline-error" role="alert">{preferenceError}</p>}</section>
        <form className="panel event-filters" onSubmit={apply}>
          <div className="filter-grid">
            <label className="filter-field filter-field--wide"><span>Keyword</span><input id="discover-search" type="search" placeholder="Message, host, IP, rule…" maxLength={200} {...field("search")} /></label>
            <label className="filter-field"><span>Time range</span><select {...field("preset")}><option value="15m">Last 15 minutes</option><option value="1h">Last hour</option><option value="24h">Last 24 hours</option><option value="7d">Last 7 days</option><option value="custom">Custom</option></select></label>
            <label className="filter-field"><span>Source type</span><select {...field("sourceType")}><option value="">All sources</option>{EVENT_SOURCE_TYPES.map((value) => <option value={value} key={value}>{humanize(value)}</option>)}</select></label>
            <label className="filter-field"><span>Source IP</span><input placeholder="127.0.0.1" maxLength={64} {...field("sourceIp")} /></label>
            <label className="filter-field"><span>Destination IP</span><input placeholder="127.0.0.1" maxLength={64} {...field("destinationIp")} /></label>
            <label className="filter-field"><span>Hostname</span><input maxLength={255} {...field("hostname")} /></label>
            <label className="filter-field"><span>Username</span><input maxLength={512} {...field("username")} /></label>
            <label className="filter-field"><span>Event ID / code</span><input maxLength={255} {...field("eventId")} /></label>
            <label className="filter-field"><span>Wazuh rule ID</span><input maxLength={128} {...field("ruleId")} /></label>
            <label className="filter-field"><span>Event category</span><input maxLength={255} {...field("eventCategory")} /></label>
            <label className="filter-field"><span>Outcome</span><input maxLength={128} placeholder="success / failure" {...field("outcome")} /></label>
            <label className="filter-field"><span>Minimum severity</span><input type="number" min="0" max="16" {...field("severityMin")} /></label>
            <label className="filter-field"><span>Maximum severity</span><input type="number" min="0" max="16" {...field("severityMax")} /></label>
            <label className="filter-field"><span>Sort</span><select {...field("sort")}><option value="newest">Newest first</option><option value="oldest">Oldest first</option></select></label>
            {draft.preset === "custom" && <><label className="filter-field"><span>Start</span><input type="datetime-local" {...field("startTime")} /></label><label className="filter-field"><span>End</span><input type="datetime-local" {...field("endTime")} /></label></>}
          </div>
          <div className="filter-actions">{draft.search && <button className="button button--ghost" type="button" onClick={() => setDraft((current) => ({ ...current, search: "" }))}>Clear search</button>}<button className="button button--primary" type="submit">Search events</button><button className="button button--secondary" type="button" onClick={clearFilters}>Reset</button></div>
        </form>
        {activeFilters.length > 0 && <section className="active-filters" aria-label="Active filters"><span>Active filters</span>{activeFilters.map(([name, value]) => <button type="button" key={name} onClick={() => removeFilter(name)} aria-label={`Remove ${humanize(name)} filter`}>{humanize(name)}: {value}<b aria-hidden="true">×</b></button>)}<button className="active-filters__clear" type="button" onClick={clearFilters}>Clear all</button></section>}
        {loading && !data && <StatePanel kind="loading" title="Searching events" message="Running bounded indexed queries…" />}
        {error && <StatePanel kind="unavailable" title="Event search unavailable" message={error} actionLabel="Retry" onAction={() => setRevision((value) => value + 1)} />}
        {!loading && !error && data?.items.length === 0 && <StatePanel kind="empty" title="No matching events" message="No stored event matches this range and filter set." />}
        {!error && data && data.items.length > 0 && <><EventsTable events={data.items} selectedId={selectedId} onSelect={selectEvent} columns={preferences.discover_columns} compact={preferences.table_density === "COMPACT"} /><Pagination visible={data.items.length} total={data.page.total} hasPrevious={cursorStack.length > 0} hasNext={Boolean(data.page.next_cursor)} loading={loading} pageSize={pageSize} onPageSizeChange={(next) => { const size = next as 25 | 50 | 100; setPageSize(size); setCursor(undefined); setCursorStack([]); void persistPreferences({ discover_page_size: size }); }} onPrevious={() => { setCursor(cursorStack[cursorStack.length - 1]); setCursorStack((current) => current.slice(0, -1)); }} onNext={() => { if (data.page.next_cursor) { setCursorStack((current) => [...current, cursor]); setCursor(data.page.next_cursor); } }} /></>}
      </section>
      {selectedId && !detail && !detailError && <aside className="detail-panel detail-panel--state"><StatePanel kind="loading" title="Loading event" message="Reading redacted structured evidence…" /></aside>}
      {detailError && <aside className="detail-panel detail-panel--state"><StatePanel kind="error" title="Event unavailable" message={detailError} actionLabel="Close" onAction={closeEvent} /></aside>}
      {detail && <EventDetail event={detail} onClose={closeEvent} onOpenAlert={onOpenAlert} onOpenIncident={onOpenIncident} />}
    </div>
  );
}
