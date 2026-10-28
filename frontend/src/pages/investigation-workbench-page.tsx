import { useEffect, useMemo, useRef, useState } from "react";

import { CopyButton } from "../components/copy-button";
import { EventSourceContext } from "../components/event-source-context";
import { MitreTags } from "../components/mitre-tags";
import { SeverityBadge } from "../components/severity-badge";
import { StatePanel } from "../components/state-panel";
import { TimeValue } from "../components/time-value";
import type { BackendApi } from "../types/api";
import type { InvestigationEntity, InvestigationTimelineItem, InvestigationWorkbench, WorkbenchTarget } from "../types/investigation-workbench";
import { humanize } from "../utils/format";

interface Props {
  api: BackendApi;
  target: WorkbenchTarget | null;
  canMutate: boolean;
  onTargetChange(target: WorkbenchTarget): void;
  onOpenEvent(id: string): void;
  onOpenAlert(id: string): void;
  onOpenIncident(id: string): void;
  onOpenCase(id: string): void;
  onOpenRule(id: string): void;
  onReturn(): void;
}

const TIMELINE_FILTERS = ["ALL", "SECURITY_EVENT", "ALERT", "DETECTION_FINDING", "INCIDENT_ACTIVITY", "ANALYST_NOTE", "CASE_ACTIVITY", "CASE_COMMENT", "EVIDENCE_ACTION"] as const;

function relationship(value: string): string {
  return humanize(value.toLowerCase());
}

function openLink(item: InvestigationWorkbench["links"][number], props: Props): void {
  if (item.target_type === "ALERT") props.onOpenAlert(item.target_id);
  else if (item.target_type === "INCIDENT" || item.target_type === "CORRELATION_GROUP") props.onOpenIncident(item.target_id);
  else props.onOpenCase(item.target_id);
}

function DetectionExplanation({ context, onOpenEvent, onOpenRule }: {
  context: NonNullable<InvestigationWorkbench["detection_context"]>;
  onOpenEvent(id: string): void;
  onOpenRule(id: string): void;
}) {
  return <section className="panel investigation-section" aria-labelledby="detection-explanation-title">
    <div className="section-heading"><div><span className="eyebrow">Explainable detection</span><h2 id="detection-explanation-title">Why this finding matched</h2></div><SeverityBadge level={context.finding.severity} /></div>
    <p>{context.finding.explanation}</p>
    <dl className="metadata-grid">
      <div><dt>Rule</dt><dd><button className="link-button mono" type="button" onClick={() => onOpenRule(context.rule.rule_id)}>{context.rule.rule_id}</button> · {context.rule.name}</dd></div>
      <div><dt>Family</dt><dd>{context.rule.description}</dd></div>
      <div><dt>Activation</dt><dd><strong>{context.rule.activation_state}</strong></dd></div>
      <div><dt>Finding namespace</dt><dd>{humanize(context.source_kind)}</dd></div>
      <div><dt>Threshold</dt><dd>{context.finding.matched_event_count} matched / {context.finding.threshold} required</dd></div>
      <div><dt>Evaluation window</dt><dd>{context.rule.window_seconds} seconds</dd></div>
      <div><dt>Event-time order</dt><dd>{context.finding.first_event_at} → {context.finding.last_event_at}</dd></div>
      <div><dt>Deduplication key</dt><dd className="mono wrap-anywhere">{context.finding.deduplication_key}</dd></div>
      <div><dt>Evaluation budget</dt><dd>{context.evaluated_event_count} events · {context.execution_budget_ms} ms maximum</dd></div>
    </dl>
    <h3>Matched conditions</h3><ul>{context.rule.conditions.map((condition) => <li key={condition}>{condition}</li>)}</ul>
    <h3>Correlation keys</h3><dl className="metadata-grid">{Object.entries(context.finding.group).map(([key, value]) => <div key={key}><dt>{humanize(key)}</dt><dd className="mono">{value}</dd></div>)}</dl>
    <h3>Matched evidence</h3><div className="stack-list">{context.finding.evidence.map((evidence) => <article className="list-card" key={evidence.event_id}><div><strong>{evidence.summary}</strong><small><TimeValue value={evidence.timestamp} /> · {evidence.event_id}</small></div><button className="button button--secondary" type="button" onClick={() => onOpenEvent(evidence.event_id)}>Open evidence</button></article>)}</div>
    <h3>ATT&amp;CK context</h3><MitreTags mitre={{ ids: context.finding.mitre_ids, tactics: context.rule.mitre_mappings.map((item) => item.tactic), techniques: context.rule.mitre_mappings.map((item) => item.technique_name) }} detailed />
    {context.rule.mitre_mappings.map((mapping) => <p className="trust-note" key={mapping.technique_id}><strong>{mapping.technique_id}</strong>: {mapping.relationship}</p>)}
    <h3>Prerequisite and limitations</h3><p>{context.rule.availability?.explanation ?? context.rule.prerequisites.configuration_evidence}</p>
    {context.rule.availability?.missing_required_fields.length ? <p className="stale-warning">Missing fields: {context.rule.availability.missing_required_fields.join(", ")}</p> : null}
    <p className="trust-note">This is a deterministic {context.source_kind === "SHADOW" ? "shadow" : "dry-run"} projection. It created no live alert, incident, case, notification, or rule activation.</p>
  </section>;
}

function TimelineCard({ item, expanded, onToggle, onOpenEvent, onOpenAlert, onOpenIncident, onOpenCase }: {
  item: InvestigationTimelineItem; expanded: boolean; onToggle(): void;
  onOpenEvent(id: string): void; onOpenAlert(id: string): void; onOpenIncident(id: string): void; onOpenCase(id: string): void;
}) {
  const open = () => {
    if (item.item_type === "SECURITY_EVENT") onOpenEvent(item.source_id);
    else if (item.item_type === "ALERT") onOpenAlert(item.source_id);
    else if (item.item_type === "INCIDENT_ACTIVITY" || item.item_type === "ANALYST_NOTE") onOpenIncident(item.source_id);
    else if (["CASE_ACTIVITY", "CASE_COMMENT", "EVIDENCE_ACTION"].includes(item.item_type)) onOpenCase(item.source_id);
  };
  const navigable = item.item_type !== "DETECTION_FINDING";
  return <article className="timeline-card" data-type={item.item_type}>
    <button className="timeline-card__toggle" type="button" aria-expanded={expanded} onClick={onToggle}>
      <span className="source-pill">{humanize(item.item_type.toLowerCase())}</span><strong>{item.title}</strong><TimeValue value={item.timestamp} />
    </button>
    {expanded && <div className="timeline-card__body">
      <p className="muted-copy">{humanize(item.timestamp_kind.toLowerCase())}{item.timestamp_status === "FUTURE" ? " · future timestamp" : ""}{item.actor_display ? ` · ${item.actor_display}` : ""}</p>
      <div className="filter-chip-row">{item.relationship_types.map((type) => <span className="filter-chip" key={type}>{relationship(type)}</span>)}</div>
      {Object.keys(item.details).length > 0 && <pre className="compact-json">{JSON.stringify(item.details, null, 2)}</pre>}
      {navigable && <button className="button button--secondary" type="button" onClick={open}>Open source evidence</button>}
    </div>}
  </article>;
}

export function InvestigationWorkbenchPage(props: Props) {
  const { api, target } = props;
  const [data, setData] = useState<InvestigationWorkbench | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [revision, setRevision] = useState(0);
  const [timelineFilter, setTimelineFilter] = useState<(typeof TIMELINE_FILTERS)[number]>("ALL");
  const [sort, setSort] = useState<"oldest" | "newest">(target?.sort ?? "oldest");
  const [severityMin, setSeverityMin] = useState(0);
  const [timelineStart, setTimelineStart] = useState("");
  const [timelineEnd, setTimelineEnd] = useState("");
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [actionStatus, setActionStatus] = useState<string | null>(null);
  const [noteBody, setNoteBody] = useState("");
  const [caseId, setCaseId] = useState("");
  const heading = useRef<HTMLHeadingElement>(null);

  useEffect(() => {
    if (!target) { setData(null); setError(null); return; }
    const controller = new AbortController();
    let active = true;
    setLoading(true); setError(null); setData(null);
    api.getInvestigationWorkbench({ ...target, sort }, controller.signal)
      .then((response) => { if (active) { setData(response); window.setTimeout(() => heading.current?.focus(), 0); } })
      .catch((reason: unknown) => { if (active && !(reason instanceof DOMException && reason.name === "AbortError")) setError(reason instanceof Error ? reason.message : "Investigation could not be loaded."); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; controller.abort(); };
  }, [api, target, sort, revision]);

  const visibleTimeline = useMemo(() => {
    const start = timelineStart ? new Date(timelineStart).getTime() : null;
    const end = timelineEnd ? new Date(timelineEnd).getTime() : null;
    return (data?.timeline ?? []).filter((item) => {
      const timestamp = new Date(item.timestamp).getTime();
      return (timelineFilter === "ALL" || item.item_type === timelineFilter)
        && (severityMin === 0 || (item.severity ?? -1) >= severityMin)
        && (start === null || timestamp >= start)
        && (end === null || timestamp <= end);
    });
  }, [data, severityMin, timelineEnd, timelineFilter, timelineStart]);

  const pivot = (entity: InvestigationEntity) => {
    if (!entity.pivot_supported) return;
    props.onTargetChange({ target_type: "ENTITY", entity_type: entity.entity_type, entity_value: entity.value, relative_minutes: 10080, related_limit: 50, timeline_limit: 150, sort });
  };

  const pinToIncident = async (incidentId: string) => {
    if (!data) return;
    setActionStatus("Pinning evidence…");
    try {
      await api.pinEvidence(incidentId, { evidence_type: "EVENT", evidence_id: data.primary_event.event_id, annotation: "Pinned from M12 Investigation Workbench" });
      setActionStatus(`Evidence pinned to ${incidentId}.`);
    } catch (reason) { setActionStatus(reason instanceof Error ? reason.message : "Evidence could not be pinned."); }
  };

  const addIncidentNote = async (incidentId: string) => {
    const body = noteBody.trim();
    if (!body) { setActionStatus("Enter a note before saving."); return; }
    setActionStatus("Saving incident note…");
    try {
      await api.addIncidentNote(incidentId, { body });
      setNoteBody("");
      setActionStatus(`Note added to ${incidentId}.`);
      setRevision((value) => value + 1);
    } catch (reason) { setActionStatus(reason instanceof Error ? reason.message : "The note could not be saved."); }
  };

  const associateWithCase = async () => {
    if (!data) return;
    const requestedCase = caseId.trim();
    if (!requestedCase) { setActionStatus("Enter an existing case ID."); return; }
    setActionStatus(`Checking ${requestedCase}…`);
    try {
      const existing = await api.getCase(requestedCase);
      if (existing.event_ids.includes(data.primary_event.event_id)) {
        setActionStatus(`${data.primary_event.event_id} is already linked to ${requestedCase}.`);
        return;
      }
      await api.linkCaseReference(requestedCase, "event", data.primary_event.event_id, existing.version);
      setCaseId("");
      setActionStatus(`Evidence associated with ${requestedCase}.`);
      setRevision((value) => value + 1);
    } catch (reason) { setActionStatus(reason instanceof Error ? reason.message : "Evidence could not be associated with the case."); }
  };

  const openNextRelatedPage = () => {
    if (!target || !data?.query.related_next_cursor) return;
    props.onTargetChange({
      ...target,
      start_time: data.query.start_time,
      end_time: data.query.end_time,
      relative_minutes: null,
      related_cursor: data.query.related_next_cursor,
    });
  };

  if (!target) return <StatePanel kind="empty" title="No investigation target" message="Open an event or an M11 dry-run finding to begin a bounded investigation." />;
  if (loading) return <section className="panel investigation-skeleton" role="status" aria-live="polite"><span className="eyebrow">Investigation Workbench</span><h1>Building bounded context…</h1><p>Loading related evidence, links, timeline and entity context.</p></section>;
  if (error) return <StatePanel kind="error" title="Investigation unavailable" message={error} actionLabel="Retry" onAction={() => setRevision((value) => value + 1)} />;
  if (!data) return null;
  const incidentLinks = data.links.filter((item) => item.target_type === "INCIDENT");
  return <div className="investigation-workbench">
    {data.durable_shadow_context && <section className="panel investigation-section" aria-label="Durable shadow evidence">
      <h2>Durable finding revision {data.durable_shadow_context.revision}</h2>
      <p>{data.durable_shadow_context.finding_id} · rule SHA {data.durable_shadow_context.rule_version}</p>
      <p>{data.durable_shadow_context.matching_evidence.explanation}</p>
      <p>Historical continuity UNPROVEN. Identity assessed at evaluation time. Rule tags are not confirmed compromise.</p>
      <p>MITRE: {data.durable_shadow_context.matching_evidence.mitre.map(item=>item.technique_id).join(', ')}</p>
      <ul>{data.durable_shadow_context.matching_evidence.evidence.map(item=><li key={item.event_id}><button type="button" onClick={()=>props.onOpenEvent(item.event_id)}>Open finding evidence {item.event_id}</button> · <TimeValue value={item.event_time}/></li>)}</ul>
      <p>Availability was checked at request time across separate databases; this is not a shared atomic snapshot.</p>
    </section>}
    <header className="page-header investigation-header">
      <div><span className="eyebrow">Analyst Investigation Workbench</span><h1 ref={heading} tabIndex={-1}>{data.target_label}</h1><p>Evidence-backed context only. Observations and analyst interpretations are labelled separately.</p></div>
      <div className="page-actions"><button className="button button--secondary" type="button" onClick={props.onReturn}>← Return to results</button><button className="button button--ghost" type="button" onClick={() => setRevision((value) => value + 1)}>Refresh</button></div>
    </header>
    <div className="filter-chip-row"><span className="filter-chip">Schema {data.query.schema_version}</span><span className="filter-chip">{data.query.execution_ms.toFixed(1)} ms</span><span className="filter-chip">{data.related_events.length} related events</span>{data.query.related_truncated && <span className="filter-chip filter-chip--warning">Results bounded</span>}</div>
    <section className="panel investigation-section" aria-labelledby="summary-title"><div className="section-heading"><div><span className="eyebrow">Deterministic summary</span><h2 id="summary-title">Investigation summary</h2></div>{data.primary_event.severity != null && <SeverityBadge level={data.primary_event.severity} />}</div>
      <h3>Observed facts</h3><ul>{data.summary.observations.map((item) => <li key={item}>{item}</li>)}</ul>
      <h3>Interpretation boundary</h3><ul>{data.summary.interpretations.map((item) => <li key={item}>{item}</li>)}</ul>
      {data.summary.missing_fields.length > 0 && <p className="stale-warning"><strong>Unavailable fields:</strong> {data.summary.missing_fields.join(", ")}</p>}
    </section>
    {data.detection_context && <DetectionExplanation context={data.detection_context} onOpenEvent={props.onOpenEvent} onOpenRule={props.onOpenRule} />}
    <div className="investigation-grid">
      <section className="panel investigation-section" aria-labelledby="evidence-title"><div className="section-heading"><div><span className="eyebrow">Primary evidence</span><h2 id="evidence-title">{data.primary_event.message}</h2></div><TimeValue value={data.primary_event.timestamp} /></div>
        <dl className="metadata-grid"><div><dt>Event ID</dt><dd className="mono wrap-anywhere">{data.primary_event.event_id}</dd></div><div><dt>Ingested</dt><dd><TimeValue value={data.primary_event.ingested_at} /></dd></div><div><dt>Host</dt><dd>{data.primary_event.hostname ?? "Unavailable"}</dd></div><div><dt>Account</dt><dd>{data.primary_event.username ?? "Unavailable"}</dd></div><div><dt>Rule</dt><dd>{data.primary_event.rule_id ?? "Unavailable"}</dd></div><div><dt>Source</dt><dd className="mono">{data.primary_event.source_ip ?? "Unavailable"}</dd></div></dl>
        <div className="copy-actions"><CopyButton value={data.primary_event.event_id} label="Copy event ID" />{data.primary_event.rule_id && <CopyButton value={data.primary_event.rule_id} label="Copy rule ID" />}<CopyButton value={JSON.stringify(data.primary_event.raw_payload, null, 2)} label="Copy redacted JSON" /><button className="button button--secondary" type="button" onClick={() => props.onOpenEvent(data.primary_event.event_id)}>Open event detail</button></div>
        {props.canMutate && incidentLinks.map((link) => <button className="button button--secondary" key={link.target_id} type="button" onClick={() => void pinToIncident(link.target_id)}>Pin to {link.target_id}</button>)}
        <EventSourceContext event={data.primary_event} />
        <details className="json-evidence"><summary>Normalized fields</summary><pre>{JSON.stringify(data.primary_event.structured_payload, null, 2)}</pre></details>
        <details className="json-evidence"><summary>Redacted raw evidence</summary><pre>{JSON.stringify(data.primary_event.raw_payload, null, 2)}</pre></details>
      </section>
      <section className="panel investigation-section" aria-labelledby="entities-title"><div className="section-heading"><div><span className="eyebrow">Entity context</span><h2 id="entities-title">Evidence-backed pivots</h2></div></div>
        <div className="entity-list">{data.entities.map((entity) => <button className="entity-pivot" disabled={!entity.pivot_supported} type="button" key={`${entity.entity_type}:${entity.value}`} onClick={() => pivot(entity)}><span>{entity.label}</span><strong className="mono wrap-anywhere">{entity.value}</strong><small>{entity.pivot_supported ? "Investigate related activity" : "Index unavailable"}{entity.sensitive ? " · kept out of URL" : ""}</small></button>)}</div>
        {data.query.unavailable_relationships.length > 0 && <p className="muted-copy">Unavailable relationships: {data.query.unavailable_relationships.map(relationship).join(", ")}.</p>}
      </section>
    </div>
    <section className="panel investigation-section" aria-labelledby="links-title"><div className="section-heading"><div><span className="eyebrow">Authoritative links</span><h2 id="links-title">Alerts, incidents and cases</h2></div></div>
      {data.links.length === 0 ? <p className="empty-copy">No persisted alert, incident, case, or correlation link exists for this evidence.</p> : <div className="stack-list">{data.links.map((link) => <article className="list-card" key={`${link.target_type}:${link.target_id}`}><div><span className="source-pill">{humanize(link.target_type.toLowerCase())}</span><strong>{link.title}</strong><small>{link.target_id}{link.status ? ` · ${link.status}` : ""}</small></div><div className="copy-actions"><CopyButton value={link.target_id} label={`Copy ${humanize(link.target_type.toLowerCase())} ID`} /><button className="button button--secondary" type="button" onClick={() => openLink(link, props)}>Open</button></div></article>)}</div>}
    </section>
    {props.canMutate && <section className="panel investigation-section" aria-labelledby="analyst-actions-title"><span className="eyebrow">Audited existing workflows</span><h2 id="analyst-actions-title">Analyst actions</h2>
      <p className="muted-copy">These actions reuse the incident and case APIs. They never create an incident, case, or alert implicitly.</p>
      {incidentLinks.length > 0 && <div className="investigation-action-form"><label>Incident note<textarea maxLength={4096} value={noteBody} onChange={(event) => setNoteBody(event.target.value)} placeholder={`Add a note to ${incidentLinks[0].target_id}`} /></label><button className="button button--secondary" disabled={!noteBody.trim()} type="button" onClick={() => void addIncidentNote(incidentLinks[0].target_id)}>Add note to {incidentLinks[0].target_id}</button></div>}
      <div className="investigation-action-form"><label>Existing case ID<input maxLength={128} value={caseId} onChange={(event) => setCaseId(event.target.value)} placeholder="CASE-…" /></label><button className="button button--secondary" disabled={!caseId.trim()} type="button" onClick={() => void associateWithCase()}>Associate event with case</button></div>
      {actionStatus && <p role="status">{actionStatus}</p>}
    </section>}
    <section className="panel investigation-section" aria-labelledby="related-title"><div className="section-heading"><div><span className="eyebrow">Related event explorer</span><h2 id="related-title">Shared indexed evidence</h2></div></div>
      {data.related_events.length === 0 ? <p className="empty-copy">No event shares a supported indexed entity in the bounded range. Time proximity alone is not treated as a relationship.</p> : <div className="stack-list">{data.related_events.map(({ event, relationship_types }) => <article className="list-card" key={event.event_id}><div><strong>{event.message}</strong><small><TimeValue value={event.timestamp} /> · {event.event_id}</small><div className="filter-chip-row">{relationship_types.map((type) => <span className="filter-chip" key={type}>{relationship(type)}</span>)}</div></div><div className="page-actions"><button className="button button--ghost" type="button" onClick={() => props.onOpenEvent(event.event_id)}>Open in Discover</button><button className="button button--secondary" type="button" onClick={() => props.onTargetChange({ target_type: "EVENT", target_id: event.event_id, relative_minutes: 10080, related_limit: 50, timeline_limit: 150, sort })}>Investigate</button></div></article>)}</div>}
      {(target.related_cursor || data.query.related_next_cursor) && <nav className="pagination-controls" aria-label="Related event pages"><button className="button button--ghost" type="button" disabled={!target.related_cursor} onClick={() => window.history.back()}>Previous related page</button><button className="button button--secondary" type="button" disabled={!data.query.related_next_cursor} onClick={openNextRelatedPage}>Next related page</button></nav>}
    </section>
    <section className="panel investigation-section" aria-labelledby="timeline-title"><div className="section-heading"><div><span className="eyebrow">Unified timeline</span><h2 id="timeline-title">Evidence and analyst activity</h2></div><div className="page-actions"><button className="button button--ghost" type="button" onClick={() => setExpanded(new Set(visibleTimeline.map((item) => item.item_id)))}>Expand all</button><button className="button button--ghost" type="button" onClick={() => setExpanded(new Set())}>Collapse all</button></div></div>
      <div className="toolbar"><label>Type<select value={timelineFilter} onChange={(event) => setTimelineFilter(event.target.value as typeof timelineFilter)}>{TIMELINE_FILTERS.map((item) => <option value={item} key={item}>{humanize(item.toLowerCase())}</option>)}</select></label><label>Minimum severity<select value={severityMin} onChange={(event) => setSeverityMin(Number(event.target.value))}><option value={0}>Any</option><option value={7}>7+</option><option value={10}>10+</option><option value={13}>13+</option></select></label><label>From<input type="datetime-local" value={timelineStart} onChange={(event) => setTimelineStart(event.target.value)} /></label><label>Until<input type="datetime-local" value={timelineEnd} onChange={(event) => setTimelineEnd(event.target.value)} /></label><label>Order<select value={sort} onChange={(event) => setSort(event.target.value as "oldest" | "newest")}><option value="oldest">Chronological</option><option value="newest">Reverse chronological</option></select></label>{(timelineStart || timelineEnd) && <button className="button button--ghost" type="button" onClick={() => { setTimelineStart(""); setTimelineEnd(""); }}>Clear time filter</button>}</div>
      {visibleTimeline.length === 0 ? <p className="empty-copy">No timeline items match these filters.</p> : <div className="investigation-timeline">{visibleTimeline.map((item) => <TimelineCard key={item.item_id} item={item} expanded={expanded.has(item.item_id)} onToggle={() => setExpanded((current) => { const next = new Set(current); if (next.has(item.item_id)) next.delete(item.item_id); else next.add(item.item_id); return next; })} onOpenEvent={props.onOpenEvent} onOpenAlert={props.onOpenAlert} onOpenIncident={props.onOpenIncident} onOpenCase={props.onOpenCase} />)}</div>}
    </section>
    {data.correlation_groups.map((group) => <section className="panel investigation-section" aria-labelledby={`correlation-${group.group_id}`} key={group.group_id}><span className="eyebrow">Correlation group</span><h2 id={`correlation-${group.group_id}`}>{group.correlation_rule} · {group.classification}</h2><p>{group.explanation}</p><dl className="metadata-grid"><div><dt>Group ID</dt><dd className="mono wrap-anywhere">{group.group_id}</dd></div><div><dt>Confidence</dt><dd>{group.confidence}</dd></div><div><dt>Window</dt><dd><TimeValue value={group.first_seen} /> → <TimeValue value={group.last_seen} /></dd></div><div><dt>Evidence</dt><dd>{group.evidence_count} alerts</dd></div>{Object.entries(group.grouping_keys).map(([key, value]) => <div key={key}><dt>{humanize(key)}</dt><dd className="mono">{value}</dd></div>)}</dl><button className="button button--secondary" type="button" onClick={() => props.onOpenIncident(group.incident_id)}>Open linked incident</button></section>)}
    <section className="panel investigation-section" aria-labelledby="ioc-title"><span className="eyebrow">Local threat intelligence</span><h2 id="ioc-title">IOC context</h2>{data.ioc_matches.length === 0 ? <p className="empty-copy">No active local IOC exactly matches the extracted IP, domain, or hash evidence.</p> : <div className="stack-list">{data.ioc_matches.map((match) => <article className="list-card" key={match.indicator_id}><div><strong>{match.indicator_type} · <span className="mono">{match.value}</span></strong><small>{match.source} · confidence {match.confidence}% · {match.evidence_field}</small><p className="trust-note">An IOC match is context, not proof of compromise.</p></div></article>)}</div>}</section>
  </div>;
}
