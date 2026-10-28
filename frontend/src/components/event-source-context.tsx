import type { SecurityEventDetail } from "../types/events";
import { humanize } from "../utils/format";
import { TimeValue } from "./time-value";

export function EventSourceContext({ event, onPivotQuery }: { event: SecurityEventDetail; onPivotQuery?:(query:string)=>void }) {
  const cuse = event.cuse;
  const pivots = [
    ["dns.question.name", cuse?.attributes.dns_question_name],
    ["tls.server.name", cuse?.attributes.tls_server_name],
    ["http.host", cuse?.attributes.http_host],
    ["network.connection.uid", cuse?.attributes.connection_uid],
    ["source.ip", event.source_ip], ["destination.ip", event.destination_ip],
  ].filter((item):item is [string,string]=>typeof item[0]==="string"&&typeof item[1]==="string"&&item[1].length>0&&item[1].length<=1024);
  return <section className="detail-section" aria-label="Source context">
    <h3>Source context</h3>
    <dl className="metadata-grid">
      <div><dt>Source family</dt><dd>{cuse ? humanize(cuse.source_family.toLowerCase()) : "UNKNOWN"}</dd></div>
      <div><dt>Normalization status</dt><dd>{cuse?.normalization_status ?? "UNKNOWN"}</dd></div>
      <div><dt>Provenance</dt><dd>{cuse?.provenance_status ?? "UNKNOWN"}</dd></div>
      <div><dt>Endpoint identity</dt><dd>Not independently verified</dd></div>
      <div><dt>Provider</dt><dd>{event.event_provider ?? "UNKNOWN"}</dd></div>
      <div><dt>Source channel</dt><dd>{event.event_channel ?? "UNKNOWN"}</dd></div>
      <div><dt>Source event time</dt><dd>{cuse?.source_event_time ? <TimeValue value={cuse.source_event_time} /> : "UNKNOWN"}</dd></div>
      <div><dt>Collector observation</dt><dd>{cuse ? <TimeValue value={cuse.collector_observation_time} /> : "UNKNOWN"}</dd></div>
      {cuse?.source_generation&&<div><dt>Registered generation</dt><dd>{cuse.source_generation}</dd></div>}
      {cuse?.delivery_identity&&<div><dt>Collector delivery ID</dt><dd>{cuse.delivery_identity}</dd></div>}
      {cuse?.idempotency_contract==="REGISTERED_SOURCE_RECORD_SHA256"&&<div><dt>Original source record ID</dt><dd>{cuse.original_event_identity}</dd></div>}
    </dl>
    {cuse && Object.keys(cuse.attributes).length > 0 && <details><summary>Source-specific fields</summary><dl className="metadata-grid">{Object.entries(cuse.attributes).map(([key, value]) => <div key={key}><dt>{humanize(key)}</dt><dd className="mono wrap-anywhere">{value}</dd></div>)}</dl></details>}
    {onPivotQuery&&pivots.length>0&&<div className="copy-actions" aria-label="Normalized event pivots">{pivots.map(([field,value])=><button className="button button--ghost" type="button" key={field} onClick={()=>onPivotQuery(`${field} = ${JSON.stringify(value)}`)}>Search {field}</button>)}</div>}
  </section>;
}
