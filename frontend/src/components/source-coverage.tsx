import {useEffect,useState} from 'react';
import type {BackendApi} from '../types/api';
import type {SourceCoverageReport} from '../types/collection';
import {TimeValue} from './time-value';

export function SourceCoverage({api,onOpenEvent,compact=false}:{api:BackendApi;onOpenEvent?:(id:string)=>void;compact?:boolean}) {
  const [report,setReport]=useState<SourceCoverageReport|null>(null),[error,setError]=useState(''),[revision,setRevision]=useState(0);
  useEffect(()=>{
    const controller=new AbortController();setReport(null);setError('');
    void api.getSourceCoverage(controller.signal).then(value=>{if(!controller.signal.aborted)setReport(value);}).catch(reason=>{if(!controller.signal.aborted)setError(reason instanceof Error?reason.message:'Source coverage unavailable');});
    return()=>controller.abort();
  },[api,revision]);
  return <section className="panel" aria-label="Source coverage and collection evidence">
    <header className="panel__header"><div><span className="eyebrow">Collection evidence</span><h2>Source coverage</h2></div><button className="button button--ghost" type="button" onClick={()=>setRevision(value=>value+1)}>Refresh source coverage</button></header>
    {!report&&!error&&<p role="status">Loading bounded source coverage…</p>}
    {error&&<p role="alert">Source coverage unavailable: {error}</p>}
    {report&&<>
      <p>{report.scope==='SYNTHETIC_TEST'?'SYNTHETIC TEST':'Data origin: UNKNOWN'} · {report.sample_count} retained events sampled (limit {report.sample_limit}). {report.truncated?'PARTIAL SAMPLE — counts are not totals.':'Retained sample; no claim of historical completeness.'}</p>
      <p className="trust-note">Parser availability does not prove connectivity. Collector acknowledgement and queue backlog remain UNKNOWN when unobserved. Measured <TimeValue value={report.observed_at}/>; historical continuity UNPROVEN.</p>
      {!report.sample_count&&<p>No retained source observations. Available parsers are source capability only.</p>}
      <div className="table-frame"><table className="data-table"><caption>Normalized source evidence</caption><thead><tr><th scope="col">Family</th><th scope="col">Sample / normalized</th><th scope="col">Freshness</th><th scope="col">Connectivity</th><th scope="col">Evidence</th></tr></thead><tbody>{report.families.filter(item=>!compact||item.observed||['ZEEK','SURICATA'].includes(item.family)).map(item=><tr key={item.family}><td>{item.family}</td><td>{item.sample_event_count} / {item.sample_normalized_count}</td><td>{item.freshness}</td><td>UNKNOWN</td><td>{item.latest_event_id&&onOpenEvent?<button className="button button--ghost" type="button" onClick={()=>onOpenEvent(item.latest_event_id!)}>Open {item.family} event</button>:'Not observed'}</td></tr>)}</tbody></table></div>
      {!compact&&<>
        <h3>Registered isolated sources</h3>{!report.registered_sources.length&&<p>No registered collector. Network ingestion gate is closed.</p>}
        <ul className="compact-list">{report.registered_sources.map(source=><li key={source.source_id}><strong>{source.source_id}</strong> · {source.source_type} · {source.delivery_state} · connected UNKNOWN
          <span className="cell-subtle">Host {source.host}; collector {source.collector_id}; generation {source.source_generation}; sample {source.sample_event_count}. Process inserts {source.process_counters.inserted??0}, duplicates {source.process_counters.duplicate??0}, rejected {source.process_counters.rejected??0}, conflicts {source.process_counters.conflict??0}; counters reset at application restart.</span></li>)}</ul>
        <h3>Continuous shadow evaluation</h3>{!report.detection_workers.length&&<p>UNKNOWN — no isolated continuous worker is observed; production activation is unavailable.</p>}
        {report.detection_workers.map(worker=><p key={worker.rule_version}>{worker.rule_id}: {worker.state}; committed ticks {worker.ticks_committed}; late source observations {worker.late_observed}, outside overlap {worker.late_outside_overlap}; pending recovery {worker.pending_evaluation?'YES':'NO'}. {worker.reason??''} SHADOW ONLY; gaps UNPROVEN.</p>)}
        {report.detection_workers.filter(worker=>worker.progress).map(worker=><aside key={'progress:'+worker.rule_version} aria-label="Durable evaluation progress">
          <p>Evaluation stage: {worker.progress!.stage}; observed gap: {worker.progress!.observed_gap}. Pending run {worker.progress!.pending_run_id??'NONE'}; snapshot {worker.progress!.snapshot_state??'NOT_CREATED'}.</p>
          <p>Last history completion {worker.progress!.last_completed_evaluation??'UNKNOWN'}. Checkpoint commits: {worker.ticks_committed}. These are separate durable boundaries; collector delivery acknowledgement is UNKNOWN.</p>
        </aside>)}
      </>}
    </>}
  </section>;
}
