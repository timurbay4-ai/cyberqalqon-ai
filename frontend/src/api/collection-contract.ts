import {ContractError} from './contracts';
import type {SourceCoverageReport,SourceFamilyCoverage,RegisteredSourceCoverage,ContinuousWorkerObservation} from '../types/collection';

const fail=():never=>{throw new ContractError('collection');};
const obj=(v:unknown):Record<string,unknown>=>!v||typeof v!=='object'||Array.isArray(v)?fail():v as Record<string,unknown>;
const text=(v:unknown,max=255):string=>typeof v!=='string'||!v||v.length>max?fail():v;
const number=(v:unknown,max=Number.MAX_SAFE_INTEGER):number=>typeof v!=='number'||!Number.isSafeInteger(v)||v<0||v>max?fail():v;
const date=(v:unknown):string|null=>v===null?null:typeof v==='string'&&v.length<=40&&/(Z|[+-]\d{2}:\d{2})$/.test(v)&&Number.isFinite(Date.parse(v))?v:fail();
const flag=(v:unknown):boolean=>typeof v==='boolean'?v:fail();
const choice=<T extends string>(v:unknown,values:readonly T[]):T=>typeof v==='string'&&values.includes(v as T)?v as T:fail();
const event=(v:unknown):string|null=>v===null?null:typeof v==='string'&&/^EVT-[A-F0-9]{24}$/.test(v)?v:fail();
const list=(v:unknown,max:number):unknown[]=>Array.isArray(v)&&v.length<=max?v:fail();

export function parseSourceCoverage(value:unknown):SourceCoverageReport {
  const row=obj(value);
  if(row.contract!=='cq-source-coverage-v1'||row.production_active!==false||row.historical_continuity!=='UNPROVEN'||row.sample_limit!==1000)return fail();
  const sample=number(row.sample_count,1000),truncated=flag(row.truncated);
  const families=list(row.families,8).map(value=>{
    const item=obj(value),count=number(item.sample_event_count,1000),normalized=number(item.sample_normalized_count,count);
    const observed=flag(item.observed),latest=event(item.latest_event_id),last=date(item.last_event_time),ingested=date(item.last_ingestion_time);
    if(observed!==(count>0)||(count>0)!==(latest!==null)||(count>0)!==(last!==null)||(count>0)!==(ingested!==null)||item.connected!=='UNKNOWN'||item.detection_eligible!=='UNKNOWN'||item.queue_backlog!==null)return fail();
    const freshness=choice(item.freshness,['UNKNOWN','OBSERVED','STALE'] as const);
    if(!observed&&freshness!=='UNKNOWN')return fail();
    return {family:choice(item.family,['WINDOWS_EVENTCHANNEL','SYSMON','LINUX_AUTH','SYSLOG','JOURNALD','WAZUH_GENERIC','ZEEK','SURICATA'] as const),parser_available:flag(item.parser_available),observed,
      sample_event_count:count,sample_normalized_count:normalized,last_event_time:last,last_ingestion_time:ingested,latest_event_id:latest,freshness,search_fields_available:flag(item.search_fields_available),connected:'UNKNOWN',detection_eligible:'UNKNOWN',queue_backlog:null} satisfies SourceFamilyCoverage;
  });
  if(new Set(families.map(item=>item.family)).size!==families.length||families.reduce((sum,item)=>sum+item.sample_event_count,0)>sample)return fail();
  const registered=list(row.registered_sources,32).map(value=>{
    const item=obj(value),counters=obj(item.process_counters),safeCounters:Record<string,number>={};
    if(item.configured!==true||item.connected!=='UNKNOWN'||item.last_acknowledged_delivery!==null||item.queue_backlog!==null||item.retry_count!==null||item.dead_letter_count!==null||item.counter_scope!=='SINCE_APPLICATION_START'||item.configuration_authority!=='EXPLICIT_DISPOSABLE_CONSTRUCTOR'||Object.keys(counters).length>8)return fail();
    for(const [key,count] of Object.entries(counters)){
      if(!['inserted','duplicate','rejected','conflict','retryable_failure'].includes(key))return fail();
      safeCounters[key]=number(count);
    }
    return {source_id:text(item.source_id,128),source_type:choice(item.source_type,['ZEEK_JSON','SURICATA_EVE'] as const),host:text(item.host),collector_id:text(item.collector_id,128),source_generation:text(item.source_generation,128),configured:true,connected:'UNKNOWN',
      delivery_state:choice(item.delivery_state,['UNKNOWN','OBSERVED_COMMIT'] as const),last_committed_delivery_at:date(item.last_committed_delivery_at),last_acknowledged_delivery:null,queue_backlog:null,retry_count:null,dead_letter_count:null,
      sample_event_count:number(item.sample_event_count,1000),last_event_time:date(item.last_event_time),last_ingestion_time:date(item.last_ingestion_time),process_counters:safeCounters,counter_scope:'SINCE_APPLICATION_START',configuration_authority:'EXPLICIT_DISPOSABLE_CONSTRUCTOR',family:choice(item.family,['ZEEK','SURICATA'] as const)} satisfies RegisteredSourceCoverage;
  });
  if(new Set(registered.map(item=>item.source_id)).size!==registered.length)return fail();
  const workers=list(row.detection_workers,8).map(value=>{
    const item=obj(value);
    if(item.contract!=='cq-continuous-shadow-v1'||item.production_active!==false||item.historical_continuity!=='UNPROVEN'||item.gap_status!=='UNPROVEN'||item.source_checkpoint_reused!==false||item.cross_database_atomicity!==false||item.scope!=='DISPOSABLE_SHADOW_ONLY')return fail();
    const ids=list(item.last_finding_ids,100).map(value=>typeof value==='string'&&/^DSF-[a-f0-9]{64}$/.test(value)?value:fail());
    const hash=text(item.rule_version,64);if(!/^[a-f0-9]{64}$/.test(hash))return fail();
    let progress:ContinuousWorkerObservation['progress'];
    if(item.progress!==undefined){
      const p=obj(item.progress),runId=(value:unknown):string|null=>value===null?null:typeof value==='string'&&/^RUN-[a-f0-9]{32}$/.test(value)?value:fail();
      if(p.contract!=='cq-shadow-progress-v1'||p.window_completeness!=='UNPROVEN'||p.audit_scope!=='M35_ONLY_LEGACY_NOT_BACKFILLED')return fail();
      const stage=choice(p.stage,['CREATED','PENDING','RECOVERY_REQUIRED','FINDINGS_COMMITTED','CHECKPOINT_COMMITTED','BLOCKED'] as const);
      const pending=flag(item.pending_evaluation),pendingId=runId(p.pending_run_id),completed=runId(p.last_completed_evaluation);
      const runStatus=p.run_status===null?null:choice(p.run_status,['RUNNING','FAILED','CANCELLED','COMPLETED'] as const);
      const snapshot=p.snapshot_state===null?null:choice(p.snapshot_state,['SEALED','UNSEALED'] as const);
      if((pendingId===null)!==(runStatus===null)||(pendingId===null)!==(snapshot===null))return fail();
      if(stage==='CHECKPOINT_COMMITTED'&&(pending||!item.ticks_committed||!completed)||stage==='FINDINGS_COMMITTED'&&(!pending||runStatus!=='COMPLETED'||snapshot!=='SEALED'||pendingId!==completed)||stage==='RECOVERY_REQUIRED'&&(!pending||!pendingId||runStatus==='COMPLETED')||stage==='CREATED'&&(pending||item.ticks_committed!==0))return fail();
      const tail=list(p.transition_tail,32).map(value=>{const row=obj(value),tick=number(row.tick,2048);if(!tick)return fail();return {tick,stage:choice(row.stage,['PENDING_COMMITTED','CHECKPOINT_COMMITTED'] as const),run_id:runId(row.run_id)};});
      const count=number(p.transition_count,4096);if(count<tail.length)return fail();
      progress={contract:'cq-shadow-progress-v1',stage,observed_gap:choice(p.observed_gap,['UNPROVEN','PARTIAL','SOURCE_GAP','RETENTION_GAP'] as const),pending_run_id:pendingId,run_status:runStatus,snapshot_state:snapshot,unsealed_intent_present:flag(p.unsealed_intent_present),last_completed_evaluation:completed,transition_count:count,audit_scope:'M35_ONLY_LEGACY_NOT_BACKFILLED',transition_tail:tail,window_completeness:'UNPROVEN'};
    }
    return {rule_id:text(item.rule_id,64),rule_version:hash,state:choice(item.state,['OWNED','STOPPED','COMMITTED','NOT_DUE','PENDING_RECOVERY','DEGRADED'] as const),reason:item.reason===null?null:text(item.reason,128),ticks_committed:number(item.ticks_committed,2048),
      pending_evaluation:flag(item.pending_evaluation),late_observed:number(item.late_observed),late_outside_overlap:number(item.late_outside_overlap),last_finding_ids:ids,historical_continuity:'UNPROVEN',production_active:false,...(progress?{progress}:{})} satisfies ContinuousWorkerObservation;
  });
  const workerState=choice(row.continuous_worker_state,['OBSERVED_ISOLATED_WORKERS','UNKNOWN_NOT_ACTIVATED'] as const);
  if((workers.length>0)!==(workerState==='OBSERVED_ISOLATED_WORKERS'))return fail();
  const coverage=choice(row.coverage,['PARTIAL_SAMPLE','RETAINED_SAMPLE'] as const);
  if(truncated!==(coverage==='PARTIAL_SAMPLE'))return fail();
  return {contract:'cq-source-coverage-v1',observed_at:date(row.observed_at)??fail(),scope:choice(row.scope,['SYNTHETIC_TEST','UNKNOWN'] as const),coverage,sample_limit:1000,sample_count:sample,truncated,historical_continuity:'UNPROVEN',production_active:false,families,registered_sources:registered,detection_workers:workers,continuous_worker_state:workerState};
}
