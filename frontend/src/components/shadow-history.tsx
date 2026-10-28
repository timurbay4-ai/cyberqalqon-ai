import {useEffect,useRef,useState} from 'react';
import type {BackendApi} from '../types/api';
import type {DurableStatus,DurableRun,FindingPage,FindingDetail,FindingTransition,DurableRequest} from '../types/shadow-history';
import type {ShadowCatalog} from '../types/shadow-detection';
import {TimeValue} from './time-value';
import {ApiError} from '../api/client';
import type {ReconciliationPage} from '../types/evidence-consistency';
import type {SigmaPreview} from '../api/sigma-contract';

export function ShadowHistory({api,canMutate,onOpenEvent,onInvestigate,importedRules=[]}:{api:BackendApi;canMutate:boolean;onOpenEvent:(id:string)=>void;onInvestigate?:(target:import('../types/investigation-workbench').WorkbenchTarget)=>void;importedRules?:SigmaPreview['rules']}){
    const [status,setStatus]=useState<DurableStatus|null>(null),[catalog,setCatalog]=useState<ShadowCatalog|null>(null);
    const [page,setPage]=useState<FindingPage|null>(null),[detail,setDetail]=useState<FindingDetail|null>(null),[run,setRun]=useState<DurableRun|null>(null);
    const [rule,setRule]=useState(''),[minimum,setMinimum]=useState<DurableRequest['identity_policy']['minimum']>('PARTIAL');
    const [start,setStart]=useState(()=>new Date(Date.now()-3600000).toISOString()),[end,setEnd]=useState(()=>new Date().toISOString());
    const [busy,setBusy]=useState(false),[error,setError]=useState('');
    const [reconciliation,setReconciliation]=useState<ReconciliationPage|null>(null);
    const operation=useRef<AbortController|null>(null);
    function invalidate(){operation.current?.abort();operation.current=null;setBusy(false);setError('');setRun(null);}
    useEffect(()=>{
        const controller=new AbortController();
        void api.getDurableShadowStatus(controller.signal).then(async value=>{
            if(controller.signal.aborted)return;setStatus(value);
            if(value.enabled){const [rows,rules]=await Promise.all([api.listDurableShadowFindings(null,controller.signal),api.getShadowCatalog(controller.signal)]);
                if(!controller.signal.aborted){setPage(rows);setCatalog(rules);setRule(importedRules.length?'import:'+importedRules[importedRules.length-1].rule_version:rules.rules[0]?.definition.rule_id||'');}}
        }).catch(reason=>{if(!controller.signal.aborted)setError(reason instanceof Error?reason.message:'History unavailable');});
        return()=>{controller.abort();operation.current?.abort();};
    },[api]);
    const importedVersion=importedRules[importedRules.length-1]?.rule_version;
    useEffect(()=>{if(importedVersion){invalidate();setRule('import:'+importedVersion);}},[importedVersion]);
    const choices=[...(catalog?.rules||[]).map(value=>({...value,key:value.definition.rule_id})),...importedRules.map(value=>({...value,key:'import:'+value.rule_version}))];
    async function perform(action:(signal:AbortSignal)=>Promise<void>){
        const controller=new AbortController();operation.current?.abort();operation.current=controller;setBusy(true);setError('');
        try{await action(controller.signal);}catch(reason){if(!controller.signal.aborted){
            setError(reason instanceof Error?reason.message:'Durable shadow operation failed');
            if(reason instanceof ApiError&&reason.runId){try{const value=await api.getDurableShadowRun(reason.runId,controller.signal);if(!controller.signal.aborted)setRun(value);}catch{/* Preserve the original failure; no operation is automatically retried. */}}
        }}
        finally{if(operation.current===controller){operation.current=null;setBusy(false);}}
    }
    async function refresh(signal:AbortSignal,cursor:string|null=null){const value=await api.listDurableShadowFindings(cursor,signal);if(!signal.aborted)setPage(value);}
    function evaluate(){void perform(async signal=>{
        const selected=choices.find(value=>value.key===rule);if(!selected)throw new Error('Select an available definition');
        const result=await api.createDurableShadowRun({simulation:{rule:selected.definition,start_time:start,end_time:end,evaluation_time:new Date().toISOString()},identity_policy:{minimum}},signal);
        if(!signal.aborted)setRun(result);await refresh(signal);
    });}
    function select(id:string,revision?:number){void perform(async signal=>{const value=await api.getDurableShadowFinding(id,revision,signal);if(!signal.aborted)setDetail(value);});}
    function transition(target:FindingTransition['target'],reason:FindingTransition['reason']){if(!detail)return;void perform(async signal=>{
        const value=await api.transitionDurableShadowFinding(detail.finding_id,{expected_revision:detail.current_revision,expected_state:detail.state,target,reason},signal);
        if(!signal.aborted)setDetail(value);await refresh(signal);
    });}
    const available=detail&&Object.values(detail.current_evidence_availability).every(value=>value==='AVAILABLE');
    return <section className="panel" aria-label="Durable shadow finding history">
        <h2>Durable findings — SHADOW ONLY</h2><p>NOT PRODUCTION ACTIVE. Pattern review is not confirmation of compromise. Historical continuity: UNPROVEN.</p>
        {error&&<p role="alert">{error}</p>}{!status&&!error&&<p role="status">Loading history capability…</p>}
        {status&&!status.enabled&&<p>Durable history gate closed. No migration or activation can be requested from this UI.</p>}
        {status?.enabled&&<>
            <label>Versioned rule<select aria-label="Durable rule" value={rule} onChange={event=>{invalidate();setRule(event.target.value);}}>{choices.map(value=><option key={value.rule_version} value={value.key}>{value.definition.title}</option>)}</select></label>
            <label>Required identity strength<select aria-label="Required identity strength" value={minimum} onChange={event=>{invalidate();setMinimum(event.target.value as typeof minimum);}}>
                <option value="PARTIAL">PARTIAL — claimed source only</option><option value="STRONGLY_CORRELATED">STRONGLY_CORRELATED</option><option value="VERIFIED">VERIFIED — independent inventory required</option></select></label>
            <label>Start (UTC offset)<input aria-label="Durable start" value={start} maxLength={40} onChange={event=>{invalidate();setStart(event.target.value);}}/></label>
            <label>End (UTC offset)<input aria-label="Durable end" value={end} maxLength={40} onChange={event=>{invalidate();setEnd(event.target.value);}}/></label>
            <button type="button" disabled={!canMutate||busy||!rule} onClick={evaluate}>Evaluate and save bounded findings</button>
            {busy&&<button type="button" onClick={()=>{operation.current?.abort();setBusy(false);}}>Cancel owned request</button>}
            {!canMutate&&<p>Read-only: ANALYST or ADMIN required for evaluation and review.</p>}
            {run&&<p role="status">Run {run.run_id}: {run.status}; checkpoint {run.checkpoint}; recovery {run.recovery_state||'NOT_REQUIRED'}; {run.result?.finding_ids.length??0} durable findings; identity rejected {run.result?.identity_rejected??0}. Not a global detection count.</p>}
            {(status.recovery_runs||[]).map(item=><button type="button" key={item.run_id} disabled={busy} onClick={()=>void perform(async signal=>{const value=await api.getDurableShadowRun(item.run_id,signal);if(!signal.aborted)setRun(value);})}>Inspect pending run {item.run_id}</button>)}
            {run&&run.status!=='COMPLETED'&&run.checkpoint==='SEALED'&&<button type="button" disabled={!canMutate||busy} onClick={()=>void perform(async signal=>{const value=await api.resumeDurableShadowRun(run.run_id,signal);if(!signal.aborted)setRun(value);await refresh(signal);})}>Resume sealed evaluation</button>}
            {run?.recovery_state==='UNSEALED_VERIFICATION_REQUIRED'&&run.recovery_intent&&<aside aria-label="Unsealed recovery verification">
                <p>Durable intent covers {run.recovery_intent.candidate_rows} bounded candidates. Source rows must match the original manifest before sealing and evaluation. Checkpoint has not advanced; global completeness remains UNPROVEN.</p>
                <button type="button" disabled={!canMutate||busy} onClick={()=>void perform(async signal=>{const value=await api.resumeDurableShadowRun(run.run_id,signal);if(!signal.aborted)setRun(value);await refresh(signal);})}>Verify source and resume unsealed intent</button>
            </aside>}
            {run?.recovery_state==='UNSEALED_BLOCKED'&&<p role="alert">Legacy unsealed run has no durable snapshot witness. Reconciliation is required; no successful evaluation or checkpoint progress is inferred.</p>}
            {page&&page.items.length===0&&<p>No durable findings recorded.</p>}
            <ul>{page?.items.map(item=><li key={item.finding_id}><button type="button" onClick={()=>select(item.finding_id)}>{item.finding_id}</button> — {item.state}; version {item.rule_version.slice(0,12)}; revision {item.current_revision}</li>)}</ul>
            {page?.next_cursor&&<button type="button" disabled={busy} onClick={()=>void perform(signal=>refresh(signal,page.next_cursor))}>Next findings page</button>}
            <button type="button" disabled={busy} onClick={()=>void perform(signal=>refresh(signal))}>Refresh findings</button>
            <button type="button" disabled={busy} onClick={()=>void perform(async signal=>{const value=await api.reconcileShadowEvidence(null,signal);if(!signal.aborted)setReconciliation(value);})}>Reconcile retained evidence</button>
            {reconciliation&&<aside aria-label="Evidence reconciliation audit">
                <h3>Read-only evidence audit</h3><p>Observed <TimeValue value={reconciliation.observed_at}/>. Each page is a separate snapshot, not a global completeness count. History is unchanged; references are not automatic pins. Cross-database atomicity: false.</p>
                <ul>{Object.entries(reconciliation.counts).map(([state,count])=><li key={state}>{state}: {count}</li>)}</ul>
                {!reconciliation.revisions.length&&<p>No evidence revisions in this page.</p>}
                {reconciliation.revisions.map(row=><p key={row.finding_id+row.revision}>{row.finding_id} — evidence revision {row.revision}: {Object.entries(row.availability).map(([event,state])=>event+' '+state).join('; ')}</p>)}
                {reconciliation.next_cursor&&<button type="button" disabled={busy} onClick={()=>void perform(async signal=>{const value=await api.reconcileShadowEvidence(reconciliation.next_cursor,signal);if(!signal.aborted)setReconciliation(value);})}>Next reconciliation page</button>}
            </aside>}
        </>}
        {detail&&<article aria-label="Durable finding detail">
            <h3>{detail.matching_evidence.rule_snapshot.title} — {detail.state}</h3>
            {onInvestigate&&<button type="button" disabled={!available} onClick={()=>onInvestigate({target_type:'DURABLE_SHADOW_FINDING',target_id:detail.finding_id,shadow_revision:detail.revision,relative_minutes:10080,related_limit:50,timeline_limit:150,sort:'oldest'})}>Investigate durable finding revision {detail.revision}</button>}
            <p>Current lifecycle state; viewing evidence revision {detail.revision} of {detail.current_revision}. No automatic incident or evidence pin.</p>
            <p>Rule SHA {detail.rule_version}; identity policy SHA {detail.policy_sha}. Identity is recorded at original evaluation, not a current endpoint attestation.</p>
            <p>{detail.matching_evidence.explanation}</p>
            <p>MITRE rule tags, not confirmed stages: {detail.matching_evidence.mitre.map(item=>item.technique_id).join(', ')||'None'}</p>
            <table><caption>Resolved entities and uncertainty</caption><thead><tr><th>Kind</th><th>Status</th><th>Reason</th></tr></thead><tbody>{detail.identity.entities.map(entity=><tr key={entity.kind}><td>{entity.kind}</td><td>{entity.status}{entity.status==='VERIFIED'?' (configured inventory authority)':''}</td><td>{entity.reason}</td></tr>)}</tbody></table>
            <table><caption>Evidence timeline — temporal order is not causation</caption><thead><tr><th>Time</th><th>Host / account</th><th>Availability</th><th>Evidence</th></tr></thead><tbody>{detail.matching_evidence.evidence.map(item=><tr key={item.event_id}><td><TimeValue value={item.event_time}/></td><td>{item.host} / {item.user||'Unknown'}</td><td>{detail.current_evidence_availability[item.event_id]}</td><td><button type="button" disabled={detail.current_evidence_availability[item.event_id]!=='AVAILABLE'} onClick={()=>onOpenEvent(item.event_id)}>Open retained event {item.event_id}</button></td></tr>)}</tbody></table>
            {!available&&<p role="alert">Evidence is missing, changed or could not be rechecked. Historical metadata is retained; completeness is UNPROVEN.</p>}
            {detail.revision>1&&<button type="button" disabled={busy} onClick={()=>select(detail.finding_id,detail.revision-1)}>Previous evidence revision</button>}
            <h4>Append-only lifecycle history</h4><ul>{detail.history.map(item=><li key={item.sequence}>{item.previous_state||'Initial'} → {item.target_state}: {item.reason} by {item.actor} at <TimeValue value={item.occurred_at}/></li>)}</ul>
            {detail.history_truncated&&<p>Only the latest 50 transitions are shown.</p>}
            <button type="button" disabled={!canMutate||busy||!available||!['SHADOW_CANDIDATE','INCOMPLETE_EVIDENCE'].includes(detail.state)} onClick={()=>transition('SHADOW_CONFIRMED_MATCH','ANALYST_PATTERN_REVIEW')}>Review matched pattern — not compromise</button>
            <button type="button" disabled={!canMutate||busy||!['SHADOW_CANDIDATE','SHADOW_CONFIRMED_MATCH'].includes(detail.state)} onClick={()=>transition('INCOMPLETE_EVIDENCE','EVIDENCE_UNAVAILABLE')}>Mark incomplete evidence</button>
        </article>}
    </section>;
}
