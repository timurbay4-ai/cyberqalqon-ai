import type {DurableStatus,DurableRun,FindingPage,FindingDetail} from '../types/shadow-history';
import {parseShadowResult,ShadowContractError} from './shadow-contracts';
const STATES=['SHADOW_CANDIDATE','SHADOW_CONFIRMED_MATCH','INCOMPLETE_EVIDENCE','SUPERSEDED','EXPIRED','INVALIDATED'];
function check(value:unknown):asserts value {if(!value)throw new ShadowContractError();}
function obj(value:unknown):Record<string,any>{check(value&&typeof value==='object'&&!Array.isArray(value));return value as Record<string,any>;}
function list(value:unknown,max:number):any[]{check(Array.isArray(value)&&value.length<=max);return value;}
function str(value:unknown,max=4096){check(typeof value==='string'&&value.length<=max);return value;}
function hash(value:unknown){check(/^[a-f0-9]{64}$/.test(str(value,64)));}
function integer(value:unknown,max=8192){check(Number.isInteger(value)&&Number(value)>=0&&Number(value)<=max);}
function scope(value:Record<string,any>){check(value.scope==='DISPOSABLE_DURABLE_SHADOW'&&value.production_active===false);}
function header(value:unknown){const row=obj(value);check(/^DSF-[a-f0-9]{64}$/.test(str(row.finding_id)));hash(row.rule_version);hash(row.policy_sha);integer(row.current_revision);check(row.current_revision>0&&STATES.includes(row.state));return row;}
export function parseDurableStatus(value:unknown):DurableStatus {const row=obj(value);scope(row);check(typeof row.enabled==='boolean'&&(row.enabled?row.schema_version===1:row.schema_version===null));return row as unknown as DurableStatus;}
export function parseFindingPage(value:unknown):FindingPage {const row=obj(value);scope(row);for(const item of list(row.items,50))header(item);check(row.next_cursor===null||typeof row.next_cursor==='string'&&row.next_cursor.length<=512);return row as unknown as FindingPage;}
export function parseDurableRun(value:unknown):DurableRun {
    const row=obj(value);scope(row);check(/^RUN-[a-f0-9]{32}$/.test(str(row.run_id))&&['RUNNING','COMPLETED','FAILED','CANCELLED'].includes(row.status));
    check(['SEALED','UNSEALED'].includes(row.checkpoint)&&row.historical_continuity==='UNPROVEN');integer(row.attempts,3);check(row.attempts>0);
    if(row.recovery_state!==undefined)check(['NOT_REQUIRED','IN_PROGRESS','EXPLICIT_RESUME_REQUIRED','UNSEALED_BLOCKED','UNSEALED_VERIFICATION_REQUIRED','ATTEMPTS_EXHAUSTED'].includes(row.recovery_state));
    check((row.checkpoint==='SEALED')===(row.snapshot_sha256!==null));if(row.snapshot_sha256!==null)hash(row.snapshot_sha256);
    if(row.recovery_intent!==undefined&&row.recovery_intent!==null){
        const intent=obj(row.recovery_intent);check(intent.version==='m35-bounded-snapshot-intent-v1'&&intent.scope==='BOUNDED_CANDIDATES_NOT_GLOBAL_COMPLETENESS');
        hash(intent.manifest_sha256);integer(intent.candidate_rows,1000);check(typeof intent.candidate_truncated==='boolean');
        check(intent.verification===(row.checkpoint==='SEALED'?'SEALED':'RECHECK_REQUIRED'));
        if(row.checkpoint==='SEALED')check(intent.manifest_sha256===row.snapshot_sha256);
    }
    if(row.recovery_state==='UNSEALED_VERIFICATION_REQUIRED')check(row.checkpoint==='UNSEALED'&&!!row.recovery_intent&&row.result===null);
    check((row.status==='COMPLETED')===(row.result!==null));
    if(row.result!==null){const result=obj(row.result);check(result.evaluation_version==='m31-shadow-v1'&&result.historical_continuity==='UNPROVEN'&&result.window_completeness==='UNPROVEN');
        for(const id of list(result.finding_ids,100))check(/^DSF-[a-f0-9]{64}$/.test(str(id)));
        integer(result.identity_rejected,100);integer(result.candidate_count,100);
        for(const edge of list(result.graph_edges,256)){check(obj(edge).causal_claim===false);check(['FINDING_SUPPORTED_BY_EVENT','OBSERVED_BEFORE','OBSERVED_SHARED_PROCESS_GUID'].includes(edge.relationship));}
    }
    return row as unknown as DurableRun;
}
export function parseFindingDetail(value:unknown):FindingDetail {
    const row=header(value);scope(row);integer(row.revision);check(row.revision>0&&row.historical_continuity==='UNPROVEN'&&row.evidence_retention==='REFERENCES_NOT_AUTOMATIC_PINS');
    check(row.identity_context==='AT_ORIGINAL_EVALUATION_NOT_CURRENT_SOURCE_ATTESTATION');
    // Reuse the existing standalone match checks in a validation context, not UI data.
    const match=obj(row.matching_evidence);
    parseShadowResult({version:'cdrc-v2',scope:'DISPOSABLE_SIMULATION',status:'COMPLETE',outcome:'MATCH',rule_version:row.rule_version,
        findings:[match],graph_edges:[],diagnostics:{},candidate_truncated:false,coverage:'BOUNDED_CANDIDATE_SLICE',historical_continuity:'UNPROVEN',
        window_completeness:'UNPROVEN',evidence_retention:'NOT_PINNED_RECHECK_ON_DRILLDOWN',persistence:'STATELESS_CONTENT_ADDRESSED_OUTPUT',side_effects:false,execution_ms:0});
    check(row.matching_id===match.finding_id);
    const identity=obj(row.identity);check(identity.version==='m31-identity-v1'&&identity.causal_claim===false&&identity.historical_continuity==='UNPROVEN'&&identity.satisfied===true);
    const docs=list(row.authority_documents,1),kinds=new Set<string>();
    for(const entity of list(identity.entities,7)){
        check(['HOST','ACCOUNT','PROCESS','NETWORK_ENDPOINT','SESSION','AGENT','COLLECTOR'].includes(entity.kind)&&!kinds.has(entity.kind));kinds.add(entity.kind);
        check(['VERIFIED','STRONGLY_CORRELATED','PARTIAL','AMBIGUOUS','UNVERIFIED','CONFLICTING'].includes(entity.status));hash(entity.scope_sha256);str(entity.reason,128);
        if(entity.status==='VERIFIED'){hash(entity.authority_sha256);check(docs.length===1);hash(obj(docs[0]).signature);}
        for(const id of list(entity.evidence_ids,32))check(match.evidence.some((item:any)=>item.event_id===id));
    }
    const refs=list(row.evidence_references,32);check(refs.length===match.evidence.length);
    for(const ref of refs){hash(ref.envelope_sha);hash(ref.row_sha);check(match.evidence.some((item:any)=>item.event_id===ref.event_id&&item.stored_envelope_sha256===ref.envelope_sha));}
    for(const [id,status] of Object.entries(obj(row.current_evidence_availability)))check(refs.some(ref=>ref.event_id===id)&&['AVAILABLE','MISSING','CHANGED','UNKNOWN'].includes(String(status)));
    check(Object.keys(row.current_evidence_availability).length===refs.length);
    for(const transition of list(row.history,50)){check(transition.finding_id===row.finding_id&&STATES.includes(transition.target_state));str(transition.reason,64);str(transition.actor,128);}
    check(typeof row.history_truncated==='boolean');return row as unknown as FindingDetail;
}
