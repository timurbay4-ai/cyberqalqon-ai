import type {ShadowCatalog,ShadowRule,ShadowSimulationResult,ShadowValidation} from "../types/shadow-detection";

export class ShadowContractError extends Error {
    constructor() { super("Backend response violates the shadow-only detection contract."); this.name="ShadowContractError"; }
}
function requireThat(value: unknown): asserts value { if (!value) throw new ShadowContractError(); }
function object(value:unknown):Record<string,unknown> { requireThat(value && typeof value==="object" && !Array.isArray(value)); return value as Record<string,unknown>; }
function text(value:unknown,max=4096):string { requireThat(typeof value==="string" && value.length<=max); return value; }
function integer(value:unknown,max=1_000_000):number { requireThat(typeof value==="number" && Number.isInteger(value) && value>=0 && value<=max); return value; }
function list(value:unknown,max:number):unknown[] { requireThat(Array.isArray(value) && value.length<=max); return value; }
function strings(value:unknown,max:number):string[] { return list(value,max).map(item=>text(item)); }
function hash(value:unknown):string { const result=text(value,64); requireThat(/^[a-f0-9]{64}$/.test(result)); return result; }
function date(value:unknown):string { const result=text(value,40); requireThat(/(?:Z|[+-]\d{2}:\d{2})$/.test(result) && Number.isFinite(Date.parse(result))); return result; }
function oneOf(value:unknown,allowed:readonly string[]):string { requireThat(typeof value==="string" && allowed.includes(value)); return value; }
function rule(value:unknown):ShadowRule {
    const item=object(value);
    requireThat(["cdrc-v2","cdrc-v3"].includes(String(item.contract)) && item.suppression_policy==="EVIDENCE_IDENTITY_ONLY" && item.account_identity_policy==="SID_WHEN_PRESENT_NO_DOWNGRADE"
        && item.source_duplicate_policy==="SOURCE_RECORD_WHEN_AVAILABLE_ELSE_DELIVERY");
    if(item.contract==='cdrc-v3'){
        oneOf(item.correlation_mode,['ORDERED','UNORDERED']);oneOf(item.predicate_semantics,['CQQL_SQL_3VL','SIGMA_2VL']);
        strings(item.external_rule_ids,8).forEach(value=>requireThat(value.length>0&&value.length<=128));
        if(item.external_metadata_json!==null){
            const metadata=text(item.external_metadata_json,8192);
            try{object(JSON.parse(metadata));}catch{throw new ShadowContractError();}
        }
    }else for(const key of ['correlation_mode','predicate_semantics','external_rule_ids','external_metadata_json'])requireThat(!(key in item));
    requireThat(/^SHADOW-[A-Z0-9-]{1,48}$/.test(text(item.rule_id,55)));
    for(const field of ["title","description","author"]) text(item[field]);
    oneOf(item.status,["DRAFT","VALIDATED","SHADOW_ONLY","DISABLED_BY_POLICY","INVALID","DEPRECATED"]);
    integer(item.severity,16); integer(item.confidence,100); integer(item.minimum_confidence,100);
    requireThat(integer(item.window_seconds,1800)>0); integer(item.allowed_lateness,300);
    for(const [field,max] of [["source_families",8],["required_fields",16],["group_by",4],["mitre_ids",8],["tags",12],["references",5]] as const) strings(item[field],max);
    strings(item.source_families,8).forEach(value=>oneOf(value,['WINDOWS_EVENTCHANNEL','SYSMON','LINUX_AUTH','SYSLOG','JOURNALD','WAZUH_GENERIC','ZEEK','SURICATA']));
    const steps=list(item.steps,3); requireThat(steps.length>0);
    for(const step of steps) {
        const entry=object(step); text(entry.query,2000); requireThat(integer(entry.threshold,10)>0);
        for(const field of ["process_basename_equals","parent_basename_equals"]) if(entry[field]!==null) text(entry[field],128);
    }
    date(item.created_at); date(item.updated_at);
    return item as unknown as ShadowRule;
}
export {rule as parseShadowRule};
export function parseShadowCatalog(value:unknown):ShadowCatalog {
    const item=object(value);
    requireThat(item.version==="cdrc-v2" && item.scope==="SOURCE_TEST_RESULTS" && item.production_active===false && typeof item.simulation_enabled==="boolean");
    for(const row of list(item.rules,100)) { const entry=object(row); rule(entry.definition); hash(entry.rule_version); }
    return item as unknown as ShadowCatalog;
}
export function parseShadowValidation(value:unknown):ShadowValidation {
    const item=object(value); requireThat(item.valid===true && item.production_active===false);
    hash(item.rule_version); rule(item.definition); strings(item.warnings,20);
    return item as unknown as ShadowValidation;
}
export function parseShadowResult(value:unknown):ShadowSimulationResult {
    const item=object(value);
    requireThat(item.version==="cdrc-v2" && item.scope==="DISPOSABLE_SIMULATION" && item.side_effects===false
        && item.historical_continuity==="UNPROVEN" && item.window_completeness==="UNPROVEN"
        && item.evidence_retention==="NOT_PINNED_RECHECK_ON_DRILLDOWN" && item.persistence==="STATELESS_CONTENT_ADDRESSED_OUTPUT");
    oneOf(item.status,["COMPLETE","RULE_DISABLED"]);
    oneOf(item.outcome,["MATCH","NO_MATCH","RULE_DISABLED","UNSUPPORTED_FIELDS","INVALID_EVENT"]);
    oneOf(item.coverage,["PARTIAL","BOUNDED_CANDIDATE_SLICE"]);
    requireThat(typeof item.candidate_truncated==="boolean" && (!item.candidate_truncated || item.coverage==="PARTIAL"));
    const version=hash(item.rule_version),findings=list(item.findings,100),nodes=new Set<string>();
    requireThat((item.outcome==="MATCH") === (findings.length>0));
    requireThat((item.status==="RULE_DISABLED") === (item.outcome==="RULE_DISABLED"));
    for(const row of findings) {
        const finding=object(row),definition=rule(finding.rule_snapshot);
        requireThat(finding.rule_version===version && finding.rule_id===definition.rule_id && definition.status==="SHADOW_ONLY"
            && finding.status==="SHADOW_ONLY" && finding.completeness==="UNPROVEN" && finding.evaluation_version===(definition.contract==='cdrc-v3'?'m34-shadow-v1':'m30-shadow-v1')
            && finding.identity_confidence==="CLAIMED_ENDPOINT_SCOPED");
        const id=text(finding.finding_id,67); requireThat(/^SF-[a-f0-9]{64}$/.test(id) && !nodes.has(id)); nodes.add(id);
        integer(finding.severity,16); integer(finding.confidence,40); date(finding.window_start); date(finding.window_end);
        hash(finding.evidence_manifest_sha256);
        text(finding.explanation); strings(finding.uncertainty,16);
        for(const value of Object.values(object(finding.group))) text(value,1024);
        const evidence=list(finding.evidence,32); requireThat(evidence.length>0);
        const seen=new Set<string>();
        for(const row of evidence) {
            const entry=object(row),eventId=text(entry.event_id,64);
            requireThat(/^EVT-[A-F0-9]{24}$/.test(eventId) && !seen.has(eventId) && entry.provenance==="PARTIAL"); seen.add(eventId); nodes.add(eventId);
            date(entry.event_time); date(entry.ingestion_time); text(entry.host); text(entry.source_family);
            for(const field of ["user","user_sid","process","event_code","process_guid"]) if(entry[field]!==null) text(entry[field]);
            hash(entry.stored_envelope_sha256); hash(entry.source_identity_sha256);
            if(entry.source_record_key_sha256!==null)hash(entry.source_record_key_sha256);
        }
        for(const row of list(finding.mitre,8)) {
            const entry=object(row); requireThat(entry.evidence_strength==="RULE_TAGGED_TECHNIQUE");
            requireThat(/^T\d{4}(?:\.\d{3})?$/.test(text(entry.technique_id,16))); text(entry.name); text(entry.tactic);
        }
    }
    requireThat(nodes.size<=128);
    for(const row of list(item.graph_edges,256)) {
        const edge=object(row); requireThat(edge.causal_claim===false && nodes.has(text(edge.source)) && nodes.has(text(edge.target)));
        oneOf(edge.relationship,["FINDING_SUPPORTED_BY_EVENT","OBSERVED_BEFORE","OBSERVED_SHARED_PROCESS_GUID"]);
    }
    for(const count of Object.values(object(item.diagnostics))) integer(count);
    requireThat(typeof item.execution_ms==="number" && Number.isFinite(item.execution_ms) && item.execution_ms>=0);
    return item as unknown as ShadowSimulationResult;
}
