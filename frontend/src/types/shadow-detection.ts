export interface ShadowStep {
    query: string;
    threshold: number;
    process_basename_equals: string | null;
    parent_basename_equals: string | null;
}
export interface ShadowRule {
    contract: "cdrc-v2" | "cdrc-v3";
    correlation_mode?: "ORDERED" | "UNORDERED";
    predicate_semantics?: "CQQL_SQL_3VL" | "SIGMA_2VL";
    external_rule_ids?: string[];
    external_metadata_json?: string | null;
    rule_id: string;
    title: string;
    description: string;
    author: string;
    status: "DRAFT" | "VALIDATED" | "SHADOW_ONLY" | "DISABLED_BY_POLICY" | "INVALID" | "DEPRECATED";
    severity: number;
    confidence: number;
    minimum_confidence: number;
    source_families: string[];
    required_fields: string[];
    steps: ShadowStep[];
    group_by: string[];
    window_seconds: number;
    allowed_lateness: number;
    suppression_policy: "EVIDENCE_IDENTITY_ONLY";
    account_identity_policy: "SID_WHEN_PRESENT_NO_DOWNGRADE";
    source_duplicate_policy: "SOURCE_RECORD_WHEN_AVAILABLE_ELSE_DELIVERY";
    mitre_ids: string[];
    tags: string[];
    references: string[];
    created_at: string;
    updated_at: string;
}
export interface ShadowCatalog {
    version: "cdrc-v2";
    scope: "SOURCE_TEST_RESULTS";
    production_active: false;
    simulation_enabled: boolean;
    rules: {definition: ShadowRule; rule_version: string}[];
}
export interface ShadowSimulationRequest {rule: ShadowRule; start_time: string; end_time: string; evaluation_time: string}
export interface ShadowEvidence {
    event_id: string; event_time: string; ingestion_time: string; source_family: string;
    host: string; user: string | null; user_sid: string | null; process: string | null;
    stored_envelope_sha256: string; source_identity_sha256: string; provenance: "PARTIAL";
    source_record_key_sha256: string | null;
    event_code: string | null; process_guid: string | null;
}
export interface ShadowFinding {
    finding_id: string; rule_id: string; rule_version: string; rule_snapshot: ShadowRule;
    evidence_manifest_sha256: string;
    evaluation_version: "m30-shadow-v1" | "m34-shadow-v1"; status: "SHADOW_ONLY"; severity: number; confidence: number;
    identity_confidence: "CLAIMED_ENDPOINT_SCOPED"; window_start: string; window_end: string;
    completeness: "UNPROVEN"; group: Record<string,string>; explanation: string; uncertainty: string[];
    evidence: ShadowEvidence[];
    mitre: {technique_id:string;name:string;tactic:string;evidence_strength:"RULE_TAGGED_TECHNIQUE"}[];
}
export interface ShadowSimulationResult {
    version: "cdrc-v2"; scope: "DISPOSABLE_SIMULATION"; status: "COMPLETE" | "RULE_DISABLED";
    outcome: "MATCH" | "NO_MATCH" | "RULE_DISABLED" | "UNSUPPORTED_FIELDS" | "INVALID_EVENT";
    rule_version: string; findings: ShadowFinding[];
    graph_edges: {source:string;target:string;relationship:"FINDING_SUPPORTED_BY_EVENT"|"OBSERVED_BEFORE"|"OBSERVED_SHARED_PROCESS_GUID";causal_claim:false}[];
    diagnostics: Record<string,number>; candidate_truncated:boolean;coverage:"PARTIAL"|"BOUNDED_CANDIDATE_SLICE";
    historical_continuity:"UNPROVEN";window_completeness:"UNPROVEN";
    evidence_retention:"NOT_PINNED_RECHECK_ON_DRILLDOWN";persistence:"STATELESS_CONTENT_ADDRESSED_OUTPUT";
    side_effects:false;execution_ms:number;
}
export interface ShadowValidation {valid:true;rule_version:string;definition:ShadowRule;production_active:false;warnings:string[]}
